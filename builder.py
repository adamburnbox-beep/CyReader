#!/usr/bin/env python3
"""CyReader feed builder.

Reads feeds.json, fetches every enabled feed in parallel, enriches the entries
(CVE ids, severity, CISA KEV, EPSS, tags) and merges them into data.json so the
static front-end (index.html) always has a rolling history to work with.

Usage:
    python builder.py            # normal run
    python builder.py --check    # fetch feeds and print a health report only
"""
import calendar
import concurrent.futures as cf
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.request

import feedparser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FEEDS_PATH = os.path.join(BASE_DIR, 'feeds.json')
DATA_PATH = os.path.join(BASE_DIR, 'data.json')

RETENTION_DAYS = 30        # how long articles are kept in data.json
MAX_ARTICLES = 4000        # hard cap on stored articles
DEFAULT_MAX_ITEMS = 50     # entries taken per feed per run
SUMMARY_LEN = 600
FETCH_TIMEOUT = 25
EPSS_WINDOW_DAYS = 14
USER_AGENT = 'CyReader/2.0 (+https://github.com/adamburnbox-beep/CyReader)'

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS_URL = 'https://api.first.org/data/v1/epss?cve='

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical']
SEVERITY_WORDS = {
    'critical': 'critical', 'important': 'high', 'high': 'high',
    'moderate': 'medium', 'medium': 'medium', 'low': 'low',
}
SEV_LABEL_RE = re.compile(
    r'(?:severity|impact rating|security impact|rating|priority)\s*(?:rating)?\s*[:=\-]?\s*\(?\s*'
    r'(critical|important|high|moderate|medium|low)\b', re.I)
CVSS_RE = re.compile(r'(?:cvss|base score)[^0-9]{0,30}(10(?:\.0)?|\d\.\d)', re.I)

TAG_PATTERNS = [
    ('zero-day', re.compile(r'zero[- ]?day|0[- ]day', re.I)),
    ('exploited', re.compile(r'actively exploited|exploited in the wild|under (?:active )?attack|being exploited|known exploited', re.I)),
    ('rce', re.compile(r'remote code execution|\brce\b|arbitrary code', re.I)),
    ('auth-bypass', re.compile(r'authentication bypass|auth(?:entication)? bypass|unauthenticated', re.I)),
    ('priv-esc', re.compile(r'privilege escalation|elevation of privilege', re.I)),
    ('ransomware', re.compile(r'ransomware', re.I)),
    ('poc', re.compile(r'proof[- ]of[- ]concept|\bpoc\b|public exploit', re.I)),
]


def log(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------- helpers
def clean_text(raw):
    text = re.sub(r'<[^>]+>', ' ', raw or '')
    text = html.unescape(text).replace('\xa0', ' ')
    return re.sub(r'\s+', ' ', text).strip()


def truncate(text, n):
    return text if len(text) <= n else text[:n].rstrip() + '...'


def article_id(link, title):
    return hashlib.sha1((link or title).encode('utf-8', 'replace')).hexdigest()[:16]


def sev_from_cvss(score):
    if score >= 9.0:
        return 'critical'
    if score >= 7.0:
        return 'high'
    if score >= 4.0:
        return 'medium'
    return 'low' if score > 0 else 'info'


def max_sev(a, b):
    return a if SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b) else b


def detect_severity(text, default='info'):
    """Return (severity, cvss) found in free text."""
    cvss = None
    m = CVSS_RE.search(text)
    if m:
        try:
            cvss = float(m.group(1))
        except ValueError:
            cvss = None
    sev = None
    m = SEV_LABEL_RE.search(text)
    if m:
        sev = SEVERITY_WORDS[m.group(1).lower()]
    if cvss is not None:
        sev = max_sev(sev, sev_from_cvss(cvss)) if sev else sev_from_cvss(cvss)
    return (sev or default), cvss


def detect_tags(text):
    return [name for name, rx in TAG_PATTERNS if rx.search(text)]


def http_get(url, retries=2):
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': USER_AGENT,
                'Accept': 'application/rss+xml, application/atom+xml, application/xml, application/json, */*',
            })
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                return resp.read()
        except Exception as e:  # noqa: BLE001 - report any failure as a feed error
            last = e
            time.sleep(1.5 * (attempt + 1))
    raise last


# ---------------------------------------------------------------- config
def load_feed_configs():
    with open(FEEDS_PATH, 'r') as f:
        raw = json.load(f)
    configs = []
    for item in raw:
        cfg = {'url': item} if isinstance(item, str) else dict(item)
        if not cfg.get('url') or cfg.get('enabled', True) is False:
            continue
        cfg.setdefault('name', cfg['url'])
        cfg.setdefault('vendor', 'Unknown')
        cfg.setdefault('category', 'Vendor')
        cfg.setdefault('default_severity', 'info')
        cfg.setdefault('max_items', DEFAULT_MAX_ITEMS)
        configs.append(cfg)
    return configs


def load_previous():
    if not os.path.exists(DATA_PATH):
        return {}, {}
    try:
        with open(DATA_PATH, 'r') as f:
            old = json.load(f)
        if isinstance(old, list):
            old = {'articles': old}
        articles = {}
        for a in old.get('articles', []):
            a.setdefault('id', article_id(a.get('link'), a.get('title', '')))
            a.setdefault('first_seen', a.get('timestamp') or time.time())
            articles[a['id']] = a
        stats = {s['source']: s for s in old.get('stats', [])}
        return articles, stats
    except Exception as e:  # noqa: BLE001
        log(f'Could not load old data: {e}')
        return {}, {}


# ---------------------------------------------------------------- fetching
def fetch_feed(cfg, now):
    started = time.time()
    result = {'cfg': cfg, 'entries': [], 'error': None}
    try:
        parsed = feedparser.parse(http_get(cfg['url']))
        if parsed.bozo and not parsed.entries:
            raise ValueError(str(getattr(parsed, 'bozo_exception', 'unparseable feed')) or 'unparseable feed')
        include = [k.lower() for k in cfg.get('include', [])]
        exclude = [k.lower() for k in cfg.get('exclude', [])]
        for entry in parsed.entries[:int(cfg['max_items'])]:
            title = clean_text(entry.get('title', 'Untitled')) or 'Untitled'
            body = entry.get('summary') or ''
            if not body and entry.get('content'):
                body = entry['content'][0].get('value', '')
            summary = clean_text(body)
            blob = f'{title} {summary}'.lower()
            if include and not any(k in blob for k in include):
                continue
            if exclude and any(k in blob for k in exclude):
                continue
            ts = 0
            for key in ('published_parsed', 'updated_parsed', 'created_parsed'):
                if getattr(entry, key, None):
                    ts = calendar.timegm(entry[key])
                    break
            result['entries'].append((entry, title, summary, ts))
    except Exception as e:  # noqa: BLE001
        result['error'] = str(e)[:200]
    result['latency_ms'] = int((time.time() - started) * 1000)
    return result


def fetch_kev():
    try:
        data = json.loads(http_get(KEV_URL))
        return {v['cveID'].upper(): v for v in data.get('vulnerabilities', [])}
    except Exception as e:  # noqa: BLE001
        log(f'KEV catalog unavailable: {e}')
        return None


def fetch_epss(cves):
    scores = {}
    cves = sorted(cves)
    for i in range(0, len(cves), 80):
        chunk = cves[i:i + 80]
        try:
            data = json.loads(http_get(EPSS_URL + ','.join(chunk), retries=1))
            for row in data.get('data', []):
                scores[row['cve'].upper()] = float(row['epss'])
        except Exception as e:  # noqa: BLE001
            log(f'EPSS lookup failed: {e}')
            break
    return scores


# ---------------------------------------------------------------- main build
def build_article(cfg, entry, title, summary, ts, now):
    link = entry.get('link') or '#'
    text = f'{title} {summary}'
    sev, cvss = detect_severity(text, cfg['default_severity'])
    return {
        'id': article_id(link, title),
        'title': title,
        'link': link,
        'summary': truncate(summary, SUMMARY_LEN),
        'timestamp': min(ts, now) if ts else 0,
        'source': cfg['name'],
        'vendor': cfg['vendor'],
        'category': cfg['category'],
        'severity': sev,
        'cvss': cvss,
        'cves': sorted({c.upper() for c in CVE_RE.findall(text)}),
        'tags': detect_tags(text),
    }


def kev_articles(kev, now):
    out = []
    cutoff = now - RETENTION_DAYS * 86400
    for cve, v in kev.items():
        try:
            ts = calendar.timegm(time.strptime(v.get('dateAdded', ''), '%Y-%m-%d'))
        except ValueError:
            continue
        if ts < cutoff:
            continue
        link = f'https://nvd.nist.gov/vuln/detail/{cve}'
        title = f"{cve} - {v.get('vendorProject', '')} {v.get('product', '')}: {v.get('vulnerabilityName', '')}".strip()
        summary = clean_text(v.get('shortDescription', ''))
        if v.get('requiredAction'):
            summary += f" Required action: {clean_text(v['requiredAction'])}"
        out.append({
            'id': article_id(link + '#kev', title), 'title': title, 'link': link,
            'summary': truncate(summary, SUMMARY_LEN), 'timestamp': min(ts, now),
            'source': 'CISA KEV Catalog', 'vendor': 'CISA', 'category': 'Government',
            'severity': 'critical', 'cvss': None, 'cves': [cve],
            'tags': ['exploited'] + (['ransomware'] if v.get('knownRansomwareCampaignUse') == 'Known' else []),
            'kev_due': v.get('dueDate'),
        })
    return out


def build_feed(check_only=False):
    now = time.time()
    configs = load_feed_configs()
    articles, old_stats = load_previous()

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda c: fetch_feed(c, now), configs))

    stats = []
    for res in results:
        cfg = res['cfg']
        prev = old_stats.get(cfg['name'], {})
        stat = {
            'source': cfg['name'], 'vendor': cfg['vendor'], 'category': cfg['category'],
            'url': cfg['url'], 'status': 'ok', 'error': None, 'new_count': 0,
            'total_count': len(res['entries']), 'latency_ms': res['latency_ms'],
            'last_checked': now, 'last_success': prev.get('last_success'),
            'last_new': prev.get('last_new'), 'failures': 0,
        }
        if res['error']:
            stat.update(status='error', error=res['error'], failures=prev.get('failures', 0) + 1)
            log(f"FAIL {cfg['name']}: {res['error']}")
        else:
            stat['last_success'] = now
            if not res['entries']:
                stat.update(status='warn', error='Feed returned no entries')
            for entry, title, summary, ts in res['entries']:
                art = build_article(cfg, entry, title, summary, ts, now)
                existing = articles.get(art['id'])
                if existing:
                    art['first_seen'] = existing.get('first_seen', now)
                    art['epss'] = existing.get('epss')
                    art['timestamp'] = art['timestamp'] or existing.get('timestamp', 0)
                else:
                    art['first_seen'] = now
                    stat['new_count'] += 1
                art['timestamp'] = art['timestamp'] or art['first_seen']
                articles[art['id']] = art
            if stat['new_count']:
                stat['last_new'] = now
            log(f"ok   {cfg['name']}: {len(res['entries'])} entries, {stat['new_count']} new")
        stats.append(stat)

    if check_only:
        return

    # CISA Known Exploited Vulnerabilities: flag matching CVEs + add recent additions
    kev = fetch_kev()
    if kev is not None:
        for art in kev_articles(kev, now):
            existing = articles.get(art['id'])
            art['first_seen'] = existing['first_seen'] if existing else now
            articles[art['id']] = art
        for a in articles.values():
            hits = [c for c in a.get('cves', []) if c in kev]
            a['kev'] = bool(hits)
            if hits:
                a['severity'] = max_sev(a.get('severity', 'info'), 'high')
                a['kev_due'] = kev[hits[0]].get('dueDate')
                if 'exploited' not in a.get('tags', []):
                    a.setdefault('tags', []).append('exploited')
    stats.append({
        'source': 'CISA KEV Catalog', 'vendor': 'CISA', 'category': 'Government',
        'url': KEV_URL, 'status': 'ok' if kev is not None else 'error',
        'error': None if kev is not None else 'KEV catalog unavailable',
        'new_count': 0, 'total_count': len(kev or {}), 'latency_ms': 0, 'last_checked': now,
        'last_success': now if kev is not None else old_stats.get('CISA KEV Catalog', {}).get('last_success'),
        'last_new': None, 'failures': 0 if kev is not None else 1,
    })

    # EPSS exploit-probability for recent CVEs
    recent = {c for a in articles.values() if a['timestamp'] > now - EPSS_WINDOW_DAYS * 86400
              for c in a.get('cves', [])}
    if recent:
        scores = fetch_epss(recent)
        for a in articles.values():
            vals = [scores[c] for c in a.get('cves', []) if c in scores]
            if vals:
                a['epss'] = round(max(vals), 4)

    # Retention + cap
    cutoff = now - RETENTION_DAYS * 86400
    kept = [a for a in articles.values() if a['timestamp'] > cutoff]
    kept.sort(key=lambda a: a['timestamp'], reverse=True)
    kept = kept[:MAX_ARTICLES]
    for a in kept:
        a.setdefault('kev', False)

    output = {
        'version': 2,
        'last_updated': now,
        'retention_days': RETENTION_DAYS,
        'stats': stats,
        'articles': kept,
    }
    with open(DATA_PATH, 'w') as f:
        json.dump(output, f, indent=1, ensure_ascii=False)
    log(f'Wrote {len(kept)} articles from {len(stats)} sources')


if __name__ == '__main__':
    build_feed(check_only='--check' in sys.argv)
