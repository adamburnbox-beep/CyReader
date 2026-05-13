import json
import feedparser
import time
import os

def build_feed():
    # Get the directory where the script is located
    base_dir = os.path.dirname(os.path.abspath(__file__))
    feeds_path = os.path.join(base_dir, 'feeds.json')
    data_path = os.path.join(base_dir, 'data.json')

    if not os.path.exists(feeds_path):
        print(f"Error: {feeds_path} not found.")
        return

    with open(feeds_path, 'r') as f:
        feed_configs = json.load(f)

    # Load existing articles to identify "new" ones
    existing_links = set()
    if os.path.exists(data_path):
        try:
            with open(data_path, 'r') as f:
                old_data = json.load(f)
                # Handle both old list format and new dict format
                old_articles = old_data.get('articles', []) if isinstance(old_data, dict) else old_data
                existing_links = {a['link'] for a in old_articles}
        except Exception as e:
            print(f"Could not load old data: {e}")

    articles = []
    stats = []
    
    for config in feed_configs:
        # Handle both list of strings and list of dicts
        if isinstance(config, dict):
            url = config.get('url')
            source_name = config.get('name', url)
        else:
            url = config
            source_name = url

        if not url:
            continue

        try:
            parsed = feedparser.parse(url)
            source_name = config.get('name', parsed.feed.get('title', url))
            vendor = config.get('vendor', 'Unknown')
            
            new_count = 0
            feed_articles = []
            
            for entry in parsed.entries[:10]:
                link = entry.get('link', '#')
                timestamp = time.mktime(entry.published_parsed) if getattr(entry, 'published_parsed', None) else 0
                summary = entry.get('summary', '')
                clean_summary = summary[:150] + '...' if len(summary) > 150 else summary

                if link not in existing_links:
                    new_count += 1

                article = {
                    'title': entry.get('title', 'Untitled'),
                    'link': link,
                    'summary': clean_summary,
                    'timestamp': timestamp,
                    'source': source_name,
                    'vendor': vendor
                }
                feed_articles.append(article)
                articles.append(article)
            
            stats.append({
                'source': source_name,
                'vendor': vendor,
                'new_count': new_count,
                'total_count': len(feed_articles),
                'status': 'ok'
            })
        except Exception as e:
            print(f"Failed to parse {url}: {e}")
            stats.append({
                'source': source_name,
                'vendor': config.get('vendor', 'Unknown'),
                'new_count': 0,
                'total_count': 0,
                'status': 'error'
            })
    
    articles.sort(key=lambda x: x['timestamp'], reverse=True)

    output = {
        'stats': stats,
        'articles': articles,
        'last_updated': time.time()
    }

    with open(data_path, 'w') as f:
        json.dump(output, f, indent=2)

if __name__ == '__main__':
    build_feed()
