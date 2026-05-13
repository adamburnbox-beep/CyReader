import json
import feedparser
import time

def build_feed():
    with open('feeds.json', 'r') as f:
        urls = json.load(f)

    articles = []
    for url in urls:
        parsed = feedparser.parse(url)
        source_name = parsed.feed.get('title', url)
        
        for entry in parsed.entries[:10]:
            # Convert messy RSS dates to raw Unix timestamps for the frontend
            timestamp = time.mktime(entry.published_parsed) if getattr(entry, 'published_parsed', None) else 0
            
            # Strip excessive HTML from summaries
            summary = entry.get('summary', '')
            clean_summary = summary[:150] + '...' if len(summary) > 150 else summary

            articles.append({
                'title': entry.get('title', 'Untitled'),
                'link': entry.get('link', '#'),
                'summary': clean_summary,
                'timestamp': timestamp,
                'source': source_name
            })
    
    # Sort globally by newest first
    articles.sort(key=lambda x: x['timestamp'], reverse=True)

    with open('data.json', 'w') as f:
        json.dump(articles, f, indent=2)

if __name__ == '__main__':
    build_feed()