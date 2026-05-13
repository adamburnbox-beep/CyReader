import json
import feedparser
import time
import os

def build_feed():
    # Get the directory where the script is located
    base_dir = os.path.dirname(os.path.abspath(__file__))
    feeds_path = os.path.join(base_dir, 'feeds.json')
    output_path = os.path.join(base_dir, 'data.json')

    if not os.path.exists(feeds_path):
        print(f"Error: {feeds_path} not found.")
        return

    with open(feeds_path, 'r') as f:
        urls = json.load(f)

    articles = []
    for url in urls:
        try:
            parsed = feedparser.parse(url)
            source_name = parsed.feed.get('title', url)
            
            for entry in parsed.entries[:10]:
                timestamp = time.mktime(entry.published_parsed) if getattr(entry, 'published_parsed', None) else 0
                summary = entry.get('summary', '')
                clean_summary = summary[:150] + '...' if len(summary) > 150 else summary

                articles.append({
                    'title': entry.get('title', 'Untitled'),
                    'link': entry.get('link', '#'),
                    'summary': clean_summary,
                    'timestamp': timestamp,
                    'source': source_name
                })
        except Exception as e:
            print(f"Failed to parse {url}: {e}")
    
    articles.sort(key=lambda x: x['timestamp'], reverse=True)

    with open(output_path, 'w') as f:
        json.dump(articles, f, indent=2)

if __name__ == '__main__':
    build_feed()
