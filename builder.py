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
        urls = json.load(f)

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
    
    for url in urls:
        try:
            parsed = feedparser.parse(url)
            source_name = parsed.feed.get('title', url)
            
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
                    'source': source_name
                }
                feed_articles.append(article)
                articles.append(article)
            
            stats.append({
                'source': source_name,
                'new_count': new_count,
                'total_count': len(feed_articles)
            })
        except Exception as e:
            print(f"Failed to parse {url}: {e}")
    
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
