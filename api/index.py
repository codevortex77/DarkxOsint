from flask import Flask, request, jsonify
import requests
from functools import lru_cache
import time
from datetime import datetime

app = Flask(__name__)

# Cache for superfast responses
cache = {}
CACHE_DURATION = 300  # 5 minutes

def get_cached_response(cache_key):
    if cache_key in cache:
        data, timestamp = cache[cache_key]
        if time.time() - timestamp < CACHE_DURATION:
            return data
    return None

def set_cache(cache_key, data):
    cache[cache_key] = (data, time.time())

@app.route('/api', methods=['GET'])
def api_handler():
    query_type = request.args.get('type', 'num')
    query_key = request.args.get('key', 'swayam')
    query_value = request.args.get('query', '')
    
    # Create cache key
    cache_key = f"{query_type}:{query_key}:{query_value}"
    
    # Check cache first for superfast response
    cached_response = get_cached_response(cache_key)
    if cached_response:
        return jsonify(cached_response)
    
    try:
        # Make request to original API
        original_url = f"https://rootx-osint.in/?type={query_type}&key={query_key}&query={query_value}"
        
        # Use session for better performance
        session = requests.Session()
        response = session.get(original_url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            
            # Clean and modify response
            if isinstance(data, dict):
                # Remove unwanted fields
                data.pop('req_left', None)
                data.pop('req_total', None)
                data.pop('expiry', None)
                
                # Replace developer credit
                if 'developer' in data:
                    data['Credit'] = '@RichUniversal'
                    del data['developer']
                elif 'Credit' not in data:
                    data['Credit'] = '@RichUniversal'
                
                # Replace any @simpleguy444 mentions
                data = replace_text_recursive(data, '@simpleguy444', '@RichUniversal')
            
            # Cache the response
            set_cache(cache_key, data)
            
            return jsonify(data)
        else:
            return jsonify({"error": "Failed to fetch data", "Credit": "@RichUniversal"}), 500
            
    except requests.RequestException as e:
        return jsonify({
            "error": "Request timeout or failed",
            "Credit": "@RichUniversal",
            "message": "Please try again"
        }), 504
    except Exception as e:
        return jsonify({
            "error": "Internal server error",
            "Credit": "@RichUniversal"
        }), 500

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        "status": "active",
        "Credit": "@RichUniversal",
        "endpoints": ["/api?type=num&key=swayam&query=7811017125"],
        "speed": "Superfast with caching"
    })

def replace_text_recursive(obj, old_text, new_text):
    """Recursively replace text in nested structures"""
    if isinstance(obj, dict):
        return {key: replace_text_recursive(value, old_text, new_text) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [replace_text_recursive(item, old_text, new_text) for item in obj]
    elif isinstance(obj, str):
        return obj.replace(old_text, new_text)
    return obj

# For Vercel serverless
def handler(request, context):
    return app(request.environ, start_response)
