from flask import Flask, request, jsonify
import requests
import time

app = Flask(__name__)

# Simple cache
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

def clean_response(data):
    """Clean the response and add credit"""
    if isinstance(data, dict):
        # Create new dict without unwanted fields
        cleaned = {}
        for key, value in data.items():
            # Skip unwanted fields
            if key in ['req_left', 'req_total', 'expiry', 'developer']:
                continue
            # Replace @simpleguy444 with @RichUniversal
            if isinstance(value, str):
                cleaned[key] = value.replace('@simpleguy444', '@RichUniversal')
            elif isinstance(value, (dict, list)):
                cleaned[key] = clean_response(value)
            else:
                cleaned[key] = value
        
        # Add Credit
        cleaned['Credit'] = '@RichUniversal'
        return cleaned
    elif isinstance(data, list):
        return [clean_response(item) for item in data]
    elif isinstance(data, str):
        return data.replace('@simpleguy444', '@RichUniversal')
    return data

@app.route('/api', methods=['GET'])
def api_handler():
    query_type = request.args.get('type', 'num')
    query_key = request.args.get('key', 'swayam')
    query_value = request.args.get('query', '')
    
    if not query_value:
        return jsonify({"error": "Query parameter required", "Credit": "@RichUniversal"}), 400
    
    # Create cache key
    cache_key = f"{query_type}:{query_key}:{query_value}"
    
    # Check cache
    cached_response = get_cached_response(cache_key)
    if cached_response:
        return jsonify(cached_response)
    
    try:
        # Request to original API
        original_url = f"https://rootx-osint.in/?type={query_type}&key={query_key}&query={query_value}"
        
        response = requests.get(original_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Clean the response
            cleaned_data = clean_response(data)
            
            # Cache it
            set_cache(cache_key, cleaned_data)
            
            return jsonify(cleaned_data)
        else:
            return jsonify({"error": "Failed to fetch data", "Credit": "@RichUniversal"}), 500
            
    except Exception as e:
        return jsonify({
            "error": str(e),
            "Credit": "@RichUniversal"
        }), 500

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        "status": "active",
        "Credit": "@RichUniversal",
        "usage": "/api?type=num&query=7811017125"
    })

# Vercel handler
def handler(request, context):
    return app(request.environ, start_response)
