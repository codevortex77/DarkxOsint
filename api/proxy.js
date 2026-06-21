const CACHE = new Map();
const CACHE_TTL = 300000; // 5 minutes
const TIMEOUT = 5000; // 5 second upstream timeout

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Cache-Control', 's-maxage=300, stale-while-revalidate=60');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  try {
    const { type, key, query } = req.query;
    if (!type || !key || !query) {
      return res.status(400).json({ error: 'Missing parameters' });
    }

    const cacheKey = `${type}|${key}|${query}`;
    const cached = CACHE.get(cacheKey);
    if (cached && Date.now() - cached.time < CACHE_TTL) {
      return res.status(200).json(cached.data);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT);

    const response = await fetch(`https://rootx-osint.in/?type=${type}&key=${key}&query=${query}`, {
      signal: controller.signal,
      headers: { 'Accept-Encoding': 'gzip' }
    });
    clearTimeout(timeout);

    const text = await response.text();
    const cleaned = text
      .replace(/"req_left":\d+,?/g, '')
      .replace(/"req_total":\d+,?/g, '')
      .replace(/"expiry":"[^"]+",?/g, '')
      .replace(/"developer":"@simpleguy444"/g, '"Credit":"@RichUniversal"')
      .replace(/,}/g, '}')
      .replace(/{,/g, '{');

    const data = JSON.parse(cleaned);
    CACHE.set(cacheKey, { data, time: Date.now() });
    
    return res.status(200).json(data);
  } catch (error) {
    return res.status(500).json({ error: 'Request failed' });
  }
}
