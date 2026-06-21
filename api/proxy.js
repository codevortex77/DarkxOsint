export const config = {
  runtime: 'edge',
};

const CACHE = caches.default;
const UPSTREAM = 'https://rootx-osint.in'; // Never exposed

export default async function handler(req) {
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
      },
    });
  }

  try {
    const url = new URL(req.url);
    const type = url.searchParams.get('type');
    const key = url.searchParams.get('key');
    const query = url.searchParams.get('query');

    if (!type || !key || !query) {
      return new Response(JSON.stringify({ error: 'Missing parameters' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    // Sanitize inputs to prevent injection
    const safeType = type.replace(/[^a-zA-Z]/g, '');
    const safeKey = key.replace(/[^a-zA-Z0-9_@.-]/g, '');
    const safeQuery = query.replace(/[^0-9]/g, '');

    const cacheKey = new Request(`https://cache/?t=${safeType}&k=${safeKey}&q=${safeQuery}`);
    const cached = await CACHE.match(cacheKey);
    if (cached) return cached;

    const upstream = `${UPSTREAM}/?type=${safeType}&key=${safeKey}&query=${safeQuery}`;
    const response = await fetch(upstream);

    if (!response.ok) {
      throw new Error();
    }

    const text = await response.text();

    const cleaned = text
      .replace(/"req_left":\d+,?/g, '')
      .replace(/"req_total":\d+,?/g, '')
      .replace(/"expiry":"[^"]+",?/g, '')
      .replace(/"developer":"@simpleguy444"/g, '"Credit":"@RichUniversal"')
      .replace(/,}/g, '}')
      .replace(/{,/g, '{');

    const result = new Response(cleaned, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, s-maxage=300, stale-while-revalidate=60',
      },
    });

    await CACHE.put(cacheKey, result.clone());
    return result;
  } catch (error) {
    // Generic error - never expose upstream details
    return new Response(JSON.stringify({ error: 'Service temporarily unavailable' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }
}
