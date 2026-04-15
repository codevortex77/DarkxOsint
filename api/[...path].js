// api/[...path].js - DARKXOSINT API Proxy Handler
// This runs on Vercel as a serverless function

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const pathParts = req.query.path || [];
  
  // Route: /api/proxy/[endpoint]?param=value
  if (pathParts[0] === 'proxy' && pathParts[1]) {
    return handleProxy(req, res, pathParts[1]);
  }

  // Route: /api/data - for saving/loading panel data
  if (pathParts[0] === 'data') {
    return handleData(req, res);
  }

  return res.status(404).json({ error: 'Route not found' });
}

// ======= PROXY HANDLER =======
async function handleProxy(req, res, endpoint) {
  // In production, this reads from a KV store or DB
  // For now we read from a local JSON file (or you can use Vercel KV)
  
  try {
    // Get API config - in production use Vercel KV or similar
    // For demo, we'll use the request headers to pass config
    const apiKey = req.headers['x-api-key'] || req.query.apikey;
    
    if (!apiKey) {
      return res.status(401).json({
        status: 'error',
        message: 'API key required. Add ?apikey=YOUR_KEY',
        powered_by: 'DARKXOSINT by @CyberXylus'
      });
    }

    // Build upstream URL - in production this comes from your DB
    // The panel stores config in localStorage; for server-side proxying
    // you'd store in Vercel KV. See README for setup.
    const upstreamBase = req.headers['x-upstream-url'];
    
    if (!upstreamBase) {
      return res.status(503).json({
        status: 'error', 
        message: 'API not configured for server-side proxying yet.',
        note: 'This panel works in client-side mode. See README.md for Vercel KV setup.',
        powered_by: 'DARKXOSINT by @CyberXylus'
      });
    }

    // Get param value from query
    const paramKeys = Object.keys(req.query).filter(k => k !== 'apikey');
    const paramVal = paramKeys.length ? req.query[paramKeys[0]] : '';

    const upstreamURL = upstreamBase + encodeURIComponent(paramVal);
    
    const upstream = await fetch(upstreamURL, {
      headers: { 'User-Agent': 'DARKXOSINT-Gateway/2.0' }
    });

    let data = await upstream.json();

    // Apply transformations from config
    const config = req.headers['x-api-config'] ? JSON.parse(req.headers['x-api-config']) : {};

    // Hide fields
    if (config.hideFields && config.hiddenFields) {
      const fields = config.hiddenFields.split(',').map(f => f.trim());
      fields.forEach(f => { if (f) delete data[f]; });
    }

    // Replace credit fields
    if (config.replaceCredit && config.replaceFields) {
      const fields = config.replaceFields.split(',').map(f => f.trim());
      fields.forEach(f => {
        if (f && data[f] !== undefined) data[f] = config.replaceWith || '@CyberXylus';
      });
    }

    // Add powered by
    if (config.poweredBy !== false) {
      data.powered_by = config.poweredByTag || 'API Powered By @CyberXylus';
    }

    return res.status(200).json(data);

  } catch (err) {
    return res.status(500).json({
      status: 'error',
      message: 'Gateway error: ' + err.message,
      powered_by: 'DARKXOSINT by @CyberXylus'
    });
  }
}

// ======= DATA HANDLER =======
async function handleData(req, res) {
  // Placeholder - in production use Vercel KV
  return res.status(200).json({ status: 'ok', message: 'Use client-side storage or add Vercel KV' });
}
