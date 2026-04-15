// api/kv-check.js
// Tells the frontend whether Vercel KV is configured

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  
  const kvConfigured = !!(
    process.env.KV_REST_API_URL && 
    process.env.KV_REST_API_TOKEN
  );

  res.status(200).json({ kv: kvConfigured });
}
