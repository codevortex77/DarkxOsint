module.exports = function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  const kvConfigured = !!(
    process.env.KV_REST_API_URL &&
    process.env.KV_REST_API_TOKEN
  );

  res.status(200).json({ kv: kvConfigured });
};
