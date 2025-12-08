// api/proxy.js
// Simple proxy endpoint. Forwards any path in "x-dest-path" header to your Supabase service role.
// Use this for testing; later we can replace it with the catch-all version.

export default async function handler(req, res) {
  try {
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE;
    const PROXY_SECRET = process.env.PROXY_SECRET;

    // quick header-based secret check
    const secret = (req.headers['x-proxy-secret'] || req.headers['x-api-key'] || '').toString();
    if (!secret || secret !== PROXY_SECRET) {
      return res.status(401).json({ error: 'invalid proxy secret' });
    }

    // Destination path must be provided as a header for the simple tester:
    // Example: x-dest-path: rest/v1/leads?id=eq.123
    const dest = req.headers['x-dest-path'];
    if (!dest) {
      return res.status(400).json({ error: 'missing x-dest-path header (e.g. rest/v1/leads)' });
    }

    // build URL
    const destUrl = `${SUPABASE_URL}/${dest}`;

    // forward headers
    const forwardHeaders = {
      apikey: SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
      ...(req.headers['content-type'] ? { 'Content-Type': req.headers['content-type'] } : {})
    };

    const body = ['GET','HEAD','DELETE'].includes(req.method) ? undefined : JSON.stringify(req.body);

    const r = await fetch(destUrl, {
      method: req.method,
      headers: forwardHeaders,
      body
    });

    const text = await r.text();
    // try parse JSON, otherwise send text
    try { return res.status(r.status).json(JSON.parse(text)); } catch (e) { return res.status(r.status).send(text); }
  } catch (err) {
    console.error('proxy runtime error', String(err));
    return res.status(500).json({ error: 'proxy runtime error', detail: String(err) });
  }
}
