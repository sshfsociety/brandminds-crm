// api/proxy.js
// Hardened proxy: whitelist paths, forward safe headers, return JSON or text.

export default async function handler(req, res) {
  try {
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE;
    const PROXY_SECRET = process.env.PROXY_SECRET;

    const secret = (req.headers['x-proxy-secret'] || req.headers['x-api-key'] || '').toString();
    if (!secret || secret !== PROXY_SECRET) {
      return res.status(401).json({ error: 'invalid proxy secret' });
    }

    const dest = (req.headers['x-dest-path'] || '').toString().trim();
    if (!dest) return res.status(400).json({ error: 'missing x-dest-path header' });

    // BASIC WHITELIST: only allow forwarding to rest/v1/* and auth/v1/*
    if (!dest.startsWith('rest/v1/') && !dest.startsWith('auth/v1/')) {
      return res.status(403).json({ error: 'destination not allowed' });
    }

    // Build destination URL (preserve querystring contained in dest)
    const destUrl = `${SUPABASE_URL}/${dest}`;

    // Forward only these safe headers (allow Prefer and Content-Type)
    const forwardHeaders = {
      'apikey': SERVICE_ROLE_KEY,
      'Authorization': `Bearer ${SERVICE_ROLE_KEY}`,
    };
    if (req.headers['content-type']) forwardHeaders['Content-Type'] = req.headers['content-type'];
    if (req.headers['prefer']) forwardHeaders['Prefer'] = req.headers['prefer'];

    // Allow client to forward a small safe set (optional): X-Request-ID
    if (req.headers['x-request-id']) forwardHeaders['x-request-id'] = req.headers['x-request-id'];

    const body = ['GET','HEAD','DELETE'].includes(req.method) ? undefined : JSON.stringify(req.body);

    const r = await fetch(destUrl, {
      method: req.method,
      headers: forwardHeaders,
      body
    });

    const text = await r.text();
    try {
      const json = JSON.parse(text);
      return res.status(r.status).json(json);
    } catch {
      return res.status(r.status).send(text);
    }
  } catch (err) {
    console.error('proxy runtime error', String(err));
    return res.status(500).json({ error: 'proxy runtime error', detail: String(err) });
  }
}
