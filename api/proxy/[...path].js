// api/proxy/[...path].js
export default async function handler(req, res) {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const PROXY_SECRET = process.env.PROXY_SECRET;

  try {
    const secret = req.headers['x-proxy-secret'] || req.headers['x-api-key'];
    if (!secret || secret !== PROXY_SECRET) {
      return res.status(401).json({ error: 'invalid proxy secret' });
    }

    const pathArray = req.query.path || [];
    const destPath = Array.isArray(pathArray) ? pathArray.join('/') : pathArray;
    const qs = req.url.split('?')[1] || '';
    const destUrl = `${SUPABASE_URL}/${destPath}${qs ? ('?' + qs) : ''}`;

    const forwardHeaders = {
      'apikey': SERVICE_ROLE_KEY,
      'Authorization': `Bearer ${SERVICE_ROLE_KEY}`,
      ...(req.headers['content-type'] ? { 'Content-Type': req.headers['content-type'] } : {})
    };

    const init = {
      method: req.method,
      headers: forwardHeaders,
      body: ['GET','HEAD','DELETE'].includes(req.method) ? undefined : JSON.stringify(req.body)
    };

    const r = await fetch(destUrl, init);
    const text = await r.text();

    try { return res.status(r.status).json(JSON.parse(text)); } 
    catch { return res.status(r.status).send(text); }
  } catch (err) {
    console.error('proxy error', err);
    return res.status(500).json({ error: 'proxy error', detail: String(err) });
  }
}
