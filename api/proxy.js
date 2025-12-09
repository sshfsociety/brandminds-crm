// api/proxy/[...path].js
export default async function handler(req, res) {
  try {
    const PROXY_SECRET = process.env.PROXY_SECRET;
    const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE || process.env.SUPABASE_SERVICE_ROLE_KEY;
    const SUPABASE_URL = process.env.SUPABASE_URL;

    // secret check
    const secret = req.headers['x-proxy-secret'] || req.headers['x-api-key'];
    if (!secret || secret !== PROXY_SECRET) {
      return res.status(401).json({ error: 'invalid proxy secret' });
    }

    // path assembly
    const pathArray = req.query.path || [];
    const destPath = Array.isArray(pathArray) ? pathArray.join('/') : String(pathArray || '');
    const headerDest = req.headers['x-dest-path'];
    const finalPath = headerDest ? headerDest : destPath;
    const destUrl = SUPABASE_URL.replace(/\/+$/,'') + '/' + finalPath.replace(/^\/+/,'');
    
    // forward headers
    const forwardHeaders = {
      apikey: SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
    };
    if (req.headers['content-type']) forwardHeaders['Content-Type'] = req.headers['content-type'];

    // body handling
    let body = undefined;
    if (!['GET','HEAD','DELETE'].includes(req.method)) {
      try { body = JSON.stringify(req.body === undefined ? {} : req.body); }
      catch(e) { body = undefined; }
    }

    const r = await fetch(destUrl, { method: req.method, headers: forwardHeaders, body });
    const text = await r.text();
    try {
      const json = JSON.parse(text);
      return res.status(r.status).json(json);
    } catch (e) {
      return res.status(r.status).send(text);
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'proxy error', detail: String(err) });
  }
}
