// api/proxy/[...path].js
// Simple proxy that forwards requests to Supabase using the service role key.
// Protects the service role behind an X-Proxy-Secret header.

const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE || process.env.SUPABASE_SERVICE_ROLE_KEY;
const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/,'');
const PROXY_SECRET = process.env.PROXY_SECRET || process.env.INTERNAL_TOKEN;

export default async function handler(req, res) {
  try {
    const incomingSecret = (req.headers['x-proxy-secret'] || req.headers['x-api-key'] || req.headers['x-internal-token'] || '').toString();
    if (!incomingSecret || incomingSecret !== PROXY_SECRET) {
      return res.status(401).json({ error: 'invalid proxy secret' });
    }

    const headerPath = req.headers['x-dest-path'];
    const routePath = Array.isArray(req.query.path) ? req.query.path.join('/') : (req.query.path || '');
    const destPath = headerPath ? headerPath : routePath;
    if (!destPath) return res.status(400).json({ error: 'missing destination path (x-dest-path or route)' });

    const destUrl = `${SUPABASE_URL.replace(/\/$/,'')}/${destPath.replace(/^\/+/,'')}`;

    const forwardHeaders = {
      'apikey': SERVICE_ROLE_KEY,
      'Authorization': `Bearer ${SERVICE_ROLE_KEY}`,
      ...(req.headers['content-type'] ? { 'Content-Type': req.headers['content-type'] } : {})
    };

    let body;
    if (['GET','HEAD'].includes(req.method)) {
      body = undefined;
    } else {
      if (req.body && Object.keys(req.body).length) {
        body = JSON.stringify(req.body);
      } else {
        body = await new Promise((resolve, reject) => {
          let data = [];
          req.on('data', chunk => data.push(chunk));
          req.on('end', () => resolve(Buffer.concat(data).toString('utf8')));
          req.on('error', err => reject(err));
        });
        if (!body) body = undefined;
      }
    }

    const init = { method: req.method, headers: forwardHeaders, body };
    const r = await fetch(destUrl, init);
    const text = await r.text();
    const contentType = r.headers.get('content-type') || '';

    if (contentType.includes('application/json')) {
      try { return res.status(r.status).json(JSON.parse(text)); } 
      catch (e) { return res.status(r.status).send(text); }
    } else {
      return res.status(r.status).send(text);
    }
  } catch (err) {
    console.error('proxy error', String(err));
    return res.status(500).json({ error: 'proxy error', detail: String(err) });
  }
}
