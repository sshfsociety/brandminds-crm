// api/proxy.js — LOCKED DOWN proxy
import fetch from 'node-fetch';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE;
const PROXY_SECRET = process.env.PROXY_SECRET;

// Whitelist of safe write targets (table names or prefixes) that clients may POST to
const SAFE_WRITE_PATHS = [
  'rest/v1/leads'           // public lead ingestion endpoint (bots/WhatsApp)
];

// Sensitive tables that must never be written by clients (even with proxy secret)
const SENSITIVE_TABLES = [
  'users_meta',
  'tenants',
  'audit_logs_v2',
  'payments',
  'user_tenants'
];

function isSensitive(dest) {
  return SENSITIVE_TABLES.some(t => dest.startsWith(`rest/v1/${t}`) || dest.includes(`${t}?`));
}

export default async function handler(req, res) {
  try {
    const secret = (req.headers['x-proxy-secret'] || '').toString();
    if (!secret || secret !== PROXY_SECRET) {
      return res.status(401).json({ error: 'invalid proxy secret' });
    }

    const dest = (req.headers['x-dest-path'] || '').toString().trim();
    if (!dest) return res.status(400).json({ error: 'missing x-dest-path header' });

    const method = (req.method || 'GET').toUpperCase();

    // Deny client writes on sensitive tables
    if (['POST','PUT','PATCH','DELETE'].includes(method) && isSensitive(dest)) {
      return res.status(403).json({ error: 'destination is protected' });
    }

    // If method is a write, ensure destination is explicitly allowed
    if (['POST','PUT','PATCH','DELETE'].includes(method)) {
      const allowed = SAFE_WRITE_PATHS.some(p => dest.startsWith(p));
      if (!allowed) {
        return res.status(403).json({ error: 'write to destination not allowed' });
      }
    }

    const destUrl = `${SUPABASE_URL}/${dest}`;

    // Copy all headers except host and secrets
    const forwardHeaders = { ...req.headers };
    delete forwardHeaders.host;
    delete forwardHeaders['x-proxy-secret'];
    delete forwardHeaders['x-dest-path'];

    // Force service-role auth on forwarded request so it can read protected rows when necessary
    forwardHeaders['apikey'] = SERVICE_ROLE_KEY;
    forwardHeaders['Authorization'] = `Bearer ${SERVICE_ROLE_KEY}`;

    const body = ['GET','HEAD','DELETE'].includes(method) ? undefined : JSON.stringify(req.body);

    const r = await fetch(destUrl, {
      method,
      headers: forwardHeaders,
      body
    });

    const text = await r.text();
    try {
      return res.status(r.status).json(JSON.parse(text));
    } catch (e) {
      return res.status(r.status).send(text);
    }
  } catch (err) {
    console.error('proxy runtime error', String(err));
    return res.status(500).json({ error: 'proxy runtime error', detail: String(err) });
  }
}
