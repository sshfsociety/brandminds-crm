// Minimal Vercel Serverless function using Supabase service role
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE,
  { auth: { persistSession: false } }
);

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send({ error: 'Method not allowed' });

  // internal token check
  if (req.headers['x-internal-token'] !== process.env.INTERNAL_TOKEN) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const { email, password, display_name, tenant_id, created_by } = req.body || {};
  if (!email || !password || !tenant_id) return res.status(400).json({ error: 'missing fields' });

  try {
    // Create auth user
    const { data: authData, error: createErr } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true
    });
    if (createErr) throw createErr;

    const userId = authData.user.id;

    // Insert into users_meta
    const { error: insertErr } = await supabase
      .from('users_meta')
      .insert({
        id: userId,
        tenant_id,
        role: 'tenant_admin',
        display_name: display_name || '',
        must_change_password: true,
        is_active: true,
        created_at: new Date().toISOString()
      });

    if (insertErr) throw insertErr;

    return res.status(200).json({ ok: true, userId });
  } catch (err) {
    console.error('create_tenant_admin error', err);
    return res.status(500).json({ error: err.message || err });
  }
}
