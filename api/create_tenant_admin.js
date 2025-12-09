// api/create_tenant_admin.js
// Minimal Vercel Serverless function using Supabase service role
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE,
  { auth: { persistSession: false } }
);

// ----------------- AUDIT HELPER -----------------
async function audit_create_tenant_admin({ tenant_id, userId, email, actor_id = null }) {
  try {
    await fetch(`${process.env.SUPABASE_URL}/rest/v1/audit_logs_v2`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': process.env.SUPABASE_SERVICE_ROLE,
        'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE}`
      },
      body: JSON.stringify({
        tenant_id: tenant_id,
        actor_id: actor_id,
        actor_role: 'super_admin',
        action: 'create_tenant_admin',
        object_type: 'users_meta',
        object_id: userId,
        details: { id: userId, email: email, tenant_id: tenant_id },
        created_at: new Date().toISOString()
      })
    });
  } catch (err) {
    // Do not fail the whole request if audit fails — just log it.
    console.error('audit write failed', String(err));
  }
}
// ----------------- END AUDIT HELPER -----------------

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

    // --- AUDIT CALL: record the provisioning action ---
    // This runs server-side using the service role key.
    await audit_create_tenant_admin({ tenant_id, userId, email, actor_id: null });

    // Return success
    return res.status(200).json({ ok: true, userId });
  } catch (err) {
    console.error('create_tenant_admin error', err);
    // If Supabase returns an object error.message may exist; handle both forms.
    const msg = err && err.message ? err.message : String(err);
    return res.status(500).json({ error: msg });
  }
}
