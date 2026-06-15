import { createClient } from '@supabase/supabase-js';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const AFRIPAY_APP_ID = process.env.AFRIPAY_APP_ID;
const DOWNLOAD_WINDOW_MINUTES = 30;

const rateMap = new Map();

function rateLimit(ip) {
    const now = Date.now();
    const w = 60000;
    if (!rateMap.has(ip)) rateMap.set(ip, []);
    const reqs = rateMap.get(ip).filter(t => t > now - w);
    rateMap.set(ip, reqs);
    if (reqs.length >= 30) return false;
    reqs.push(now);
    return true;
}

function vt(t) { return /^[a-zA-Z0-9_]{20,80}$/.test(t); }
function vf(f) { return typeof f === 'string' && f.length >= 10 && f.length <= 200; }
function vu(id) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id); }

function setCORS(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Content-Type', 'application/json');
}

async function isAdmin(req) {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) return false;
    const key = auth.slice(7);
    const { data } = await supabase.from('admin_keys').select('key_hash');
    if (!data?.length) return false;
    for (const r of data) {
        const { data: m } = await supabase.rpc('verify_admin_key', { input_key: key, stored_hash: r.key_hash });
        if (m) return true;
    }
    return false;
}

export default async function handler(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;
    const method = req.method;
    const ip = req.headers['x-forwarded-for'] || 'unknown';

    setCORS(res);
    if (method === 'OPTIONS') return res.status(200).end();
    if (method === 'POST' && path !== '/api/callback' && !path.startsWith('/api/admin/upload')) {
        if (!rateLimit(ip)) return res.status(429).json({ error: 'Too many requests' });
    }

    try {

        // GET all active documents
        if (path === '/api/documents' && method === 'GET') {
            const { data, error } = await supabase
                .from('documents')
                .select('id,title,description,image_url,price,currency,clicks,created_at')
                .eq('active', true)
                .order('created_at', { ascending: false });
            if (error) return res.status(500).json({ error: 'Failed to fetch documents' });
            return res.status(200).json(data || []);
        }

        // GET single document
        if (path.match(/^\/api\/documents\/[a-f0-9-]+$/) && method === 'GET') {
            const docId = path.split('/').pop();
            if (!vu(docId)) return res.status(400).json({ error: 'Invalid ID' });
            const { data, error } = await supabase
                .from('documents')
                .select('id,title,description,image_url,price,currency,clicks,created_at')
                .eq('id', docId).eq('active', true).single();
            if (error || !data) return res.status(404).json({ error: 'Not found' });
            return res.status(200).json(data);
        }

        // Track click
        if (path.match(/^\/api\/documents\/[a-f0-9-]+\/click$/) && method === 'POST') {
            const docId = path.split('/')[3];
            if (!vu(docId)) return res.status(400).json({ error: 'Invalid ID' });
            await supabase.rpc('increment_click', { doc_id: docId });
            return res.status(200).json({ ok: true });
        }

        // Init payment
        if (path === '/api/init-payment' && method === 'POST') {
            const { document_id, device_fingerprint, client_token } = req.body;
            if (!vu(document_id) || !vf(device_fingerprint) || !vt(client_token))
                return res.status(400).json({ error: 'Invalid parameters' });

            const { data: exist } = await supabase.from('payments')
                .select('id').eq('device_fingerprint', device_fingerprint)
                .eq('document_id', document_id).eq('status', 'completed').limit(1);
            if (exist?.length) return res.status(200).json({ already_paid: true });

            const { data: doc, error: derr } = await supabase.from('documents')
                .select('price,currency,title').eq('id', document_id).eq('active', true).single();
            if (derr || !doc) return res.status(404).json({ error: 'Not found' });

            await supabase.from('payments').insert({
                document_id, device_fingerprint, client_token,
                amount: doc.price, currency: doc.currency, status: 'pending'
            });
            return res.status(200).json({ success: true, amount: doc.price, currency: doc.currency, title: doc.title });
        }

        // Check payment
        if (path === '/api/check-payment' && method === 'POST') {
            const { client_token, device_fingerprint, document_id } = req.body;
            if (client_token) {
                if (!vt(client_token)) return res.status(400).json({ error: 'Invalid token' });
                const { data } = await supabase.from('payments')
                    .select('status,document_id,amount,currency,created_at').eq('client_token', client_token).single();
                if (!data) return res.status(404).json({ error: 'Not found' });
                return res.status(200).json({
                    paid: data.status === 'completed',
                    status: data.status,
                    document_id: data.document_id,
                    amount: data.amount,
                    currency: data.currency,
                    created_at: data.created_at
                });
            }
            if (device_fingerprint && document_id) {
                if (!vf(device_fingerprint) || !vu(document_id)) return res.status(400).json({ error: 'Invalid params' });
                const { data } = await supabase.from('payments')
                    .select('id,status,created_at').eq('device_fingerprint', device_fingerprint)
                    .eq('document_id', document_id).eq('status', 'completed').limit(1);
                return res.status(200).json({
                    already_paid: data?.length > 0,
                    payment: data?.[0] || null
                });
            }
            return res.status(400).json({ error: 'Missing params' });
        }

        // Download
        if (path === '/api/download' && method === 'POST') {
            const { client_token, device_fingerprint, document_id } = req.body;
            if (!vt(client_token) || !vf(device_fingerprint) || !vu(document_id))
                return res.status(400).json({ error: 'Invalid parameters' });

            const { data: payment } = await supabase.from('payments')
                .select('*').eq('client_token', client_token)
                .eq('device_fingerprint', device_fingerprint)
                .eq('document_id', document_id).eq('status', 'completed').single();

            if (!payment) return res.status(403).json({ error: 'Payment not confirmed' });

            // Check 30-minute window
            const paidAt = new Date(payment.created_at);
            const now = new Date();
            const diffMinutes = (now - paidAt) / 60000;

            if (diffMinutes > DOWNLOAD_WINDOW_MINUTES) {
                return res.status(410).json({ error: 'Download window expired. Please purchase again.' });
            }

            const { data: doc } = await supabase.from('documents').select('file_path').eq('id', document_id).single();
            if (!doc) return res.status(404).json({ error: 'Not found' });

            const { data: signed } = await supabase.storage.from('documents').createSignedUrl(doc.file_path, 600);
            if (!signed) return res.status(500).json({ error: 'Link failed' });

            await supabase.from('payments').update({ downloaded: true, downloaded_at: new Date().toISOString() }).eq('id', payment.id);
            return res.status(200).json({ url: signed.signedUrl, expires_in_minutes: Math.max(0, Math.floor(DOWNLOAD_WINDOW_MINUTES - diffMinutes)) });
        }

        // User payments history
        if (path === '/api/user-payments' && method === 'POST') {
            const { device_fingerprint } = req.body;
            if (!vf(device_fingerprint)) return res.status(400).json({ error: 'Invalid fingerprint' });

            const { data, error } = await supabase.from('payments')
                .select('id, document_id, amount, currency, status, transaction_ref, payment_method, downloaded, created_at, downloaded_at')
                .eq('device_fingerprint', device_fingerprint)
                .order('created_at', { ascending: false })
                .limit(50);

            if (error) return res.status(500).json({ error: 'Failed to fetch' });

            // Enrich with document info
            const enriched = [];
            for (const p of (data || [])) {
                const { data: doc } = await supabase.from('documents')
                    .select('title, image_url').eq('id', p.document_id).single();
                enriched.push({ ...p, document_title: doc?.title || 'Unknown', document_image: doc?.image_url || '' });
            }

            return res.status(200).json(enriched);
        }

        // AfriPay callback
        if (path === '/api/callback' && method === 'POST') {
            const { status, transaction_ref, client_token, amount, payment_method } = req.body;
            console.log('[Callback]', JSON.stringify({ status, transaction_ref, client_token }));

            if (!client_token) return res.status(200).json({ received: true, note: 'Missing token' });
            if (!vt(client_token)) return res.status(200).json({ received: true, note: 'Invalid format' });

            const { data: payment, error: ferr } = await supabase.from('payments')
                .select('id,amount,status').eq('client_token', client_token).single();

            if (ferr || !payment) return res.status(200).json({ received: true, note: 'Not found' });
            if (payment.status === 'completed') return res.status(200).json({ received: true, note: 'Already done' });

            if (status === 'success') {
                await supabase.from('payments').update({
                    status: 'completed', transaction_ref: transaction_ref || null,
                    payment_method: payment_method || null,
                    amount: parseInt(amount) || payment.amount
                }).eq('client_token', client_token).eq('status', 'pending');
            } else {
                await supabase.from('payments').update({
                    status: 'failed', transaction_ref: transaction_ref || null
                }).eq('client_token', client_token).eq('status', 'pending');
            }

            return res.status(200).json({ received: true });
        }

        // Admin verify
        if (path === '/api/admin/verify' && method === 'POST') {
            return res.status(200).json({ authenticated: await isAdmin(req) });
        }

        // Admin upload
        if (path === '/api/admin/upload' && method === 'POST') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });
            const ct = req.headers['content-type'] || '';
            if (!ct.includes('multipart/form-data')) return res.status(400).json({ error: 'Expected file' });
            const boundary = ct.split('boundary=')[1];
            if (!boundary) return res.status(400).json({ error: 'No boundary' });
            const chunks = [];
            for await (const c of req) chunks.push(c);
            const body = Buffer.concat(chunks).toString();
            const parts = body.split('--' + boundary);
            let fb = null, fn = null, ft = null;
            for (const part of parts) {
                if (part.includes('filename=')) {
                    const he = part.indexOf('\r\n\r\n');
                    if (he === -1) continue;
                    const header = part.substring(0, he);
                    const content = part.substring(he + 4);
                    const fm = header.match(/filename="(.+?)"/);
                    if (fm) fn = fm[1];
                    const tm = header.match(/Content-Type: (.+)/);
                    if (tm) ft = tm[1].trim();
                    fb = Buffer.from(content.replace(/\r\n--$/, '').replace(/--$/, ''), 'binary');
                }
            }
            if (!fb || !fn) return res.status(400).json({ error: 'No file' });
            const safe = `${Date.now()}_${fn.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
            const { error } = await supabase.storage.from('documents').upload(safe, fb, { contentType: ft || 'application/octet-stream', upsert: false });
            if (error) return res.status(500).json({ error: 'Upload failed' });
            return res.status(200).json({ file_path: safe, filename: fn });
        }

        // Admin list documents
        if (path === '/api/admin/documents' && method === 'GET') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });
            const { data, error } = await supabase.from('documents').select('*').order('created_at', { ascending: false });
            if (error) return res.status(500).json({ error: 'Fetch failed' });
            return res.status(200).json(data || []);
        }

        // Admin add document
        if (path === '/api/admin/documents' && method === 'POST') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });
            const { title, description, image_url, file_path, price, currency } = req.body;
            if (!title || title.length > 200) return res.status(400).json({ error: 'Title required' });
            if (!file_path) return res.status(400).json({ error: 'File required' });
            if (!price || isNaN(price) || parseInt(price) <= 0) return res.status(400).json({ error: 'Price required' });
            const { data, error } = await supabase.from('documents').insert({
                title: title.trim(), description: (description || '').trim(),
                image_url: (image_url || '').trim(), file_path: file_path.trim(),
                price: parseInt(price), currency: (currency || 'RWF').toUpperCase(), active: true
            }).select().single();
            if (error) return res.status(500).json({ error: 'Insert failed' });
            return res.status(201).json(data);
        }

        // Admin delete
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+$/) && method === 'DELETE') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });
            const docId = path.split('/').pop();
            const { data: doc } = await supabase.from('documents').select('file_path').eq('id', docId).single();
            if (doc?.file_path) await supabase.storage.from('documents').remove([doc.file_path]);
            await supabase.from('documents').delete().eq('id', docId);
            return res.status(200).json({ success: true });
        }

        // Admin toggle
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+\/toggle$/) && method === 'PUT') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });
            const docId = path.split('/')[4];
            const { data: doc } = await supabase.from('documents').select('active').eq('id', docId).single();
            if (!doc) return res.status(404).json({ error: 'Not found' });
            await supabase.from('documents').update({ active: !doc.active }).eq('id', docId);
            return res.status(200).json({ active: !doc.active });
        }

        return res.status(404).json({ error: 'Endpoint not found' });

    } catch (err) {
        console.error('[Handler]', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}
