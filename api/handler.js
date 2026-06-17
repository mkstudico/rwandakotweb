import { createClient } from '@supabase/supabase-js';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const RWANDAPAY_BASE = 'https://pay.rwandapay.rw/api/v1';
const RWANDAPAY_PUBLIC_KEY = process.env.RWANDAPAY_PUBLIC_KEY;
const RWANDAPAY_SECRET_KEY = process.env.RWANDAPAY_SECRET_KEY;
const RWANDAPAY_WEBHOOK_SECRET = process.env.RWANDAPAY_WEBHOOK_SECRET;
const DOWNLOAD_WINDOW_MINUTES = 30;
const rateMap = new Map();

function rateLimit(ip) { const now = Date.now(), w = 60000; if (!rateMap.has(ip)) rateMap.set(ip, []); const reqs = rateMap.get(ip).filter(t => t > now - w); rateMap.set(ip, reqs); if (reqs.length >= 30) return false; reqs.push(now); return true; }
function vt(t) { return /^[a-zA-Z0-9_]{20,80}$/.test(t); }
function vf(f) { return typeof f === 'string' && f.length >= 10 && f.length <= 200; }
function vu(id) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id); }
function vphone(p) { return /^0?7[89]\d{7}$/.test((p||'').replace(/\s/g,'')); }
function setCORS(res) { res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization'); res.setHeader('Content-Type', 'application/json'); }
async function isAdmin(req) { const auth = req.headers.authorization; if (!auth?.startsWith('Bearer ')) return false; const key = auth.slice(7); const { data } = await supabase.from('admin_keys').select('key_hash'); if (!data?.length) return false; for (const r of data) { const { data: m } = await supabase.rpc('verify_admin_key', { input_key: key, stored_hash: r.key_hash }); if (m) return true; } return false; }

export default async function handler(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname, method = req.method, ip = req.headers['x-forwarded-for'] || 'unknown';
    setCORS(res);
    if (method === 'OPTIONS') return res.status(200).end();
    if (method === 'POST' && path !== '/api/rwandapay-callback' && !path.startsWith('/api/admin/upload')) { if (!rateLimit(ip)) return res.status(429).json({ error: 'Too many requests' }); }
    try {
        if (path === '/api/documents' && method === 'GET') { const { data, error } = await supabase.from('documents').select('id,title,description,image_url,price,currency,clicks,created_at').eq('active', true).order('created_at', { ascending: false }); if (error) return res.status(500).json({ error: 'Failed' }); return res.status(200).json(data || []); }
        if (path.match(/^\/api\/documents\/[a-f0-9-]+$/) && method === 'GET') { const docId = path.split('/').pop(); if (!vu(docId)) return res.status(400).json({ error: 'Invalid ID' }); const { data, error } = await supabase.from('documents').select('id,title,description,image_url,price,currency,clicks,created_at').eq('id', docId).eq('active', true).single(); if (error || !data) return res.status(404).json({ error: 'Not found' }); return res.status(200).json(data); }
        if (path.match(/^\/api\/documents\/[a-f0-9-]+\/click$/) && method === 'POST') { const docId = path.split('/')[3]; if (!vu(docId)) return res.status(400).json({ error: 'Invalid ID' }); await supabase.rpc('increment_click', { doc_id: docId }); return res.status(200).json({ ok: true }); }

        // RwandaPay Init
        if (path === '/api/rwandapay-init' && method === 'POST') {
            const { document_id, device_fingerprint, phone, client_token, customer_name } = req.body;
            if (!vu(document_id) || !vf(device_fingerprint) || !vphone(phone) || !vt(client_token)) return res.status(400).json({ error: 'Invalid params' });
            
            // Check env vars
            if (!RWANDAPAY_PUBLIC_KEY || !RWANDAPAY_SECRET_KEY) {
                console.error('Missing RwandaPay keys');
                return res.status(500).json({ error: 'Payment configuration error' });
            }

            const { data: exist } = await supabase.from('payments').select('id, created_at').eq('device_fingerprint', device_fingerprint).eq('document_id', document_id).eq('status', 'completed').limit(1);
            if (exist?.length && (Date.now() - new Date(exist[0].created_at).getTime()) / 60000 <= DOWNLOAD_WINDOW_MINUTES) return res.status(200).json({ already_paid: true });
            const { data: doc, error: docErr } = await supabase.from('documents').select('price,currency,title').eq('id', document_id).eq('active', true).single();
            if (docErr || !doc) return res.status(404).json({ error: 'Not found' });
            await supabase.from('payments').insert({ document_id, device_fingerprint, client_token, amount: doc.price, currency: doc.currency, status: 'pending', payment_method: 'rwandapay' });
            let np = phone.replace(/\s/g, ''); if (np.startsWith('0')) np = np.substring(1);
            const cname = (customer_name || '').trim() || 'Customer';
            const rpBody = { amount: parseInt(doc.price), tx_ref: client_token, currency: doc.currency || 'RWF', customer: { name: cname, email: cname.toLowerCase().replace(/[^a-z0-9]/g, '') + '@kotweb.rw', phone: np }, redirect_url: `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers.host}/view.html?doc=${document_id}&rp_ref=${client_token}`, webhook_url: `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers.host}/api/rwandapay-callback`, description: doc.title || 'Purchase', meta: { document_id, device_fingerprint } };
            try {
                const rpRes = await fetch(`${RWANDAPAY_BASE}/checkout/initialize`, { method: 'POST', headers: { 'X-Public-Key': RWANDAPAY_PUBLIC_KEY, 'X-Secret-Key': RWANDAPAY_SECRET_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify(rpBody) });
                const rpData = await rpRes.json();
                if (!rpData.success) {
                    console.error('RwandaPay error:', rpData);
                    return res.status(500).json({ error: rpData.message || 'Payment service error' });
                }
                await supabase.from('payments').update({ transaction_ref: rpData.data.reference || client_token }).eq('client_token', client_token);
                return res.status(200).json({ success: true, payment_url: rpData.data.payment_url, reference: rpData.data.reference || client_token });
            } catch (err) { console.error('RwandaPay fetch error:', err); return res.status(500).json({ error: 'Payment service unavailable' }); }
        }

        // RwandaPay Verify
        if (path === '/api/rwandapay-verify' && method === 'POST') {
            const { reference, client_token, document_id, device_fingerprint } = req.body;
            const ref = reference || client_token;
            try {
                const rpRes = await fetch(`${RWANDAPAY_BASE}/checkout/${ref}/verify`, { headers: { 'Accept': 'application/json' } });
                const rpData = await rpRes.json();
                if (rpData.completed && rpData.success && rpData.status === 'successful') {
                    await supabase.from('payments').update({ status: 'completed', payment_method: 'rwandapay' }).eq('client_token', ref).eq('status', 'pending');
                    await supabase.from('payments').update({ status: 'completed', payment_method: 'rwandapay' }).eq('transaction_ref', ref).eq('status', 'pending');
                    if (device_fingerprint && document_id) {
                        await supabase.from('payments').update({ status: 'completed', payment_method: 'rwandapay' }).eq('device_fingerprint', device_fingerprint).eq('document_id', document_id).eq('status', 'pending');
                    }
                    return res.status(200).json({ verified: true, status: 'completed', document_id });
                }
                if (rpData.completed && !rpData.success) { await supabase.from('payments').update({ status: 'failed' }).eq('client_token', ref).eq('status', 'pending'); await supabase.from('payments').update({ status: 'failed' }).eq('transaction_ref', ref).eq('status', 'pending'); return res.status(200).json({ verified: false, status: 'failed' }); }
                return res.status(200).json({ verified: false, status: rpData.status || 'pending' });
            } catch (err) { return res.status(500).json({ error: 'Verify failed' }); }
        }

        // RwandaPay Webhook
        if (path === '/api/rwandapay-callback' && method === 'POST') {
            let payload; try { const chunks = []; for await (const c of req) chunks.push(c); payload = JSON.parse(Buffer.concat(chunks).toString()); } catch (e) { return res.status(200).json({ received: true }); }
            console.log('[RP Webhook]', JSON.stringify(payload).substring(0, 300));
            const event = payload.event, data = payload.data;
            if ((event === 'payment.successful' || event === 'payment.success') && data?.reference) { const ref = data.reference; await supabase.from('payments').update({ status: 'completed', transaction_ref: data.transaction_id || ref, payment_method: 'rwandapay' }).or(`client_token.eq.${ref},transaction_ref.eq.${ref}`).eq('status', 'pending'); }
            if ((event === 'payment.failed' || event === 'payment.fail') && data?.reference) { await supabase.from('payments').update({ status: 'failed' }).or(`client_token.eq.${data.reference},transaction_ref.eq.${data.reference}`).eq('status', 'pending'); }
            return res.status(200).json({ received: true });
        }

        // Check payment
        if (path === '/api/check-payment' && method === 'POST') {
            const { client_token, device_fingerprint, document_id } = req.body;
            if (client_token) { if (!vt(client_token)) return res.status(400).json({ error: 'Invalid token' }); const { data } = await supabase.from('payments').select('status, document_id, amount, currency, created_at').eq('client_token', client_token).single(); if (!data) return res.status(404).json({ error: 'Not found' }); return res.status(200).json({ paid: data.status === 'completed', status: data.status, document_id: data.document_id, amount: data.amount, currency: data.currency, created_at: data.created_at }); }
            if (device_fingerprint && document_id) { if (!vf(device_fingerprint) || !vu(document_id)) return res.status(400).json({ error: 'Invalid params' }); const { data } = await supabase.from('payments').select('id, status, amount, created_at').eq('device_fingerprint', device_fingerprint).eq('document_id', document_id).order('created_at', { ascending: false }).limit(1); const found = data?.length > 0, payment = found ? data[0] : null; let ww = false; if (payment?.created_at && payment.status === 'completed') ww = (Date.now() - new Date(payment.created_at).getTime()) / 60000 <= DOWNLOAD_WINDOW_MINUTES; return res.status(200).json({ already_paid: found && payment.status === 'completed' && ww, payment, within_window: ww }); }
            return res.status(400).json({ error: 'Missing params' });
        }

        // Download
        if (path === '/api/download' && method === 'POST') {
            const { device_fingerprint, document_id } = req.body;
            if (!vf(device_fingerprint) || !vu(document_id)) return res.status(400).json({ error: 'Invalid parameters' });
            const { data: payment, error: payErr } = await supabase.from('payments').select('*').eq('device_fingerprint', device_fingerprint).eq('document_id', document_id).eq('status', 'completed').order('created_at', { ascending: false }).limit(1).single();
            if (payErr || !payment) return res.status(403).json({ error: 'No completed payment found.' });
            const diffMin = (Date.now() - new Date(payment.created_at).getTime()) / 60000;
            if (diffMin > DOWNLOAD_WINDOW_MINUTES) return res.status(410).json({ error: 'Expired', expired: true });
            const { data: doc } = await supabase.from('documents').select('file_path').eq('id', document_id).single();
            if (!doc) return res.status(404).json({ error: 'Not found' });
            const { data: signedData } = await supabase.storage.from('documents').createSignedUrl(doc.file_path, 600);
            if (!signedData) return res.status(500).json({ error: 'Link failed' });
            await supabase.from('payments').update({ downloaded: true, downloaded_at: new Date().toISOString() }).eq('id', payment.id);
            return res.status(200).json({ url: signedData.signedUrl, filename: doc.file_path.split('/').pop() });
        }

        // User payments
        if (path === '/api/user-payments' && method === 'POST') { const { device_fingerprint } = req.body; if (!vf(device_fingerprint)) return res.status(400).json({ error: 'Invalid fingerprint' }); const { data, error } = await supabase.from('payments').select('id, document_id, client_token, amount, currency, status, transaction_ref, payment_method, downloaded, created_at, downloaded_at').eq('device_fingerprint', device_fingerprint).order('created_at', { ascending: false }).limit(50); if (error) return res.status(500).json({ error: 'Fetch failed' }); const enriched = []; for (const p of (data || [])) { const { data: d } = await supabase.from('documents').select('title, image_url').eq('id', p.document_id).single(); enriched.push({ ...p, document_title: d?.title || 'Unknown', document_image: d?.image_url || '' }); } return res.status(200).json(enriched); }

        // Verify with proof
        if (path === '/api/verify-with-proof' && method === 'POST') { const { client_token, device_fingerprint, buyer_name, phone_number, ocr_text, match_percentage, is_suspicious } = req.body; if (!client_token || !vt(client_token)) return res.status(400).json({ error: 'Invalid token' }); const { data: payment } = await supabase.from('payments').select('id, document_id, amount, currency, status, documents!inner(title)').eq('client_token', client_token).single(); if (!payment) return res.status(404).json({ error: 'Not found' }); if (payment.status === 'completed') return res.status(200).json({ verified: true, suspicious: false, document_id: payment.document_id }); await supabase.from('payment_verifications').insert({ payment_id: payment.id, client_token, device_fingerprint: device_fingerprint || '', buyer_name: buyer_name || '', phone_number: phone_number || '', ocr_text: ocr_text || '', match_percentage: match_percentage || 0, is_suspicious: is_suspicious || false, verified_at: new Date().toISOString() }); if (is_suspicious) { const np = payment.amount * 2; await supabase.from('payments').update({ amount: np, status: 'pending_verification' }).eq('client_token', client_token); return res.status(200).json({ verified: false, suspicious: true, original_price: payment.amount, new_price: np, currency: payment.currency, document_id: payment.document_id }); } await supabase.from('payments').update({ status: 'completed', payment_method: 'verified_manual' }).eq('client_token', client_token).eq('status', 'pending'); return res.status(200).json({ verified: true, suspicious: false, document_id: payment.document_id }); }

        // Admin endpoints
        if (path === '/api/admin/verify' && method === 'POST') return res.status(200).json({ authenticated: await isAdmin(req) });
        if (path === '/api/admin/upload' && method === 'POST') { if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' }); const ct = req.headers['content-type'] || ''; if (!ct.includes('multipart/form-data')) return res.status(400).json({ error: 'Expected file' }); const boundary = ct.split('boundary=')[1]; if (!boundary) return res.status(400).json({ error: 'No boundary' }); const chunks = []; for await (const c of req) chunks.push(c); const fb = Buffer.concat(chunks), eb = Buffer.from('--' + boundary + '--'); let fn = null, ft = 'application/octet-stream'; const hs = fb.toString('utf8', 0, Math.min(fb.length, 4096)); const fm = hs.match(/filename="(.+?)"/); if (fm) fn = fm[1]; const cm = hs.match(/Content-Type: (.+?)\r\n/); if (cm) ft = cm[1].trim(); let cs = -1; for (let i = 0; i < fb.length - 4; i++) { if (fb[i]===0x0d&&fb[i+1]===0x0a&&fb[i+2]===0x0d&&fb[i+3]===0x0a) { cs = i + 4; break; } } if (cs === -1 || !fn) return res.status(400).json({ error: 'Parse failed' }); let ce = fb.length; for (let i = fb.length - eb.length; i >= 0; i--) { if (fb.slice(i, i + eb.length).equals(eb)) { ce = i - 2; break; } } const bf = fb.slice(cs, ce); if (!bf || bf.length === 0) return res.status(400).json({ error: 'Empty file' }); const sn = Date.now() + '_' + fn.replace(/[^a-zA-Z0-9._-]/g, '_'); const { error } = await supabase.storage.from('documents').upload(sn, bf, { contentType: ft, cacheControl: '3600', upsert: false }); if (error) return res.status(500).json({ error: 'Upload failed' }); return res.status(200).json({ file_path: sn, filename: fn, size: bf.length }); }
        if (path === '/api/admin/documents' && method === 'GET') { if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' }); const { data, error } = await supabase.from('documents').select('*').order('created_at', { ascending: false }); if (error) return res.status(500).json({ error: 'Fetch failed' }); return res.status(200).json(data || []); }
        if (path === '/api/admin/documents' && method === 'POST') { if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' }); const { title, description, image_url, file_path, price, currency } = req.body; if (!title || !file_path || !price) return res.status(400).json({ error: 'Missing fields' }); const { data, error } = await supabase.from('documents').insert({ title: title.trim(), description: (description||'').trim(), image_url: (image_url||'').trim(), file_path: file_path.trim(), price: parseInt(price), currency: (currency||'RWF').toUpperCase(), active: true }).select().single(); if (error) return res.status(500).json({ error: 'Insert failed' }); return res.status(201).json(data); }
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+$/) && method === 'DELETE') { if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' }); const docId = path.split('/').pop(); const { data: doc } = await supabase.from('documents').select('file_path').eq('id', docId).single(); if (doc?.file_path) await supabase.storage.from('documents').remove([doc.file_path]); await supabase.from('documents').delete().eq('id', docId); return res.status(200).json({ success: true }); }
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+\/toggle$/) && method === 'PUT') { if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' }); const docId = path.split('/')[4]; const { data: doc } = await supabase.from('documents').select('active').eq('id', docId).single(); if (!doc) return res.status(404).json({ error: 'Not found' }); await supabase.from('documents').update({ active: !doc.active }).eq('id', docId); return res.status(200).json({ active: !doc.active }); }
        if (path === '/api/admin/verifications' && method === 'GET') { if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' }); const { data, error } = await supabase.from('payment_verifications').select('*').order('verified_at', { ascending: false }).limit(100); if (error) return res.status(500).json({ error: 'Fetch failed' }); return res.status(200).json(data || []); }

        return res.status(404).json({ error: 'Endpoint not found' });
    } catch (err) { console.error('[Handler]', err); return res.status(500).json({ error: 'Internal server error' }); }
}
