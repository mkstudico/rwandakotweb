import { createClient } from '@supabase/supabase-js';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const RWANDAPAY_BASE = 'https://pay.rwandapay.rw/api/v1';
const RWANDAPAY_PUBLIC_KEY = process.env.RWANDAPAY_PUBLIC_KEY;
const RWANDAPAY_SECRET_KEY = process.env.RWANDAPAY_SECRET_KEY;
const DOWNLOAD_WINDOW_MINUTES = 30;
const rateMap = new Map();

function rateLimit(ip) { const now = Date.now(), w = 60000; if (!rateMap.has(ip)) rateMap.set(ip, []); const reqs = rateMap.get(ip).filter(t => t > now - w); rateMap.set(ip, reqs); if (reqs.length >= 30) return false; reqs.push(now); return true; }
function vf(f) { return typeof f === 'string' && f.length >= 10 && f.length <= 200; }
function vu(id) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id); }
function vphone(p) { return /^0?7[89]\d{7}$/.test((p||'').replace(/\s/g,'')); }
function vt(t) { return /^[a-zA-Z0-9_]{20,80}$/.test(t); }
function setCORS(res) { res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization'); res.setHeader('Content-Type', 'application/json'); }

function pubAuth(req) {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) return null;
    const token = auth.slice(7);
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        if (!payload || !payload.sub) return null;
        return { uid: payload.sub, email: payload.email || '' };
    } catch (e) { return null; }
}

async function getPublisherId(req) {
    const fbUser = pubAuth(req);
    if (!fbUser) return null;
    const { data: pub } = await supabase.from('publishers').select('id, username, email').eq('firebase_uid', fbUser.uid).single();
    if (pub) return pub;
    if (fbUser.email) {
        const { data: pub2 } = await supabase.from('publishers').select('id, username, email').eq('email', fbUser.email).single();
        if (pub2) {
            await supabase.from('publishers').update({ firebase_uid: fbUser.uid }).eq('id', pub2.id);
            return pub2;
        }
    }
    return null;
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
    if (method === 'POST' && path !== '/api/pub/upload') { if (!rateLimit(ip)) return res.status(429).json({ error: 'Too many requests' }); }

    try {
        // ═══════════════════════════════════════
        // PUB: Firebase Register (create or link publisher)
        // ═══════════════════════════════════════
        if (path === '/api/pub/firebase-register' && method === 'POST') {
            const { uid, email, username } = req.body;
            if (!uid || !email) return res.status(400).json({ error: 'Missing fields' });
            const slug = (username || email.split('@')[0]).toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-');
            const { data: exist } = await supabase.from('publishers').select('id, bonus_claimed, balance').eq('email', email).limit(1);
            if (exist?.length) {
                await supabase.from('publishers').update({ firebase_uid: uid, username: username || exist[0].username }).eq('id', exist[0].id);
                return res.status(200).json({ publisher: { id: exist[0].id, username: username || exist[0].username, slug, email } });
            }
            const name = username || email.split('@')[0];
            const { data, error } = await supabase.from('publishers').insert({
                username: name, email, password_hash: 'firebase', name, slug,
                firebase_uid: uid, balance: 1000, bonus_claimed: true
            }).select().single();
            if (error) return res.status(500).json({ error: 'Registration failed' });
            await supabase.from('pub_payments').insert({
                publisher_id: data.id, device_fingerprint: 'bonus_' + data.id,
                client_token: 'bonus_' + Date.now(), amount: 1000,
                publisher_earnings: 1000, platform_fee: 0, currency: 'RWF',
                status: 'completed', customer_name: 'Startup Bonus', customer_phone: 'N/A', payment_method: 'bonus'
            });
            return res.status(201).json({ publisher: { id: data.id, username: data.username, slug: data.slug, email: data.email } });
        }

        // ═══════════════════════════════════════
        // PUB: Get single document (public)
        // ═══════════════════════════════════════
        if (path.match(/^\/api\/pub\/document\/[a-f0-9-]+$/) && method === 'GET') {
            const docId = path.split('/').pop();
            if (!vu(docId)) return res.status(400).json({ error: 'Invalid ID' });
            const { data, error } = await supabase.from('pub_documents').select('id, title, description, image_url, price, currency, clicks, created_at').eq('id', docId).eq('active', true).single();
            if (error || !data) return res.status(404).json({ error: 'Not found' });
            return res.status(200).json(data);
        }

        // ═══════════════════════════════════════
        // PUB: My documents
        // ═══════════════════════════════════════
        if (path === '/api/pub/documents' && method === 'GET') {
            const publisher = await getPublisherId(req);
            if (!publisher) return res.status(401).json({ error: 'Unauthorized' });
            const { data, error } = await supabase.from('pub_documents').select('*').eq('publisher_id', publisher.id).order('created_at', { ascending: false });
            if (error) return res.status(500).json({ error: 'Fetch failed' });
            return res.status(200).json(data || []);
        }

        // ═══════════════════════════════════════
        // PUB: Add document
        // ═══════════════════════════════════════
        if (path === '/api/pub/documents' && method === 'POST') {
            const publisher = await getPublisherId(req);
            if (!publisher) return res.status(401).json({ error: 'Unauthorized' });
            const { title, description, image_url, file_path, price } = req.body;
            if (!title || !file_path || !price || parseInt(price) < 1000 || parseInt(price) > 500000) return res.status(400).json({ error: 'Title, file, price (1000-500000) required' });
            const { data, error } = await supabase.from('pub_documents').insert({
                publisher_id: publisher.id, title: title.trim(), description: (description||'').trim(),
                image_url: (image_url||'').trim(), file_path, price: parseInt(price), active: true
            }).select().single();
            if (error) return res.status(500).json({ error: 'Insert failed' });
            return res.status(201).json(data);
        }

        // ═══════════════════════════════════════
        // PUB: Delete document
        // ═══════════════════════════════════════
        if (path.match(/^\/api\/pub\/documents\/[a-f0-9-]+$/) && method === 'DELETE') {
            const publisher = await getPublisherId(req);
            if (!publisher) return res.status(401).json({ error: 'Unauthorized' });
            const docId = path.split('/').pop();
            const { data: doc } = await supabase.from('pub_documents').select('file_path').eq('id', docId).eq('publisher_id', publisher.id).single();
            if (!doc) return res.status(404).json({ error: 'Not found' });
            try { await supabase.storage.from('pub-documents').remove([doc.file_path]); } catch(e) {}
            await supabase.from('pub_documents').delete().eq('id', docId);
            return res.status(200).json({ success: true });
        }

        // ═══════════════════════════════════════
        // PUB: Toggle document
        // ═══════════════════════════════════════
        if (path.match(/^\/api\/pub\/documents\/[a-f0-9-]+\/toggle$/) && method === 'PUT') {
            const publisher = await getPublisherId(req);
            if (!publisher) return res.status(401).json({ error: 'Unauthorized' });
            const docId = path.split('/')[4];
            const { data: doc } = await supabase.from('pub_documents').select('active').eq('id', docId).eq('publisher_id', publisher.id).single();
            if (!doc) return res.status(404).json({ error: 'Not found' });
            await supabase.from('pub_documents').update({ active: !doc.active }).eq('id', docId);
            return res.status(200).json({ active: !doc.active });
        }

        // ═══════════════════════════════════════
        // PUB: Upload file
        // ═══════════════════════════════════════
        if (path === '/api/pub/upload' && method === 'POST') {
            const publisher = await getPublisherId(req);
            if (!publisher) return res.status(401).json({ error: 'Unauthorized' });
            const ct = req.headers['content-type'] || ''; if (!ct.includes('multipart/form-data')) return res.status(400).json({ error: 'Expected file' });
            const boundary = ct.split('boundary=')[1]; if (!boundary) return res.status(400).json({ error: 'No boundary' });
            const chunks = []; for await (const c of req) chunks.push(c);
            const fb = Buffer.concat(chunks), eb = Buffer.from('--' + boundary + '--');
            let fn = null, ft = 'application/octet-stream';
            const hs = fb.toString('utf8', 0, Math.min(fb.length, 4096));
            const fm = hs.match(/filename="(.+?)"/); if (fm) fn = fm[1];
            const cm = hs.match(/Content-Type: (.+?)\r\n/); if (cm) ft = cm[1].trim();
            let cs = -1; for (let i = 0; i < fb.length - 4; i++) { if (fb[i]===0x0d&&fb[i+1]===0x0a&&fb[i+2]===0x0d&&fb[i+3]===0x0a) { cs = i + 4; break; } }
            if (cs === -1 || !fn) return res.status(400).json({ error: 'Parse failed' });
            let ce = fb.length; for (let i = fb.length - eb.length; i >= 0; i--) { if (fb.slice(i, i + eb.length).equals(eb)) { ce = i - 2; break; } }
            const bf = fb.slice(cs, ce); if (!bf || bf.length === 0) return res.status(400).json({ error: 'Empty file' });
            const sn = `pub_${publisher.id}_${Date.now()}_${fn.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
            const { error } = await supabase.storage.from('pub-documents').upload(sn, bf, { contentType: ft, cacheControl: '3600', upsert: false });
            if (error) return res.status(500).json({ error: 'Upload failed: ' + error.message });
            return res.status(200).json({ file_path: sn, filename: fn, size: bf.length });
        }

        // ═══════════════════════════════════════
        // PUB: Earnings
        // ═══════════════════════════════════════
        if (path === '/api/pub/earnings' && method === 'GET') {
            const publisher = await getPublisherId(req);
            if (!publisher) return res.status(401).json({ error: 'Unauthorized' });
            const { data: pub } = await supabase.from('publishers').select('balance, bonus_claimed').eq('id', publisher.id).single();
            const { data: payments } = await supabase.from('pub_payments').select('amount, publisher_earnings, platform_fee, customer_name, customer_phone, created_at, payment_method').eq('publisher_id', publisher.id).eq('status', 'completed').order('created_at', { ascending: false });
            const real = (payments||[]).filter(p => p.payment_method !== 'bonus');
            const total = real.reduce((s,p) => s + p.amount, 0);
            const fees = real.reduce((s,p) => s + p.platform_fee, 0);
            const { count: docCount } = await supabase.from('pub_documents').select('id', { count: 'exact' }).eq('publisher_id', publisher.id);
            return res.status(200).json({ total_sales: total, your_earnings: pub?.balance || 0, platform_fees: fees, total_documents: docCount||0, total_transactions: real.length, recent: (payments||[]).slice(0, 10), bonus_claimed: pub?.bonus_claimed || false });
        }

        // ═══════════════════════════════════════
        // PUB: Public page
        // ═══════════════════════════════════════
        if (path.match(/^\/api\/pub\/page\/[a-z0-9-]+$/) && method === 'GET') {
            const slug = path.split('/').pop();
            const { data: pub } = await supabase.from('publishers').select('id, username, name, slug').eq('slug', slug).single();
            if (!pub) return res.status(404).json({ error: 'Publisher not found' });
            const { data: docs } = await supabase.from('pub_documents').select('id, title, description, image_url, price, currency, clicks, created_at').eq('publisher_id', pub.id).eq('active', true).order('created_at', { ascending: false });
            return res.status(200).json({ publisher: pub, documents: docs || [] });
        }

        // ═══════════════════════════════════════
        // PUB: Init payment
        // ═══════════════════════════════════════
        if (path === '/api/pub/init-payment' && method === 'POST') {
            const { document_id, device_fingerprint, phone, client_token, customer_name } = req.body;
            if (!vu(document_id) || !vf(device_fingerprint) || !vphone(phone) || !vt(client_token)) return res.status(400).json({ error: 'Invalid params' });
            const { data: doc } = await supabase.from('pub_documents').select('*, publishers!inner(id)').eq('id', document_id).eq('active', true).single();
            if (!doc) return res.status(404).json({ error: 'Not found' });
            const finalAmount = Math.max(100, parseInt(doc.price));
            const pubEarnings = Math.floor(finalAmount * 0.88);
            const platFee = finalAmount - pubEarnings;
            await supabase.from('pub_payments').insert({
                document_id, publisher_id: doc.publisher_id, device_fingerprint, client_token,
                amount: finalAmount, publisher_earnings: pubEarnings, platform_fee: platFee,
                currency: doc.currency, status: 'pending', customer_name: (customer_name||'').trim(), customer_phone: phone
            });
            let np = phone.replace(/\s/g, '').replace('+250', ''); if (np.startsWith('0')) np = np.substring(1);
            const cname = (customer_name || '').trim() || 'Customer';
            const rpBody = { amount: finalAmount, tx_ref: client_token, currency: doc.currency || 'RWF', customer: { name: cname, email: cname.toLowerCase().replace(/[^a-z0-9]/g,'')+'@kotweb.rw', phone: np }, redirect_url: `${req.headers['x-forwarded-proto']||'https'}://${req.headers.host}/pub-view.html?doc=${document_id}&rp_ref=${client_token}`, webhook_url: `${req.headers['x-forwarded-proto']||'https'}://${req.headers.host}/api/rwandapay-callback`, description: doc.title || 'Purchase' };
            try {
                const rpRes = await fetch(`${RWANDAPAY_BASE}/checkout/initialize`, { method: 'POST', headers: { 'X-Public-Key': RWANDAPAY_PUBLIC_KEY, 'X-Secret-Key': RWANDAPAY_SECRET_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify(rpBody) });
                const rpData = await rpRes.json();
                if (!rpData.success || !rpData.data?.payment_url) return res.status(500).json({ error: rpData.message || 'Payment failed' });
                await supabase.from('pub_payments').update({ transaction_ref: rpData.data.reference || client_token }).eq('client_token', client_token);
                return res.status(200).json({ success: true, payment_url: rpData.data.payment_url, reference: rpData.data.reference || client_token });
            } catch (err) { return res.status(500).json({ error: 'Service unavailable' }); }
        }

        // ═══════════════════════════════════════
        // PUB: Verify payment
        // ═══════════════════════════════════════
        if (path === '/api/pub/verify-payment' && method === 'POST') {
            const { reference, client_token, document_id, device_fingerprint } = req.body; const ref = reference || client_token;
            try {
                const rpRes = await fetch(`${RWANDAPAY_BASE}/checkout/${ref}/verify`, { headers: { 'Accept': 'application/json' } }); const rpData = await rpRes.json();
                if (rpData.completed && rpData.success && rpData.status === 'successful') {
                    await supabase.from('pub_payments').update({ status: 'completed', payment_method: 'rwandapay' }).eq('client_token', ref).eq('status', 'pending');
                    await supabase.from('pub_payments').update({ status: 'completed' }).eq('transaction_ref', ref).eq('status', 'pending');
                    if (device_fingerprint && document_id) await supabase.from('pub_payments').update({ status: 'completed' }).eq('device_fingerprint', device_fingerprint).eq('document_id', document_id).eq('status', 'pending');
                    const { data: payment } = await supabase.from('pub_payments').select('publisher_id, publisher_earnings').eq('client_token', ref).single();
                    if (payment) {
                        const { data: pub } = await supabase.from('publishers').select('balance').eq('id', payment.publisher_id).single();
                        if (pub) await supabase.from('publishers').update({ balance: (pub.balance || 0) + payment.publisher_earnings }).eq('id', payment.publisher_id);
                    }
                    return res.status(200).json({ verified: true, status: 'completed', document_id });
                }
                if (rpData.completed && !rpData.success) { await supabase.from('pub_payments').update({ status: 'failed' }).eq('client_token', ref).eq('status', 'pending'); return res.status(200).json({ verified: false, status: 'failed' }); }
                return res.status(200).json({ verified: false, status: rpData.status || 'pending' });
            } catch (err) { return res.status(500).json({ error: 'Verify failed' }); }
        }

        // ═══════════════════════════════════════
        // PUB: Download
        // ═══════════════════════════════════════
        if (path === '/api/pub/download' && method === 'POST') {
            const { device_fingerprint, document_id } = req.body;
            if (!vf(device_fingerprint) || !vu(document_id)) return res.status(400).json({ error: 'Invalid parameters' });
            const { data: payment } = await supabase.from('pub_payments').select('*').eq('device_fingerprint', device_fingerprint).eq('document_id', document_id).eq('status', 'completed').order('created_at', { ascending: false }).limit(1).single();
            if (!payment) return res.status(403).json({ error: 'No completed payment found.' });
            const diffMin = (Date.now() - new Date(payment.created_at).getTime()) / 60000;
            if (diffMin > DOWNLOAD_WINDOW_MINUTES) return res.status(410).json({ error: 'Expired', expired: true });
            const { data: doc } = await supabase.from('pub_documents').select('file_path').eq('id', document_id).single();
            if (!doc) return res.status(404).json({ error: 'Not found' });
            const { data: signedData } = await supabase.storage.from('pub-documents').createSignedUrl(doc.file_path, 600);
            if (!signedData) return res.status(500).json({ error: 'Link failed' });
            await supabase.from('pub_payments').update({ downloaded: true }).eq('id', payment.id);
            return res.status(200).json({ url: signedData.signedUrl, filename: doc.file_path.split('/').pop() });
        }

        // ═══════════════════════════════════════
        // ADMIN: Publishers list
        // ═══════════════════════════════════════
        if (path === '/api/admin/publishers' && method === 'GET') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });
            const { data, error } = await supabase.from('publishers').select('*').order('created_at', { ascending: false });
            if (error) return res.status(500).json({ error: 'Fetch failed' });
            return res.status(200).json(data || []);
        }

        // ═══════════════════════════════════════
        // ADMIN: Publisher transactions
        // ═══════════════════════════════════════
        if (path === '/api/admin/pub-transactions' && method === 'GET') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });
            const { data, error } = await supabase.from('pub_payments').select('*, publishers!inner(username, name), pub_documents!inner(title)').order('created_at', { ascending: false }).limit(200);
            if (error) return res.status(500).json({ error: 'Fetch failed' });
            return res.status(200).json(data || []);
        }

        // ═══════════════════════════════════════
        // NEW: PUBLIC – Discover all active publisher documents
        // ═══════════════════════════════════════
        if (path === '/api/pub/discover' && method === 'GET') {
            const { data, error } = await supabase
                .from('pub_documents')
                .select('id, title, description, image_url, price, currency, clicks, created_at, publisher_id, publishers!inner(username)')
                .eq('active', true)
                .order('created_at', { ascending: false })
                .limit(50);

            if (error) return res.status(500).json({ error: 'Fetch failed' });
            const docs = (data || []).map(d => ({
                ...d,
                username: d.publishers?.username || 'unknown',
                publishers: undefined,
                isPublisher: true
            }));
            return res.status(200).json(docs);
        }

        // ═══════════════════════════════════════
        // NEW: PUBLIC – Top Publishers by total views
        // ═══════════════════════════════════════
        if (path === '/api/pub/top-publishers' && method === 'GET') {
            const { data, error } = await supabase
                .from('pub_documents')
                .select('clicks, publisher_id, publishers!inner(username, name)')
                .eq('active', true);

            if (error) return res.status(500).json({ error: 'Fetch failed' });

            const map = {};
            (data || []).forEach(d => {
                const pid = d.publisher_id;
                if (!map[pid]) {
                    map[pid] = { id: pid, username: d.publishers?.username || 'unknown', name: d.publishers?.name || '', totalViews: 0 };
                }
                map[pid].totalViews += (d.clicks || 0);
            });

            const sorted = Object.values(map).sort((a, b) => b.totalViews - a.totalViews).slice(0, 5);
            return res.status(200).json(sorted);
        }

        return res.status(404).json({ error: 'Endpoint not found' });
    } catch (err) { console.error('[Publisher]', err); return res.status(500).json({ error: 'Internal error' }); }
}
