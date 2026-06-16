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
    if (!auth || !auth.startsWith('Bearer ')) return false;
    const key = auth.slice(7);
    const { data } = await supabase.from('admin_keys').select('key_hash');
    if (!data || !data.length) return false;
    for (const r of data) {
        const { data: m, error } = await supabase.rpc('verify_admin_key', {
            input_key: key,
            stored_hash: r.key_hash
        });
        if (!error && m) return true;
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
        if (!rateLimit(ip)) return res.status(429).json({ error: 'Too many requests. Please wait.' });
    }

    try {

        // ═══════════════════════════════════════════
        // PUBLIC: GET all active documents
        // ═══════════════════════════════════════════
        if (path === '/api/documents' && method === 'GET') {
            const { data, error } = await supabase
                .from('documents')
                .select('id,title,description,image_url,price,currency,clicks,created_at')
                .eq('active', true)
                .order('created_at', { ascending: false });

            if (error) return res.status(500).json({ error: 'Failed to fetch documents' });
            return res.status(200).json(data || []);
        }

        // ═══════════════════════════════════════════
        // PUBLIC: GET single document
        // ═══════════════════════════════════════════
        if (path.match(/^\/api\/documents\/[a-f0-9-]+$/) && method === 'GET') {
            const docId = path.split('/').pop();
            if (!vu(docId)) return res.status(400).json({ error: 'Invalid document ID' });

            const { data, error } = await supabase
                .from('documents')
                .select('id,title,description,image_url,price,currency,clicks,created_at')
                .eq('id', docId).eq('active', true).single();

            if (error || !data) return res.status(404).json({ error: 'Document not found' });
            return res.status(200).json(data);
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Track document click
        // ═══════════════════════════════════════════
        if (path.match(/^\/api\/documents\/[a-f0-9-]+\/click$/) && method === 'POST') {
            const docId = path.split('/')[3];
            if (!vu(docId)) return res.status(400).json({ error: 'Invalid document ID' });
            await supabase.rpc('increment_click', { doc_id: docId });
            return res.status(200).json({ ok: true });
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Initiate payment
        // ═══════════════════════════════════════════
        if (path === '/api/init-payment' && method === 'POST') {
            const { document_id, device_fingerprint, client_token } = req.body;

            if (!vu(document_id) || !vf(device_fingerprint) || !vt(client_token))
                return res.status(400).json({ error: 'Invalid parameters' });

            const { data: exist } = await supabase
                .from('payments')
                .select('id, created_at')
                .eq('device_fingerprint', device_fingerprint)
                .eq('document_id', document_id)
                .eq('status', 'completed')
                .limit(1);

            if (exist && exist.length > 0) {
                const paidAt = new Date(exist[0].created_at);
                const diffMin = (Date.now() - paidAt.getTime()) / 60000;
                if (diffMin <= DOWNLOAD_WINDOW_MINUTES)
                    return res.status(200).json({ already_paid: true });
            }

            const { data: dupToken } = await supabase
                .from('payments').select('id').eq('client_token', client_token).limit(1);

            if (dupToken && dupToken.length > 0)
                return res.status(400).json({ error: 'Duplicate token. Please try again.' });

            const { data: doc, error: docErr } = await supabase
                .from('documents').select('price,currency,title')
                .eq('id', document_id).eq('active', true).single();

            if (docErr || !doc) return res.status(404).json({ error: 'Document not found' });

            const { error: insertErr } = await supabase
                .from('payments').insert({
                    document_id, device_fingerprint, client_token,
                    amount: doc.price, currency: doc.currency, status: 'pending'
                });

            if (insertErr) return res.status(500).json({ error: 'Failed to initiate payment' });

            return res.status(200).json({
                success: true, amount: doc.price, currency: doc.currency, title: doc.title
            });
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Check payment status
        // ═══════════════════════════════════════════
        if (path === '/api/check-payment' && method === 'POST') {
            const { client_token, device_fingerprint, document_id } = req.body;

            if (client_token) {
                if (!vt(client_token)) return res.status(400).json({ error: 'Invalid token' });
                const { data, error } = await supabase
                    .from('payments').select('status, document_id, amount, currency, created_at')
                    .eq('client_token', client_token).single();

                if (error || !data) return res.status(404).json({ error: 'Payment not found' });

                return res.status(200).json({
                    paid: data.status === 'completed', status: data.status,
                    document_id: data.document_id, amount: data.amount,
                    currency: data.currency, created_at: data.created_at
                });
            }

            if (device_fingerprint && document_id) {
                if (!vf(device_fingerprint) || !vu(document_id))
                    return res.status(400).json({ error: 'Invalid parameters' });

                const { data, error } = await supabase
                    .from('payments')
                    .select('id, status, amount, created_at')
                    .eq('device_fingerprint', device_fingerprint)
                    .eq('document_id', document_id)
                    .order('created_at', { ascending: false }).limit(1);

                if (error) return res.status(500).json({ error: 'Check failed' });

                const found = data && data.length > 0;
                const payment = found ? data[0] : null;
                let withinWindow = false;

                if (payment && payment.created_at && payment.status === 'completed') {
                    const diffMin = (Date.now() - new Date(payment.created_at).getTime()) / 60000;
                    withinWindow = diffMin <= DOWNLOAD_WINDOW_MINUTES;
                }

                return res.status(200).json({
                    already_paid: found && payment.status === 'completed' && withinWindow,
                    payment: payment, within_window: withinWindow
                });
            }

            return res.status(400).json({ error: 'Missing parameters' });
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Download document (direct file)
        // ═══════════════════════════════════════════
        if (path === '/api/download' && method === 'POST') {
            const { client_token, device_fingerprint, document_id } = req.body;

            if (!vt(client_token) || !vf(device_fingerprint) || !vu(document_id))
                return res.status(400).json({ error: 'Invalid parameters' });

            const { data: payment } = await supabase
                .from('payments').select('*')
                .eq('client_token', client_token)
                .eq('device_fingerprint', device_fingerprint)
                .eq('document_id', document_id)
                .eq('status', 'completed').single();

            if (!payment) {
                const { data: anyPayment } = await supabase
                    .from('payments').select('*')
                    .eq('device_fingerprint', device_fingerprint)
                    .eq('document_id', document_id)
                    .eq('status', 'completed')
                    .order('created_at', { ascending: false }).limit(1).single();

                if (!anyPayment)
                    return res.status(403).json({ error: 'Payment not confirmed.' });
            }

            const validPayment = payment || anyPayment;
            const paidAt = new Date(validPayment.created_at);
            const diffMinutes = (Date.now() - paidAt.getTime()) / 60000;

            if (diffMinutes > DOWNLOAD_WINDOW_MINUTES)
                return res.status(410).json({ error: 'Download window expired.', expired: true });

            const { data: doc } = await supabase
                .from('documents').select('file_path').eq('id', document_id).single();

            if (!doc) return res.status(404).json({ error: 'Document not found' });

            const { data: signedData } = await supabase
                .storage.from('documents').createSignedUrl(doc.file_path, 600);

            if (!signedData) return res.status(500).json({ error: 'Failed to generate link' });

            await supabase.from('payments').update({
                downloaded: true, downloaded_at: new Date().toISOString()
            }).eq('id', validPayment.id);

            return res.status(200).json({
                url: signedData.signedUrl,
                filename: doc.file_path.split('/').pop(),
                expires_in_minutes: Math.max(0, Math.floor(DOWNLOAD_WINDOW_MINUTES - diffMinutes))
            });
        }

        // ═══════════════════════════════════════════
        // PUBLIC: User payments history
        // ═══════════════════════════════════════════
        if (path === '/api/user-payments' && method === 'POST') {
            const { device_fingerprint } = req.body;
            if (!vf(device_fingerprint)) return res.status(400).json({ error: 'Invalid fingerprint' });

            const { data, error } = await supabase
                .from('payments')
                .select('id, document_id, client_token, amount, currency, status, transaction_ref, payment_method, downloaded, created_at, downloaded_at')
                .eq('device_fingerprint', device_fingerprint)
                .order('created_at', { ascending: false }).limit(50);

            if (error) return res.status(500).json({ error: 'Failed to fetch' });

            const enriched = [];
            for (const p of (data || [])) {
                const { data: doc } = await supabase
                    .from('documents').select('title, image_url').eq('id', p.document_id).single();
                enriched.push({
                    ...p,
                    document_title: doc?.title || 'Unknown Document',
                    document_image: doc?.image_url || ''
                });
            }

            return res.status(200).json(enriched);
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Confirm payment on return
        // ═══════════════════════════════════════════
        if (path === '/api/confirm-payment' && method === 'POST') {
            const { client_token } = req.body;
            if (!client_token || !vt(client_token)) return res.status(400).json({ error: 'Invalid token' });

            const { data: payment } = await supabase
                .from('payments').select('*').eq('client_token', client_token).single();

            if (!payment) return res.status(404).json({ error: 'Not found' });
            if (payment.status === 'completed')
                return res.status(200).json({ confirmed: true, document_id: payment.document_id });

            return res.status(200).json({
                confirmed: false, status: payment.status,
                document_id: payment.document_id, amount: payment.amount,
                currency: payment.currency
            });
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Verify with proof
        // ═══════════════════════════════════════════
        if (path === '/api/verify-with-proof' && method === 'POST') {
            const { client_token, device_fingerprint, buyer_name, phone_number, ocr_text, match_percentage, is_suspicious } = req.body;

            if (!client_token || !vt(client_token)) return res.status(400).json({ error: 'Invalid token' });

            const { data: payment } = await supabase
                .from('payments').select('id, document_id, amount, currency, status, documents!inner(title, price, currency)')
                .eq('client_token', client_token).single();

            if (!payment) return res.status(404).json({ error: 'Not found' });
            if (payment.status === 'completed')
                return res.status(200).json({ verified: true, suspicious: false, document_id: payment.document_id });

            await supabase.from('payment_verifications').insert({
                payment_id: payment.id, client_token, device_fingerprint: device_fingerprint || '',
                buyer_name: buyer_name || '', phone_number: phone_number || '',
                ocr_text: ocr_text || '', match_percentage: match_percentage || 0,
                is_suspicious: is_suspicious || false, verified_at: new Date().toISOString()
            });

            if (is_suspicious) {
                const newPrice = payment.amount * 2;
                await supabase.from('payments').update({
                    amount: newPrice, status: 'pending_verification',
                    transaction_ref: 'suspicious_' + client_token.substring(0, 8)
                }).eq('client_token', client_token);

                return res.status(200).json({
                    verified: false, suspicious: true,
                    original_price: payment.amount, new_price: newPrice,
                    currency: payment.currency, document_id: payment.document_id,
                    document_title: payment.documents?.title || 'Document'
                });
            }

            await supabase.from('payments').update({
                status: 'completed', payment_method: 'verified_manual',
                transaction_ref: 'verified_' + client_token.substring(0, 8)
            }).eq('client_token', client_token).eq('status', 'pending');

            return res.status(200).json({
                verified: true, suspicious: false,
                document_id: payment.document_id,
                document_title: payment.documents?.title || 'Document'
            });
        }

        // ═══════════════════════════════════════════
        // AFRIPAY CALLBACK
        // ═══════════════════════════════════════════
        if (path === '/api/callback' && method === 'POST') {
            const { status, transaction_ref, client_token, amount, currency, payment_method } = req.body;

            if (!client_token) return res.status(200).json({ received: true, note: 'Missing token' });
            if (!vt(client_token)) return res.status(200).json({ received: true, note: 'Invalid format' });

            const { data: payment } = await supabase
                .from('payments').select('id, amount, status').eq('client_token', client_token).single();

            if (!payment) return res.status(200).json({ received: true, note: 'Not found' });
            if (payment.status === 'completed') return res.status(200).json({ received: true, note: 'Already done' });

            if (status === 'success') {
                await supabase.from('payments').update({
                    status: 'completed', transaction_ref: transaction_ref || null,
                    payment_method: payment_method || null,
                    amount: parseInt(amount) || payment.amount, currency: currency || payment.currency
                }).eq('client_token', client_token).eq('status', 'pending');
            } else {
                await supabase.from('payments').update({
                    status: 'failed', transaction_ref: transaction_ref || null
                }).eq('client_token', client_token).eq('status', 'pending');
            }

            return res.status(200).json({ received: true });
        }

        // ═══════════════════════════════════════════
        // ADMIN: Verify
        // ═══════════════════════════════════════════
        if (path === '/api/admin/verify' && method === 'POST') {
            return res.status(200).json({ authenticated: await isAdmin(req) });
        }

        // ═══════════════════════════════════════════
        // ADMIN: Upload file
        // ═══════════════════════════════════════════
        if (path === '/api/admin/upload' && method === 'POST') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });

            const ct = req.headers['content-type'] || '';
            if (!ct.includes('multipart/form-data')) return res.status(400).json({ error: 'Expected file' });

            const boundary = ct.split('boundary=')[1];
            if (!boundary) return res.status(400).json({ error: 'No boundary' });

            const chunks = [];
            for await (const c of req) chunks.push(c);
            const fullBuffer = Buffer.concat(chunks);

            const boundaryBuffer = Buffer.from('--' + boundary);
            const endBoundary = Buffer.from('--' + boundary + '--');

            let fileName = null;
            let fileType = 'application/octet-stream';
            let fileBuffer = null;

            const headerStr = fullBuffer.toString('utf8', 0, Math.min(fullBuffer.length, 4096));
            const fnMatch = headerStr.match(/filename="(.+?)"/);
            if (fnMatch) fileName = fnMatch[1];
            const ctMatch = headerStr.match(/Content-Type: (.+?)\r\n/);
            if (ctMatch) fileType = ctMatch[1].trim();

            let contentStart = -1;
            for (let i = 0; i < fullBuffer.length - 4; i++) {
                if (fullBuffer[i] === 0x0d && fullBuffer[i+1] === 0x0a &&
                    fullBuffer[i+2] === 0x0d && fullBuffer[i+3] === 0x0a) {
                    contentStart = i + 4; break;
                }
            }

            if (contentStart === -1 || !fileName)
                return res.status(400).json({ error: 'Could not parse file' });

            let contentEnd = fullBuffer.length;
            for (let i = fullBuffer.length - endBoundary.length; i >= 0; i--) {
                if (fullBuffer.slice(i, i + endBoundary.length).equals(endBoundary)) {
                    contentEnd = i - 2; break;
                }
            }

            fileBuffer = fullBuffer.slice(contentStart, contentEnd);

            if (!fileBuffer || fileBuffer.length === 0)
                return res.status(400).json({ error: 'File is empty' });

            const safeName = Date.now() + '_' + fileName.replace(/[^a-zA-Z0-9._-]/g, '_');

            const { error } = await supabase.storage.from('documents').upload(safeName, fileBuffer, {
                contentType: fileType, cacheControl: '3600', upsert: false
            });

            if (error) return res.status(500).json({ error: 'Upload failed: ' + error.message });

            return res.status(200).json({
                file_path: safeName, filename: fileName, size: fileBuffer.length
            });
        }

        // ═══════════════════════════════════════════
        // ADMIN: List documents
        // ═══════════════════════════════════════════
        if (path === '/api/admin/documents' && method === 'GET') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });
            const { data, error } = await supabase
                .from('documents').select('*').order('created_at', { ascending: false });
            if (error) return res.status(500).json({ error: 'Fetch failed' });
            return res.status(200).json(data || []);
        }

        // ═══════════════════════════════════════════
        // ADMIN: Add document
        // ═══════════════════════════════════════════
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

        // ═══════════════════════════════════════════
        // ADMIN: Delete document
        // ═══════════════════════════════════════════
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+$/) && method === 'DELETE') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });
            const docId = path.split('/').pop();
            const { data: doc } = await supabase.from('documents').select('file_path').eq('id', docId).single();
            if (doc?.file_path) await supabase.storage.from('documents').remove([doc.file_path]);
            const { error } = await supabase.from('documents').delete().eq('id', docId);
            if (error) return res.status(500).json({ error: 'Delete failed' });
            return res.status(200).json({ success: true });
        }

        // ═══════════════════════════════════════════
        // ADMIN: Toggle document
        // ═══════════════════════════════════════════
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+\/toggle$/) && method === 'PUT') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });
            const docId = path.split('/')[4];
            const { data: doc } = await supabase.from('documents').select('active').eq('id', docId).single();
            if (!doc) return res.status(404).json({ error: 'Not found' });
            await supabase.from('documents').update({ active: !doc.active }).eq('id', docId);
            return res.status(200).json({ active: !doc.active });
        }

        // ═══════════════════════════════════════════
        // ADMIN: List verifications
        // ═══════════════════════════════════════════
        if (path === '/api/admin/verifications' && method === 'GET') {
            if (!(await isAdmin(req))) return res.status(401).json({ error: 'Unauthorized' });
            const { data, error } = await supabase
                .from('payment_verifications')
                .select('*').order('verified_at', { ascending: false }).limit(100);
            if (error) return res.status(500).json({ error: 'Fetch failed' });
            return res.status(200).json(data || []);
        }

        return res.status(404).json({ error: 'Endpoint not found' });

    } catch (err) {
        console.error('[Handler]', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}
