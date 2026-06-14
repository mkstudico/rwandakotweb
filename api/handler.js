import { createClient } from '@supabase/supabase-js';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const AFRIPAY_APP_ID = process.env.AFRIPAY_APP_ID;

const rateMap = new Map();

function rateLimit(ip) {
    const now = Date.now();
    const w = 60000;
    if (!rateMap.has(ip)) rateMap.set(ip, []);
    const reqs = rateMap.get(ip).filter(t => t > now - w);
    rateMap.set(ip, reqs);
    if (reqs.length >= 20) return false;
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

    // Rate limit POST requests
    if (method === 'POST' && !path.startsWith('/api/admin/upload')) {
        if (!rateLimit(ip)) {
            return res.status(429).json({ error: 'Too many requests. Please wait.' });
        }
    }

    try {
        // ═══════════════════════════════════════════
        // PUBLIC ENDPOINTS
        // ═══════════════════════════════════════════

        // GET all active documents
        if (path === '/api/documents' && method === 'GET') {
            const { data, error } = await supabase
                .from('documents')
                .select('id,title,description,image_url,price,currency,clicks,created_at')
                .eq('active', true)
                .order('created_at', { ascending: false });

            if (error) {
                console.error('GET documents error:', error);
                return res.status(500).json({ error: 'Failed to fetch documents' });
            }

            return res.status(200).json(data || []);
        }

        // GET single document
        if (path.match(/^\/api\/documents\/[a-f0-9-]+$/) && method === 'GET') {
            const docId = path.split('/').pop();
            if (!vu(docId)) return res.status(400).json({ error: 'Invalid document ID' });

            const { data, error } = await supabase
                .from('documents')
                .select('id,title,description,image_url,price,currency,clicks,created_at')
                .eq('id', docId)
                .eq('active', true)
                .single();

            if (error || !data) return res.status(404).json({ error: 'Document not found' });
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
            if (!vu(document_id) || !vf(device_fingerprint) || !vt(client_token)) {
                return res.status(400).json({ error: 'Invalid parameters' });
            }

            const { data: exist } = await supabase
                .from('payments')
                .select('id')
                .eq('device_fingerprint', device_fingerprint)
                .eq('document_id', document_id)
                .eq('status', 'completed')
                .limit(1);

            if (exist && exist.length > 0) {
                return res.status(200).json({ already_paid: true });
            }

            const { data: doc, error: derr } = await supabase
                .from('documents')
                .select('price,currency,title')
                .eq('id', document_id)
                .eq('active', true)
                .single();

            if (derr || !doc) return res.status(404).json({ error: 'Document not found' });

            const { error: ierr } = await supabase
                .from('payments')
                .insert({
                    document_id,
                    device_fingerprint,
                    client_token,
                    amount: doc.price,
                    currency: doc.currency,
                    status: 'pending'
                });

            if (ierr) {
                console.error('Init payment error:', ierr);
                return res.status(500).json({ error: 'Failed to initiate payment' });
            }

            return res.status(200).json({
                success: true,
                amount: doc.price,
                currency: doc.currency,
                title: doc.title
            });
        }

        // Check payment
        if (path === '/api/check-payment' && method === 'POST') {
            const { client_token, device_fingerprint, document_id } = req.body;

            if (client_token) {
                if (!vt(client_token)) return res.status(400).json({ error: 'Invalid token' });
                const { data } = await supabase
                    .from('payments')
                    .select('status,document_id,amount,currency')
                    .eq('client_token', client_token)
                    .single();

                if (!data) return res.status(404).json({ error: 'Payment not found' });
                return res.status(200).json({
                    paid: data.status === 'completed',
                    status: data.status,
                    document_id: data.document_id,
                    amount: data.amount,
                    currency: data.currency
                });
            }

            if (device_fingerprint && document_id) {
                if (!vf(device_fingerprint) || !vu(document_id)) {
                    return res.status(400).json({ error: 'Invalid parameters' });
                }
                const { data } = await supabase
                    .from('payments')
                    .select('id')
                    .eq('device_fingerprint', device_fingerprint)
                    .eq('document_id', document_id)
                    .eq('status', 'completed')
                    .limit(1);

                return res.status(200).json({ already_paid: data && data.length > 0 });
            }

            return res.status(400).json({ error: 'Missing parameters' });
        }

        // Download
        if (path === '/api/download' && method === 'POST') {
            const { client_token, device_fingerprint, document_id } = req.body;
            if (!vt(client_token) || !vf(device_fingerprint) || !vu(document_id)) {
                return res.status(400).json({ error: 'Invalid parameters' });
            }

            const { data: payment } = await supabase
                .from('payments')
                .select('*')
                .eq('client_token', client_token)
                .eq('device_fingerprint', device_fingerprint)
                .eq('document_id', document_id)
                .eq('status', 'completed')
                .single();

            if (!payment) return res.status(403).json({ error: 'Payment not confirmed' });

            const { data: doc } = await supabase
                .from('documents')
                .select('file_path')
                .eq('id', document_id)
                .single();

            if (!doc) return res.status(404).json({ error: 'Document not found' });

            const { data: signed, error: serr } = await supabase
                .storage
                .from('documents')
                .createSignedUrl(doc.file_path, 600);

            if (serr || !signed) {
                console.error('Signed URL error:', serr);
                return res.status(500).json({ error: 'Failed to generate download link' });
            }

            await supabase
                .from('payments')
                .update({ downloaded: true, downloaded_at: new Date().toISOString() })
                .eq('id', payment.id);

            return res.status(200).json({ url: signed.signedUrl });
        }

        // AfriPay callback
        if (path === '/api/callback' && method === 'POST') {
            const { status, transaction_ref, client_token, amount, payment_method } = req.body;
            if (!client_token || !vt(client_token)) {
                return res.status(400).json({ error: 'Invalid token' });
            }

            const { data: p } = await supabase
                .from('payments')
                .select('id,amount,status')
                .eq('client_token', client_token)
                .single();

            if (!p) return res.status(404).json({ error: 'Payment not found' });
            if (p.status === 'completed') return res.status(200).json({ received: true });

            if (status === 'success') {
                await supabase
                    .from('payments')
                    .update({
                        status: 'completed',
                        transaction_ref: transaction_ref || null,
                        payment_method: payment_method || null,
                        amount: parseInt(amount) || p.amount
                    })
                    .eq('client_token', client_token)
                    .eq('status', 'pending');
            } else {
                await supabase
                    .from('payments')
                    .update({ status: 'failed' })
                    .eq('client_token', client_token);
            }

            return res.status(200).json({ received: true });
        }

        // ═══════════════════════════════════════════
        // ADMIN ENDPOINTS
        // ═══════════════════════════════════════════

        // Admin verify
        if (path === '/api/admin/verify' && method === 'POST') {
            const ok = await isAdmin(req);
            return res.status(200).json({ authenticated: ok });
        }

        // Admin upload file
        if (path === '/api/admin/upload' && method === 'POST') {
            if (!(await isAdmin(req))) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const ct = req.headers['content-type'] || '';
            if (!ct.includes('multipart/form-data')) {
                return res.status(400).json({ error: 'Expected file upload' });
            }

            const boundary = ct.split('boundary=')[1];
            if (!boundary) return res.status(400).json({ error: 'No boundary found' });

            const chunks = [];
            for await (const chunk of req) chunks.push(chunk);
            const body = Buffer.concat(chunks).toString();
            const parts = body.split('--' + boundary);

            let fileBuffer = null;
            let fileName = null;
            let fileType = null;

            for (const part of parts) {
                if (part.includes('filename=')) {
                    const headerEnd = part.indexOf('\r\n\r\n');
                    if (headerEnd === -1) continue;
                    const header = part.substring(0, headerEnd);
                    const content = part.substring(headerEnd + 4);

                    const fnMatch = header.match(/filename="(.+?)"/);
                    if (fnMatch) fileName = fnMatch[1];

                    const ctMatch = header.match(/Content-Type: (.+)/);
                    if (ctMatch) fileType = ctMatch[1].trim();

                    fileBuffer = Buffer.from(
                        content.replace(/\r\n--$/, '').replace(/--$/, ''),
                        'binary'
                    );
                }
            }

            if (!fileBuffer || !fileName) {
                return res.status(400).json({ error: 'No file uploaded' });
            }

            const safeName = `${Date.now()}_${fileName.replace(/[^a-zA-Z0-9._-]/g, '_')}`;

            const { error } = await supabase
                .storage
                .from('documents')
                .upload(safeName, fileBuffer, {
                    contentType: fileType || 'application/octet-stream',
                    cacheControl: '3600',
                    upsert: false
                });

            if (error) {
                console.error('Upload error:', error);
                return res.status(500).json({ error: 'Upload failed: ' + error.message });
            }

            return res.status(200).json({
                file_path: safeName,
                filename: fileName,
                size: fileBuffer.length
            });
        }

        // Admin list all documents
        if (path === '/api/admin/documents' && method === 'GET') {
            if (!(await isAdmin(req))) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const { data, error } = await supabase
                .from('documents')
                .select('*')
                .order('created_at', { ascending: false });

            if (error) {
                console.error('Admin list error:', error);
                return res.status(500).json({ error: 'Failed to fetch documents' });
            }

            return res.status(200).json(data || []);
        }

        // Admin add document
        if (path === '/api/admin/documents' && method === 'POST') {
            if (!(await isAdmin(req))) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const { title, description, image_url, file_path, price, currency } = req.body;

            if (!title || typeof title !== 'string' || title.trim().length === 0 || title.length > 200) {
                return res.status(400).json({ error: 'Title is required (1-200 characters)' });
            }
            if (!file_path || typeof file_path !== 'string') {
                return res.status(400).json({ error: 'File path is required' });
            }
            if (!price || isNaN(price) || parseInt(price) <= 0) {
                return res.status(400).json({ error: 'Valid price is required' });
            }

            const { data, error } = await supabase
                .from('documents')
                .insert({
                    title: title.trim(),
                    description: (description || '').trim(),
                    image_url: (image_url || '').trim(),
                    file_path: file_path.trim(),
                    price: parseInt(price),
                    currency: (currency || 'RWF').toUpperCase(),
                    active: true
                })
                .select()
                .single();

            if (error) {
                console.error('Admin insert error:', error);
                return res.status(500).json({ error: 'Failed to add document' });
            }

            return res.status(201).json(data);
        }

        // Admin delete document
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+$/) && method === 'DELETE') {
            if (!(await isAdmin(req))) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const docId = path.split('/').pop();
            if (!vu(docId)) return res.status(400).json({ error: 'Invalid ID' });

            const { data: doc } = await supabase
                .from('documents')
                .select('file_path')
                .eq('id', docId)
                .single();

            if (doc && doc.file_path) {
                await supabase.storage.from('documents').remove([doc.file_path]);
            }

            const { error } = await supabase
                .from('documents')
                .delete()
                .eq('id', docId);

            if (error) {
                console.error('Admin delete error:', error);
                return res.status(500).json({ error: 'Failed to delete' });
            }

            return res.status(200).json({ success: true });
        }

        // Admin toggle document
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+\/toggle$/) && method === 'PUT') {
            if (!(await isAdmin(req))) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const docId = path.split('/')[4];
            if (!vu(docId)) return res.status(400).json({ error: 'Invalid ID' });

            const { data: doc } = await supabase
                .from('documents')
                .select('active')
                .eq('id', docId)
                .single();

            if (!doc) return res.status(404).json({ error: 'Document not found' });

            const { error } = await supabase
                .from('documents')
                .update({ active: !doc.active })
                .eq('id', docId);

            if (error) {
                console.error('Admin toggle error:', error);
                return res.status(500).json({ error: 'Failed to toggle' });
            }

            return res.status(200).json({ active: !doc.active });
        }

        // 404 for everything else
        return res.status(404).json({ error: 'Endpoint not found' });

    } catch (err) {
        console.error('Unhandled error:', err);
        return res.status(500).json({
            error: 'Internal server error',
            message: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
}
