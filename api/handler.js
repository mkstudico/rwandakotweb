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

            if (error) {
                console.error('GET documents error:', error);
                return res.status(500).json({ error: 'Failed to fetch documents' });
            }

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
                .eq('id', docId)
                .eq('active', true)
                .single();

            if (error || !data) return res.status(404).json({ error: 'Document not found' });
            return res.status(200).json(data);
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Track document click
        // ═══════════════════════════════════════════
        if (path.match(/^\/api\/documents\/[a-f0-9-]+\/click$/) && method === 'POST') {
            const docId = path.split('/')[3];
            if (!vu(docId)) return res.status(400).json({ error: 'Invalid document ID' });

            const { error } = await supabase.rpc('increment_click', { doc_id: docId });
            if (error) console.error('Click track error:', error);

            return res.status(200).json({ ok: true });
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Initiate payment
        // ═══════════════════════════════════════════
        if (path === '/api/init-payment' && method === 'POST') {
            const { document_id, device_fingerprint, client_token } = req.body;

            if (!vu(document_id) || !vf(device_fingerprint) || !vt(client_token)) {
                return res.status(400).json({ error: 'Invalid parameters' });
            }

            // Check if already paid on this device
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
                if (diffMin <= DOWNLOAD_WINDOW_MINUTES) {
                    return res.status(200).json({ already_paid: true });
                }
            }

            // Check for duplicate token
            const { data: dupToken } = await supabase
                .from('payments')
                .select('id')
                .eq('client_token', client_token)
                .limit(1);

            if (dupToken && dupToken.length > 0) {
                return res.status(400).json({ error: 'Duplicate token. Please try again.' });
            }

            // Get document details
            const { data: doc, error: docErr } = await supabase
                .from('documents')
                .select('price,currency,title')
                .eq('id', document_id)
                .eq('active', true)
                .single();

            if (docErr || !doc) {
                return res.status(404).json({ error: 'Document not found' });
            }

            // Create pending payment record
            const { error: insertErr } = await supabase
                .from('payments')
                .insert({
                    document_id,
                    device_fingerprint,
                    client_token,
                    amount: doc.price,
                    currency: doc.currency,
                    status: 'pending'
                });

            if (insertErr) {
                console.error('Payment insert error:', insertErr);
                return res.status(500).json({ error: 'Failed to initiate payment' });
            }

            return res.status(200).json({
                success: true,
                amount: doc.price,
                currency: doc.currency,
                title: doc.title
            });
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Check payment status
        // ═══════════════════════════════════════════
        if (path === '/api/check-payment' && method === 'POST') {
            const { client_token, device_fingerprint, document_id } = req.body;

            // Check by client token
            if (client_token) {
                if (!vt(client_token)) return res.status(400).json({ error: 'Invalid token' });

                const { data, error } = await supabase
                    .from('payments')
                    .select('status, document_id, amount, currency, created_at')
                    .eq('client_token', client_token)
                    .single();

                if (error || !data) {
                    return res.status(404).json({ error: 'Payment not found' });
                }

                return res.status(200).json({
                    paid: data.status === 'completed',
                    status: data.status,
                    document_id: data.document_id,
                    amount: data.amount,
                    currency: data.currency,
                    created_at: data.created_at
                });
            }

            // Check by device fingerprint + document ID
            if (device_fingerprint && document_id) {
                if (!vf(device_fingerprint) || !vu(document_id)) {
                    return res.status(400).json({ error: 'Invalid parameters' });
                }

                const { data, error } = await supabase
                    .from('payments')
                    .select('id, status, created_at')
                    .eq('device_fingerprint', device_fingerprint)
                    .eq('document_id', document_id)
                    .eq('status', 'completed')
                    .order('created_at', { ascending: false })
                    .limit(1);

                if (error) return res.status(500).json({ error: 'Check failed' });

                const found = data && data.length > 0;
                const payment = found ? data[0] : null;

                let withinWindow = false;
                if (payment && payment.created_at) {
                    const diffMin = (Date.now() - new Date(payment.created_at).getTime()) / 60000;
                    withinWindow = diffMin <= DOWNLOAD_WINDOW_MINUTES;
                }

                return res.status(200).json({
                    already_paid: found && withinWindow,
                    payment: payment,
                    within_window: withinWindow
                });
            }

            return res.status(400).json({ error: 'Missing parameters' });
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Download document
        // ═══════════════════════════════════════════
        if (path === '/api/download' && method === 'POST') {
            const { client_token, device_fingerprint, document_id } = req.body;

            if (!vt(client_token) || !vf(device_fingerprint) || !vu(document_id)) {
                return res.status(400).json({ error: 'Invalid parameters' });
            }

            // Find completed payment
            const { data: payment, error: payErr } = await supabase
                .from('payments')
                .select('*')
                .eq('client_token', client_token)
                .eq('device_fingerprint', device_fingerprint)
                .eq('document_id', document_id)
                .eq('status', 'completed')
                .single();

            if (payErr || !payment) {
                return res.status(403).json({ error: 'Payment not confirmed. Please complete payment first.' });
            }

            // Check 30-minute download window
            const paidAt = new Date(payment.created_at);
            const diffMinutes = (Date.now() - paidAt.getTime()) / 60000;

            if (diffMinutes > DOWNLOAD_WINDOW_MINUTES) {
                return res.status(410).json({
                    error: 'Download window has expired. Please purchase the document again.',
                    expired: true
                });
            }

            // Get document file path
            const { data: doc, error: docErr } = await supabase
                .from('documents')
                .select('file_path')
                .eq('id', document_id)
                .single();

            if (docErr || !doc) {
                return res.status(404).json({ error: 'Document not found' });
            }

            // Generate signed URL (valid 10 minutes)
            const { data: signedData, error: signedErr } = await supabase
                .storage
                .from('documents')
                .createSignedUrl(doc.file_path, 600);

            if (signedErr || !signedData) {
                console.error('Signed URL error:', signedErr);
                return res.status(500).json({ error: 'Failed to generate download link' });
            }

            // Mark as downloaded
            await supabase
                .from('payments')
                .update({
                    downloaded: true,
                    downloaded_at: new Date().toISOString()
                })
                .eq('id', payment.id);

            const remainingMinutes = Math.max(0, Math.floor(DOWNLOAD_WINDOW_MINUTES - diffMinutes));

            return res.status(200).json({
                url: signedData.signedUrl,
                filename: doc.file_path.split('/').pop(),
                expires_in_minutes: remainingMinutes
            });
        }

        // ═══════════════════════════════════════════
        // PUBLIC: User payments history
        // ═══════════════════════════════════════════
        if (path === '/api/user-payments' && method === 'POST') {
            const { device_fingerprint } = req.body;

            if (!vf(device_fingerprint)) {
                return res.status(400).json({ error: 'Invalid fingerprint' });
            }

            const { data, error } = await supabase
                .from('payments')
                .select(`
                    id,
                    document_id,
                    client_token,
                    amount,
                    currency,
                    status,
                    transaction_ref,
                    payment_method,
                    downloaded,
                    created_at,
                    downloaded_at
                `)
                .eq('device_fingerprint', device_fingerprint)
                .order('created_at', { ascending: false })
                .limit(50);

            if (error) {
                console.error('User payments error:', error);
                return res.status(500).json({ error: 'Failed to fetch payments' });
            }

            // Enrich with document info
            const enriched = [];
            for (const p of (data || [])) {
                const { data: doc } = await supabase
                    .from('documents')
                    .select('title, image_url')
                    .eq('id', p.document_id)
                    .single();

                enriched.push({
                    ...p,
                    document_title: doc?.title || 'Unknown Document',
                    document_image: doc?.image_url || ''
                });
            }

            return res.status(200).json(enriched);
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Confirm payment on return from AfriPay
        // ═══════════════════════════════════════════
        if (path === '/api/confirm-payment' && method === 'POST') {
            const { client_token, device_fingerprint } = req.body;

            if (!client_token || !vt(client_token)) {
                return res.status(400).json({ error: 'Invalid token' });
            }

            const { data: payment, error: fetchErr } = await supabase
                .from('payments')
                .select('*')
                .eq('client_token', client_token)
                .single();

            if (fetchErr || !payment) {
                return res.status(404).json({ error: 'Payment not found' });
            }

            if (payment.status === 'completed') {
                return res.status(200).json({
                    confirmed: true,
                    document_id: payment.document_id,
                    note: 'Already confirmed'
                });
            }

            return res.status(200).json({
                confirmed: false,
                status: payment.status,
                document_id: payment.document_id,
                amount: payment.amount,
                currency: payment.currency,
                document_title: payment.document_title || 'Document',
                note: 'Payment requires verification. Redirecting to verification page.'
            });
        }

        // ═══════════════════════════════════════════
        // PUBLIC: Verify payment with screenshot + info
        // ═══════════════════════════════════════════
        if (path === '/api/verify-with-proof' && method === 'POST') {
            const {
                client_token,
                device_fingerprint,
                buyer_name,
                phone_number,
                ocr_text,
                match_percentage,
                is_suspicious
            } = req.body;

            if (!client_token || !vt(client_token)) {
                return res.status(400).json({ error: 'Invalid token' });
            }

            // Find the payment with document info
            const { data: payment, error: fetchErr } = await supabase
                .from('payments')
                .select('id, document_id, amount, currency, status, documents!inner(title, price, currency)')
                .eq('client_token', client_token)
                .single();

            if (fetchErr || !payment) {
                return res.status(404).json({ error: 'Payment not found' });
            }

            if (payment.status === 'completed') {
                return res.status(200).json({
                    verified: true,
                    suspicious: false,
                    document_id: payment.document_id,
                    message: 'Already verified'
                });
            }

            // Store verification proof
            const { error: proofErr } = await supabase
                .from('payment_verifications')
                .insert({
                    payment_id: payment.id,
                    client_token: client_token,
                    device_fingerprint: device_fingerprint || '',
                    buyer_name: buyer_name || '',
                    phone_number: phone_number || '',
                    ocr_text: ocr_text || '',
                    match_percentage: match_percentage || 0,
                    is_suspicious: is_suspicious || false,
                    verified_at: new Date().toISOString()
                });

            if (proofErr) {
                console.error('Verification insert error:', proofErr);
            }

            // If suspicious, double the price
            if (is_suspicious) {
                const newPrice = payment.amount * 2;

                const { error: updateErr } = await supabase
                    .from('payments')
                    .update({
                        amount: newPrice,
                        status: 'pending_verification',
                        transaction_ref: 'suspicious_' + client_token.substring(0, 8)
                    })
                    .eq('client_token', client_token);

                if (updateErr) {
                    console.error('Suspicious update error:', updateErr);
                    return res.status(500).json({ error: 'Failed to update payment' });
                }

                console.log('[Verify] Suspicious - price doubled:', {
                    token: client_token,
                    original: payment.amount,
                    new: newPrice
                });

                return res.status(200).json({
                    verified: false,
                    suspicious: true,
                    original_price: payment.amount,
                    new_price: newPrice,
                    currency: payment.currency,
                    document_id: payment.document_id,
                    document_title: payment.documents?.title || 'Document',
                    message: 'Amakuru yawe ntiyuzuye. Igiciro cyikubye kabiri.'
                });
            }

            // Not suspicious — mark as completed
            const { error: updateErr } = await supabase
                .from('payments')
                .update({
                    status: 'completed',
                    payment_method: 'verified_manual',
                    transaction_ref: 'verified_' + client_token.substring(0, 8)
                })
                .eq('client_token', client_token)
                .eq('status', 'pending');

            if (updateErr) {
                console.error('Verify update error:', updateErr);
                return res.status(500).json({ error: 'Failed to confirm payment' });
            }

            console.log('[Verify] Payment confirmed via proof:', client_token);

            return res.status(200).json({
                verified: true,
                suspicious: false,
                document_id: payment.document_id,
                document_title: payment.documents?.title || 'Document',
                message: 'Ubwishyu bwemejwe!'
            });
        }

        // ═══════════════════════════════════════════
        // AFRIPAY CALLBACK (webhook)
        // ═══════════════════════════════════════════
        if (path === '/api/callback' && method === 'POST') {
            const { status, transaction_ref, client_token, amount, currency, payment_method } = req.body;

            console.log('[Callback] Received:', JSON.stringify({
                status,
                transaction_ref,
                client_token,
                amount,
                currency,
                payment_method
            }));

            if (!client_token) {
                console.log('[Callback] Missing client_token');
                return res.status(200).json({ received: true, note: 'Missing token' });
            }

            if (!vt(client_token)) {
                console.log('[Callback] Invalid token format:', client_token);
                return res.status(200).json({ received: true, note: 'Invalid token format' });
            }

            const { data: payment, error: fetchErr } = await supabase
                .from('payments')
                .select('id, amount, status, document_id')
                .eq('client_token', client_token)
                .single();

            if (fetchErr || !payment) {
                console.log('[Callback] Payment not found for token:', client_token);
                return res.status(200).json({ received: true, note: 'Payment record not found' });
            }

            if (payment.status === 'completed') {
                console.log('[Callback] Already completed:', client_token);
                return res.status(200).json({ received: true, note: 'Already completed' });
            }

            if (status === 'success') {
                const callbackAmount = parseInt(amount);
                if (callbackAmount && callbackAmount !== payment.amount) {
                    console.warn('[Callback] Amount mismatch:', {
                        expected: payment.amount,
                        received: callbackAmount
                    });
                }

                const { error: updateErr } = await supabase
                    .from('payments')
                    .update({
                        status: 'completed',
                        transaction_ref: transaction_ref || null,
                        payment_method: payment_method || null,
                        amount: callbackAmount || payment.amount,
                        currency: currency || payment.currency
                    })
                    .eq('client_token', client_token)
                    .eq('status', 'pending');

                if (updateErr) {
                    console.error('[Callback] Update error:', updateErr);
                    return res.status(200).json({ received: true, note: 'Update failed but acknowledged' });
                }

                console.log('[Callback] Payment confirmed:', {
                    token: client_token,
                    ref: transaction_ref,
                    docId: payment.document_id
                });
            } else {
                const { error: failErr } = await supabase
                    .from('payments')
                    .update({
                        status: 'failed',
                        transaction_ref: transaction_ref || null
                    })
                    .eq('client_token', client_token)
                    .eq('status', 'pending');

                if (failErr) {
                    console.error('[Callback] Fail update error:', failErr);
                }

                console.log('[Callback] Payment failed:', client_token);
            }

            return res.status(200).json({ received: true });
        }

        // ═══════════════════════════════════════════
        // ADMIN: Verify admin key
        // ═══════════════════════════════════════════
        if (path === '/api/admin/verify' && method === 'POST') {
            const ok = await isAdmin(req);
            return res.status(200).json({ authenticated: ok });
        }

        // ═══════════════════════════════════════════
        // ADMIN: Upload file to storage
        // ═══════════════════════════════════════════
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
                console.error('[Upload] Error:', error);
                return res.status(500).json({ error: 'Upload failed: ' + error.message });
            }

            return res.status(200).json({
                file_path: safeName,
                filename: fileName,
                size: fileBuffer.length
            });
        }

        // ═══════════════════════════════════════════
        // ADMIN: List all documents
        // ═══════════════════════════════════════════
        if (path === '/api/admin/documents' && method === 'GET') {
            if (!(await isAdmin(req))) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const { data, error } = await supabase
                .from('documents')
                .select('*')
                .order('created_at', { ascending: false });

            if (error) {
                console.error('[Admin] List error:', error);
                return res.status(500).json({ error: 'Failed to fetch documents' });
            }

            return res.status(200).json(data || []);
        }

        // ═══════════════════════════════════════════
        // ADMIN: Add document
        // ═══════════════════════════════════════════
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
                console.error('[Admin] Insert error:', error);
                return res.status(500).json({ error: 'Failed to add document' });
            }

            return res.status(201).json(data);
        }

        // ═══════════════════════════════════════════
        // ADMIN: Delete document
        // ═══════════════════════════════════════════
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+$/) && method === 'DELETE') {
            if (!(await isAdmin(req))) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const docId = path.split('/').pop();
            if (!vu(docId)) return res.status(400).json({ error: 'Invalid document ID' });

            const { data: doc } = await supabase
                .from('documents')
                .select('file_path')
                .eq('id', docId)
                .single();

            if (doc && doc.file_path) {
                const { error: storageErr } = await supabase
                    .storage
                    .from('documents')
                    .remove([doc.file_path]);

                if (storageErr) {
                    console.warn('[Admin] Storage delete warning:', storageErr);
                }
            }

            const { error } = await supabase
                .from('documents')
                .delete()
                .eq('id', docId);

            if (error) {
                console.error('[Admin] Delete error:', error);
                return res.status(500).json({ error: 'Failed to delete document' });
            }

            return res.status(200).json({ success: true });
        }

        // ═══════════════════════════════════════════
        // ADMIN: Toggle document active status
        // ═══════════════════════════════════════════
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+\/toggle$/) && method === 'PUT') {
            if (!(await isAdmin(req))) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const docId = path.split('/')[4];
            if (!vu(docId)) return res.status(400).json({ error: 'Invalid document ID' });

            const { data: doc, error: fetchErr } = await supabase
                .from('documents')
                .select('active')
                .eq('id', docId)
                .single();

            if (fetchErr || !doc) {
                return res.status(404).json({ error: 'Document not found' });
            }

            const { error } = await supabase
                .from('documents')
                .update({ active: !doc.active })
                .eq('id', docId);

            if (error) {
                console.error('[Admin] Toggle error:', error);
                return res.status(500).json({ error: 'Failed to toggle document' });
            }

            return res.status(200).json({ active: !doc.active });
        }

        // ═══════════════════════════════════════════
        // ADMIN: List payment verifications
        // ═══════════════════════════════════════════
        if (path === '/api/admin/verifications' && method === 'GET') {
            if (!(await isAdmin(req))) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const { data, error } = await supabase
                .from('payment_verifications')
                .select('*')
                .order('verified_at', { ascending: false })
                .limit(100);

            if (error) {
                console.error('[Admin] Verifications error:', error);
                return res.status(500).json({ error: 'Failed to fetch' });
            }

            return res.status(200).json(data || []);
        }

        // ═══════════════════════════════════════════
        // 404
        // ═══════════════════════════════════════════
        return res.status(404).json({ error: 'Endpoint not found' });

    } catch (err) {
        console.error('[Handler] Unhandled error:', err);
        return res.status(500).json({
            error: 'Internal server error',
            message: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
}
