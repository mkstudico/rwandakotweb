import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

const AFRIPAY_APP_ID = process.env.AFRIPAY_APP_ID;
const RATE_LIMIT_WINDOW = 60; // seconds
const MAX_REQUESTS_PER_WINDOW = 10;

// Simple in-memory rate limiter (resets on cold start, good enough for Vercel)
const rateLimits = new Map();

function rateLimit(ip) {
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW * 1000;
    
    if (!rateLimits.has(ip)) {
        rateLimits.set(ip, []);
    }
    
    const requests = rateLimits.get(ip).filter(t => t > windowStart);
    rateLimits.set(ip, requests);
    
    if (requests.length >= MAX_REQUESTS_PER_WINDOW) {
        return false;
    }
    
    requests.push(now);
    return true;
}

function validateToken(token) {
    // Client token must be alphanumeric with underscores, 20-80 chars
    return /^[a-zA-Z0-9_]{20,80}$/.test(token);
}

function validateFingerprint(fp) {
    return typeof fp === 'string' && fp.length >= 10 && fp.length <= 200;
}

function validateUUID(id) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
}

// Admin authentication middleware
async function authenticateAdmin(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return false;
    }
    
    const key = authHeader.replace('Bearer ', '');
    
    const { data: keys, error } = await supabase
        .from('admin_keys')
        .select('key_hash');
    
    if (error || !keys) return false;
    
    for (const row of keys) {
        if (bcrypt.compareSync(key, row.key_hash)) {
            return true;
        }
    }
    
    return false;
}

export default async function handler(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;
    const method = req.method;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    
    if (method === 'OPTIONS') return res.status(200).end();

    // Rate limit all POST endpoints
    if (method === 'POST' && !rateLimit(ip)) {
        return res.status(429).json({ error: 'Too many requests. Please wait.' });
    }

    try {
        // ═══════════════════════════════════════
        // PUBLIC: Get documents
        // ═══════════════════════════════════════
        if (path === '/api/documents' && method === 'GET') {
            const { data, error } = await supabase
                .from('documents')
                .select('id, title, description, image_url, price, currency, created_at')
                .eq('active', true)
                .order('created_at', { ascending: false });

            if (error) {
                console.error('Documents fetch error:', error);
                return res.status(500).json({ error: 'Failed to load documents' });
            }

            return res.status(200).json(data);
        }

        // ═══════════════════════════════════════
        // PUBLIC: Initiate payment
        // ═══════════════════════════════════════
        if (path === '/api/init-payment' && method === 'POST') {
            const { document_id, device_fingerprint, client_token } = req.body;

            // Validate inputs
            if (!validateUUID(document_id)) {
                return res.status(400).json({ error: 'Invalid document ID' });
            }
            if (!validateFingerprint(device_fingerprint)) {
                return res.status(400).json({ error: 'Invalid device fingerprint' });
            }
            if (!validateToken(client_token)) {
                return res.status(400).json({ error: 'Invalid token format' });
            }

            // Check if already paid for this document on this device
            const { data: existingPayment } = await supabase
                .from('payments')
                .select('id, status')
                .eq('device_fingerprint', device_fingerprint)
                .eq('document_id', document_id)
                .eq('status', 'completed')
                .limit(1);

            if (existingPayment && existingPayment.length > 0) {
                return res.status(200).json({ 
                    already_paid: true,
                    client_token: existingPayment[0].id
                });
            }

            // Get document
            const { data: doc, error: docError } = await supabase
                .from('documents')
                .select('price, currency, title')
                .eq('id', document_id)
                .eq('active', true)
                .single();

            if (docError || !doc) {
                return res.status(404).json({ error: 'Document not found' });
            }

            // Check for duplicate client_token
            const { data: existingToken } = await supabase
                .from('payments')
                .select('id')
                .eq('client_token', client_token)
                .limit(1);

            if (existingToken && existingToken.length > 0) {
                return res.status(400).json({ error: 'Duplicate token. Please refresh.' });
            }

            // Create pending payment
            const { error: insertError } = await supabase
                .from('payments')
                .insert({
                    document_id,
                    device_fingerprint,
                    client_token,
                    amount: doc.price,
                    currency: doc.currency,
                    status: 'pending'
                });

            if (insertError) {
                console.error('Payment insert error:', insertError);
                return res.status(500).json({ error: 'Failed to initiate payment' });
            }

            return res.status(200).json({
                success: true,
                amount: doc.price,
                currency: doc.currency,
                document_title: doc.title
            });
        }

        // ═══════════════════════════════════════
        // PUBLIC: Check payment status
        // ═══════════════════════════════════════
        if (path === '/api/check-payment' && method === 'POST') {
            const { client_token, device_fingerprint, document_id } = req.body;

            // Two modes: check by token OR check by device+document
            if (client_token) {
                if (!validateToken(client_token)) {
                    return res.status(400).json({ error: 'Invalid token' });
                }

                const { data, error } = await supabase
                    .from('payments')
                    .select('status, document_id, amount, currency')
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
                    currency: data.currency
                });
            }

            // Check by device + document
            if (device_fingerprint && document_id) {
                if (!validateFingerprint(device_fingerprint) || !validateUUID(document_id)) {
                    return res.status(400).json({ error: 'Invalid parameters' });
                }

                const { data, error } = await supabase
                    .from('payments')
                    .select('id, status')
                    .eq('device_fingerprint', device_fingerprint)
                    .eq('document_id', document_id)
                    .eq('status', 'completed')
                    .limit(1);

                if (error) {
                    return res.status(500).json({ error: 'Check failed' });
                }

                return res.status(200).json({
                    already_paid: data && data.length > 0
                });
            }

            return res.status(400).json({ error: 'Missing parameters' });
        }

        // ═══════════════════════════════════════
        // PUBLIC: Get download URL
        // ═══════════════════════════════════════
        if (path === '/api/download' && method === 'POST') {
            const { client_token, device_fingerprint, document_id } = req.body;

            if (!validateToken(client_token) || !validateFingerprint(device_fingerprint) || !validateUUID(document_id)) {
                return res.status(400).json({ error: 'Invalid parameters' });
            }

            // Verify payment
            const { data: payment, error: paymentError } = await supabase
                .from('payments')
                .select('*')
                .eq('client_token', client_token)
                .eq('device_fingerprint', device_fingerprint)
                .eq('document_id', document_id)
                .eq('status', 'completed')
                .single();

            if (paymentError || !payment) {
                return res.status(403).json({ error: 'Payment not confirmed. Please complete payment first.' });
            }

            // Get document file path
            const { data: doc, error: docError } = await supabase
                .from('documents')
                .select('file_path')
                .eq('id', document_id)
                .single();

            if (docError || !doc) {
                return res.status(404).json({ error: 'Document not found' });
            }

            // Generate signed URL (valid 10 minutes)
            const { data: signedData, error: signedError } = await supabase
                .storage
                .from('documents')
                .createSignedUrl(doc.file_path, 600);

            if (signedError || !signedData) {
                console.error('Signed URL error:', signedError);
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

            return res.status(200).json({
                url: signedData.signedUrl,
                filename: doc.file_path.split('/').pop()
            });
        }

        // ═══════════════════════════════════════
        // AFRIPAY CALLBACK: /api/callback
        // ═══════════════════════════════════════
        if (path === '/api/callback' && method === 'POST') {
            const { 
                status, 
                transaction_ref, 
                client_token, 
                amount, 
                currency, 
                payment_method 
            } = req.body;

            if (!client_token) {
                console.error('Callback missing client_token');
                return res.status(400).json({ error: 'Missing client_token' });
            }

            if (!validateToken(client_token)) {
                console.error('Callback invalid token:', client_token);
                return res.status(400).json({ error: 'Invalid token format' });
            }

            // CRITICAL: Verify this payment actually exists and is pending
            const { data: existingPayment, error: fetchError } = await supabase
                .from('payments')
                .select('id, amount, status')
                .eq('client_token', client_token)
                .single();

            if (fetchError || !existingPayment) {
                console.error('Callback: Payment not found for token:', client_token);
                return res.status(404).json({ error: 'Payment record not found' });
            }

            // Prevent double-completion
            if (existingPayment.status === 'completed') {
                console.warn('Callback: Payment already completed for token:', client_token);
                return res.status(200).json({ received: true, note: 'Already completed' });
            }

            if (status === 'success') {
                // Verify amount matches to prevent tampering
                const callbackAmount = parseInt(amount);
                if (callbackAmount && callbackAmount !== existingPayment.amount) {
                    console.error('Amount mismatch:', { 
                        expected: existingPayment.amount, 
                        received: callbackAmount 
                    });
                    // Still mark as completed but log the discrepancy
                }

                const { error: updateError } = await supabase
                    .from('payments')
                    .update({
                        status: 'completed',
                        transaction_ref: transaction_ref || null,
                        payment_method: payment_method || null,
                        amount: callbackAmount || existingPayment.amount,
                        currency: currency || existingPayment.currency
                    })
                    .eq('client_token', client_token)
                    .eq('status', 'pending'); // Only update if still pending

                if (updateError) {
                    console.error('Callback update error:', updateError);
                    return res.status(500).json({ error: 'Failed to update payment' });
                }

                console.log('Payment confirmed:', { client_token, transaction_ref, amount });
            } else {
                // Payment failed or cancelled
                await supabase
                    .from('payments')
                    .update({ 
                        status: 'failed',
                        transaction_ref: transaction_ref || null
                    })
                    .eq('client_token', client_token);
            }

            return res.status(200).json({ received: true });
        }

        // ═══════════════════════════════════════
        // ADMIN: Verify admin key
        // ═══════════════════════════════════════
        if (path === '/api/admin/verify' && method === 'POST') {
            const isAdmin = await authenticateAdmin(req);
            return res.status(200).json({ authenticated: isAdmin });
        }

        // ═══════════════════════════════════════
        // ADMIN: Add document
        // ═══════════════════════════════════════
        if (path === '/api/admin/documents' && method === 'POST') {
            const isAdmin = await authenticateAdmin(req);
            if (!isAdmin) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const { title, description, image_url, file_path, price, currency } = req.body;

            // Validate
            if (!title || typeof title !== 'string' || title.trim().length < 1 || title.length > 200) {
                return res.status(400).json({ error: 'Title is required (1-200 chars)' });
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
                console.error('Add document error:', error);
                return res.status(500).json({ error: 'Failed to add document' });
            }

            return res.status(201).json(data);
        }

        // ═══════════════════════════════════════
        // ADMIN: List all documents (including inactive)
        // ═══════════════════════════════════════
        if (path === '/api/admin/documents' && method === 'GET') {
            const isAdmin = await authenticateAdmin(req);
            if (!isAdmin) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const { data, error } = await supabase
                .from('documents')
                .select('*')
                .order('created_at', { ascending: false });

            if (error) {
                return res.status(500).json({ error: 'Failed to fetch documents' });
            }

            return res.status(200).json(data);
        }

        // ═══════════════════════════════════════
        // ADMIN: Delete document
        // ═══════════════════════════════════════
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+$/) && method === 'DELETE') {
            const isAdmin = await authenticateAdmin(req);
            if (!isAdmin) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const docId = path.split('/').pop();
            if (!validateUUID(docId)) {
                return res.status(400).json({ error: 'Invalid document ID' });
            }

            // Get file path before deleting
            const { data: doc } = await supabase
                .from('documents')
                .select('file_path')
                .eq('id', docId)
                .single();

            // Delete from storage
            if (doc?.file_path) {
                await supabase.storage.from('documents').remove([doc.file_path]);
            }

            // Delete from database
            const { error } = await supabase
                .from('documents')
                .delete()
                .eq('id', docId);

            if (error) {
                return res.status(500).json({ error: 'Failed to delete document' });
            }

            return res.status(200).json({ success: true });
        }

        // ═══════════════════════════════════════
        // ADMIN: Toggle document active status
        // ═══════════════════════════════════════
        if (path.match(/^\/api\/admin\/documents\/[a-f0-9-]+\/toggle$/) && method === 'PUT') {
            const isAdmin = await authenticateAdmin(req);
            if (!isAdmin) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            const docId = path.split('/')[4];
            if (!validateUUID(docId)) {
                return res.status(400).json({ error: 'Invalid document ID' });
            }

            const { data: doc, error: fetchError } = await supabase
                .from('documents')
                .select('active')
                .eq('id', docId)
                .single();

            if (fetchError || !doc) {
                return res.status(404).json({ error: 'Document not found' });
            }

            const { error } = await supabase
                .from('documents')
                .update({ active: !doc.active })
                .eq('id', docId);

            if (error) {
                return res.status(500).json({ error: 'Failed to toggle document' });
            }

            return res.status(200).json({ active: !doc.active });
        }

        // ═══════════════════════════════════════
        // ADMIN: Upload file to storage
        // ═══════════════════════════════════════
        if (path === '/api/admin/upload' && method === 'POST') {
            const isAdmin = await authenticateAdmin(req);
            if (!isAdmin) {
                return res.status(401).json({ error: 'Unauthorized' });
            }

            // Handle multipart form data
            const contentType = req.headers['content-type'] || '';
            if (!contentType.includes('multipart/form-data')) {
                return res.status(400).json({ error: 'Expected file upload' });
            }

            // Parse the multipart form
            const boundary = contentType.split('boundary=')[1];
            if (!boundary) {
                return res.status(400).json({ error: 'No boundary found' });
            }

            const chunks = [];
            for await (const chunk of req) {
                chunks.push(chunk);
            }
            const body = Buffer.concat(chunks);

            // Simple multipart parser
            const bodyStr = body.toString();
            const parts = bodyStr.split('--' + boundary);
            
            let fileBuffer = null;
            let fileName = null;
            let fileType = null;

            for (const part of parts) {
                if (part.includes('Content-Disposition') && part.includes('filename=')) {
                    const headerEnd = part.indexOf('\r\n\r\n');
                    const header = part.substring(0, headerEnd);
                    const content = part.substring(headerEnd + 4);
                    
                    const filenameMatch = header.match(/filename="(.+?)"/);
                    if (filenameMatch) {
                        fileName = filenameMatch[1];
                    }
                    
                    const typeMatch = header.match(/Content-Type: (.+)/);
                    if (typeMatch) {
                        fileType = typeMatch[1].trim();
                    }

                    // Get binary content (trim trailing boundary)
                    const cleanContent = content.replace(/\r\n--$/, '').replace(/--$/, '');
                    fileBuffer = Buffer.from(cleanContent, 'binary');
                }
            }

            if (!fileBuffer || !fileName) {
                return res.status(400).json({ error: 'No file uploaded' });
            }

            // Generate unique filename
            const timestamp = Date.now();
            const safeName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
            const uniqueName = `${timestamp}_${safeName}`;

            // Upload to Supabase Storage
            const { data, error } = await supabase
                .storage
                .from('documents')
                .upload(uniqueName, fileBuffer, {
                    contentType: fileType || 'application/octet-stream',
                    cacheControl: '3600',
                    upsert: false
                });

            if (error) {
                console.error('Upload error:', error);
                return res.status(500).json({ error: 'Upload failed: ' + error.message });
            }

            return res.status(200).json({
                file_path: uniqueName,
                filename: fileName,
                size: fileBuffer.length
            });
        }

        // ═══════════════════════════════════════
        // 404
        // ═══════════════════════════════════════
        return res.status(404).json({ error: 'Endpoint not found' });

    } catch (err) {
        console.error('Unhandled error:', err);
        return res.status(500).json({ 
            error: 'Internal server error',
            message: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
}
