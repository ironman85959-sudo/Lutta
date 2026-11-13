'use strict';
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');
const { createClient } = require('@supabase/supabase-js');

const need = ['FIREBASE_SERVICE_ACCOUNT', 'SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY'];
const missing = need.filter((k) => !process.env[k]);

let fb = null, sb = null;
if (!missing.length) {
  admin.initializeApp({ credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)) });
  fb = admin;
  sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
}

// Upload rules per bucket: allowed mime prefixes + max bytes
const RULES = {
  avatars: { mime: ['image/'], max: 2 * 1024 * 1024 },
  covers:  { mime: ['image/'], max: 4 * 1024 * 1024 },
  posts:   { mime: ['image/', 'video/'], max: 50 * 1024 * 1024 },
  stories: { mime: ['image/', 'video/'], max: 30 * 1024 * 1024 },
  reels:   { mime: ['video/'], max: 80 * 1024 * 1024 },
  dreams:  { mime: ['image/'], max: 5 * 1024 * 1024 },
  chat:    { mime: ['image/'], max: 5 * 1024 * 1024 },
};

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
const origins = (process.env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
app.use(cors({ origin: (o, cb) => cb(null, !o || origins.includes(o)) }));

app.get('/api/health', (req, res) => {
  res.json({
    ok: missing.length === 0,
    service: 'tuner-social-server',
    time: new Date().toISOString(),
    missingEnv: missing, // names only, never values
  });
});

function ready(req, res, next) {
  if (missing.length) return res.status(503).json({ error: 'Server not configured', missingEnv: missing });
  next();
}

async function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    if (!token) return res.status(401).json({ error: 'Missing token' });
    req.user = await fb.auth().verifyIdToken(token);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// 1) Signed upload URL: client uploads straight to Supabase (real progress via XHR)
app.post('/api/upload/sign', ready, auth, rateLimit({ windowMs: 60000, limit: 30 }), async (req, res) => {
  try {
    const { bucket, fileName, mimeType, size } = req.body || {};
    const rule = RULES[bucket];
    if (!rule) return res.status(400).json({ error: 'Unknown bucket' });
    if (!req.user.email_verified) return res.status(403).json({ error: 'Verify your email before uploading' });
    if (!rule.mime.some((m) => String(mimeType).startsWith(m))) return res.status(400).json({ error: 'File type not allowed' });
    if (!Number.isFinite(size) || size <= 0 || size > rule.max) return res.status(400).json({ error: `File too large (max ${rule.max / 1048576} MB)` });

    const ext = String(fileName || 'file').split('.').pop().replace(/[^a-z0-9]/gi, '').slice(0, 5).toLowerCase() || 'bin';
    const path = `${req.user.uid}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
    const { data, error } = await sb.storage.from(bucket).createSignedUploadUrl(path);
    if (error) return res.status(500).json({ error: error.message });

    await sb.from('media_assets').insert({ owner_uid: req.user.uid, bucket, path, mime_type: mimeType, size_bytes: size });
    const publicUrl = sb.storage.from(bucket).getPublicUrl(path).data.publicUrl;
    res.json({ bucket, path, token: data.token, signedUrl: data.signedUrl, publicUrl });
  } catch (e) {
    res.status(500).json({ error: 'Could not create upload URL' });
  }
});

// 2) Username -> email for "login with username" (rate limited; see README tradeoff)
app.post('/api/auth/resolve', ready, rateLimit({ windowMs: 60000, limit: 10 }), async (req, res) => {
  try {
    const u = String((req.body || {}).username || '').toLowerCase();
    if (!/^[a-z0-9_.]{3,20}$/.test(u)) return res.status(400).json({ error: 'Invalid username' });
    const snap = await fb.firestore().doc(`usernames/${u}`).get();
    if (!snap.exists) return res.status(404).json({ error: 'Invalid credentials' });
    const user = await fb.auth().getUser(snap.data().uid);
    res.json({ email: user.email });
  } catch (e) {
    res.status(500).json({ error: 'Lookup failed' });
  }
});

// 3) Username availability (public, no email leak)
app.get('/api/username/:u', ready, rateLimit({ windowMs: 60000, limit: 40 }), async (req, res) => {
  const u = String(req.params.u).toLowerCase();
  if (!/^[a-z0-9_.]{3,20}$/.test(u)) return res.json({ available: false, reason: 'invalid' });
  const snap = await fb.firestore().doc(`usernames/${u}`).get();
  res.json({ available: !snap.exists });
});

// 4) Full account deletion: Auth user, Firestore profile, username, and Supabase files
app.delete('/api/account', ready, auth, rateLimit({ windowMs: 3600000, limit: 5 }), async (req, res) => {
  const uid = req.user.uid;
  try {
    const db = fb.firestore();
    const prof = await db.doc(`users/${uid}`).get();
    if (prof.exists && prof.data().username) await db.doc(`usernames/${prof.data().username}`).delete();
    await db.recursiveDelete(db.doc(`users/${uid}`));
    for (const col of ['posts', 'reels', 'dreams', 'stories']) {
      const q = await db.collection(col).where('authorId', '==', uid).get();
      await Promise.all(q.docs.map((d) => db.recursiveDelete(d.ref)));
    }
    const { data: rows } = await sb.from('media_assets').select('bucket,path').eq('owner_uid', uid);
    const byBucket = {};
    (rows || []).forEach((r) => (byBucket[r.bucket] = (byBucket[r.bucket] || []).concat(r.path)));
    for (const [b, paths] of Object.entries(byBucket)) await sb.storage.from(b).remove(paths);
    await sb.from('media_assets').delete().eq('owner_uid', uid);
    await fb.auth().deleteUser(uid);
    res.json({ deleted: true });
  } catch (e) {
    res.status(500).json({ error: 'Deletion failed part-way; retry' });
  }
});

app.listen(process.env.PORT || 10000, () => console.log('Tuner Social server up', missing.length ? `(missing env: ${missing.join(', ')})` : ''));
