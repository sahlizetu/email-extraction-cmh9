'use strict';

const crypto = require('crypto');
const path = require('path');
const { once } = require('events');
const express = require('express');
const helmet = require('helmet');
const { ImapFlow } = require('imapflow');
const { extractEmail, sanitizeFilename, MODES } = require('./lib/email-engine');
const { sealCredentials, openCredentials } = require('./lib/secure-token');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_LIMIT = Math.max(1, Number(process.env.MAX_EXTRACTION_LIMIT || 100));
const SESSION_TTL = 30 * 60 * 1000;
const AUTH_TTL_SECONDS = 30 * 24 * 60 * 60;
const COMBINED_SEPARATOR = Buffer.from('\r\n__SEP__\r\n', 'utf8');
const SESSION_SECRET = String(process.env.SESSION_SECRET || '').trim();
const REMEMBER_AVAILABLE = SESSION_SECRET.length >= 32;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const sessions = new Map();
const jobs = new Map();
const encryptionKey = crypto.randomBytes(32);

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"] } } }));
app.use(express.json({ limit: '64kb' }));
app.use('/api', (req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

function parseCookies(value = '') {
  const output = {};
  for (const part of String(value).split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const key = part.slice(0, index).trim();
    try { output[key] = decodeURIComponent(part.slice(index + 1).trim()); } catch { output[key] = ''; }
  }
  return output;
}
function appendCookie(res, value) {
  const current = res.getHeader('Set-Cookie');
  if (!current) res.setHeader('Set-Cookie', value);
  else res.setHeader('Set-Cookie', Array.isArray(current) ? [...current, value] : [current, value]);
}
function cookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${IS_PRODUCTION ? '; Secure' : ''}`;
}
function clearCookie(res, name) { appendCookie(res, cookie(name, '', 0)); }
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return { iv: iv.toString('base64'), data: data.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}
function decrypt(blob) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(blob.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(blob.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(blob.data, 'base64')), decipher.final()]).toString('utf8');
}
function createSession(res, restoredCredentials = null) {
  const id = crypto.randomBytes(24).toString('base64url');
  const session = { id, touchedAt: Date.now(), credentials: null, folders: [], result: null, job: null, restored: Boolean(restoredCredentials) };
  if (restoredCredentials) session.credentials = { email: restoredCredentials.email, password: encrypt(restoredCredentials.password) };
  sessions.set(id, session);
  appendCookie(res, cookie('cmh9_session', id, Math.floor(SESSION_TTL / 1000)));
  return session;
}
function getSession(req, res, create = true) {
  const cookies = parseCookies(req.headers.cookie);
  let session = cookies.cmh9_session ? sessions.get(cookies.cmh9_session) : null;
  if (session && Date.now() - session.touchedAt > SESSION_TTL && session.job?.status !== 'processing') {
    sessions.delete(session.id); session = null;
  }
  if (!session && REMEMBER_AVAILABLE && cookies.cmh9_auth) {
    const credentials = openCredentials(cookies.cmh9_auth, SESSION_SECRET);
    if (credentials) session = createSession(res, credentials);
    else clearCookie(res, 'cmh9_auth');
  }
  if (!session && create) session = createSession(res);
  if (session) session.touchedAt = Date.now();
  return session;
}
function createClient(session) {
  if (!session?.credentials) throw Object.assign(new Error('Connect to Gmail first.'), { status: 401 });
  return new ImapFlow({
    host: 'imap.gmail.com', port: 993, secure: true,
    auth: { user: session.credentials.email, pass: decrypt(session.credentials.password) },
    logger: false, emitLogs: false, disableAutoIdle: true,
    connectionTimeout: 20000, greetingTimeout: 20000, socketTimeout: 120000
  });
}
function timeout(promise, milliseconds, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error(message), { status: 408 })), milliseconds); })
  ]).finally(() => clearTimeout(timer));
}
function safeError(error) {
  const message = String(error?.message || '');
  if (error?.authenticationFailed || /auth|credentials|login failed|invalid password/i.test(message)) return 'Gmail rejected the credentials. Use a valid Google App Password.';
  if (error?.status === 400 || error?.status === 401 || error?.status === 408) return message;
  if (/ENOTFOUND|ECONNREFUSED|ETIMEDOUT|socket|network/i.test(message)) return 'Could not reach Gmail IMAP. Retry in a moment.';
  return 'The Gmail operation failed. Reconnect Gmail and try again.';
}
function publicJob(job) {
  return { id: job.id, status: job.status, phase: job.phase, progress: job.progress, processed: job.processed, total: job.total, count: job.count || 0, bytes: job.bytes || 0, error: job.error || null };
}
async function closeClient(client) { if (client?.usable) await client.logout().catch(() => {}); }
async function listFolders(client) {
  const boxes = await timeout(client.list(), 30000, 'Loading Gmail folders timed out.');
  const folders = [];
  for (const box of boxes) {
    let count = 0;
    try { const status = await timeout(client.status(box.path, { messages: true }), 15000, 'Folder status timed out.'); count = status.messages || 0; } catch (error) { console.warn(`[folders] ${box.path}: ${error.message}`); }
    folders.push({ path: box.path, name: box.name || box.path, count, specialUse: box.specialUse || null });
  }
  return folders.sort((a, b) => (a.specialUse === '\\Inbox' ? -1 : b.specialUse === '\\Inbox' ? 1 : a.name.localeCompare(b.name)));
}
async function refreshSessionFolders(session) {
  let client;
  try { client = createClient(session); await timeout(client.connect(), 30000, 'Gmail connection timed out.'); session.folders = await listFolders(client); return session.folders; }
  finally { await closeClient(client); }
}

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'email-extraction-cmh9', version: '5.2.0', rememberAvailable: REMEMBER_AVAILABLE }));

app.post('/api/connect', async (req, res) => {
  const email = String(req.body.email || '').trim();
  const password = String(req.body.password || '').replace(/\s/g, '');
  const remember = Boolean(req.body.remember);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8) return res.status(400).json({ error: 'Enter a valid Gmail address and App Password.' });
  const session = getSession(req, res); let client;
  try {
    client = new ImapFlow({ host: 'imap.gmail.com', port: 993, secure: true, auth: { user: email, pass: password }, logger: false, emitLogs: false, disableAutoIdle: true, connectionTimeout: 20000, greetingTimeout: 20000, socketTimeout: 120000 });
    await timeout(client.connect(), 30000, 'Gmail connection timed out.');
    const folders = await listFolders(client);
    session.credentials = { email, password: encrypt(password) }; session.folders = folders; session.result = null; session.job = null; session.restored = false;
    if (remember && REMEMBER_AVAILABLE) appendCookie(res, cookie('cmh9_auth', sealCredentials({ email, password }, SESSION_SECRET), AUTH_TTL_SECONDS));
    else clearCookie(res, 'cmh9_auth');
    res.json({ connected: true, email, folders, rememberAvailable: REMEMBER_AVAILABLE });
  } catch (error) {
    session.credentials = null;
    console.error('[connect]', error?.stack || error);
    res.status(error?.status === 408 ? 504 : 401).json({ error: safeError(error) });
  } finally { await closeClient(client); }
});

app.get('/api/status', async (req, res) => {
  const session = getSession(req, res);
  if (session.credentials && !session.folders.length && session.restored) {
    try { await refreshSessionFolders(session); session.restored = false; }
    catch (error) { console.error('[restore]', error?.stack || error); session.credentials = null; session.folders = []; clearCookie(res, 'cmh9_auth'); }
  }
  res.json({ connected: Boolean(session.credentials), email: session.credentials?.email || null, folders: session.folders || [], hasResult: Boolean(session.result), job: session.job ? publicJob(session.job) : null, rememberAvailable: REMEMBER_AVAILABLE });
});
app.post('/api/logout', (req, res) => {
  const session = getSession(req, res, false); if (session) sessions.delete(session.id);
  clearCookie(res, 'cmh9_session'); clearCookie(res, 'cmh9_auth'); res.json({ ok: true });
});

async function runExtraction(session, job, { folder, start, limit, mode, options }) {
  let client; let lock;
  const update = (phase, progress) => { job.phase = phase; job.progress = progress; job.updatedAt = Date.now(); };
  try {
    update('Connecting to Gmail', 1);
    client = createClient(session); await timeout(client.connect(), 30000, 'Gmail connection timed out.');
    update('Opening folder', 3);
    lock = await timeout(client.getMailboxLock(folder), 30000, 'Opening the Gmail folder timed out.');
    const available = client.mailbox?.exists || 0;
    if (!available) throw Object.assign(new Error('This Gmail folder is empty.'), { status: 400 });
    if (start > available) throw Object.assign(new Error(`Start position exceeds the ${available} messages in this folder.`), { status: 400 });
    const end = Math.min(available, start + limit - 1);
    job.total = end - start + 1; job.processed = 0; update('Extracting emails', 5);
    const items = [];
    for await (const message of client.fetch(`${start}:${end}`, { source: true, envelope: true, uid: true })) {
      if (!message.source) continue;
      const extracted = await extractEmail(message.source, mode, options);
      const subject = message.envelope?.subject || `email-${message.uid}`;
      items.push({ uid: message.uid, subject, filename: `${String(items.length + 1).padStart(3, '0')}-${sanitizeFilename(subject)}.${extracted.extension}`, content: extracted.content, contentType: extracted.contentType });
      job.processed = items.length;
      update(`Extracting email ${job.processed} of ${job.total}`, Math.min(99, 5 + Math.round((job.processed / job.total) * 94)));
    }
    if (!items.length) throw Object.assign(new Error('No messages were returned for this range.'), { status: 400 });
    const bytes = items.reduce((sum, item) => sum + item.content.length, 0) + Math.max(0, items.length - 1) * COMBINED_SEPARATOR.length;
    session.result = { mode, items, bytes, createdAt: Date.now() };
    job.status = 'completed'; job.count = items.length; job.bytes = bytes; update('Ready to download', 100);
  } catch (error) {
    job.status = 'failed'; job.error = safeError(error); update('Extraction failed', 0);
    console.error(`[extract:${job.id}]`, error?.stack || error);
  } finally {
    if (lock) lock.release();
    await closeClient(client);
  }
}

app.post('/api/extract/start', (req, res) => {
  const session = getSession(req, res);
  const folder = String(req.body.folder || ''); const start = Number(req.body.start); const limit = Number(req.body.limit); const mode = String(req.body.mode || '');
  if (!session.credentials) return res.status(401).json({ error: 'Connect to Gmail first.' });
  if (session.job?.status === 'processing' && Date.now() - (session.job.updatedAt || session.job.createdAt || 0) < 10 * 60 * 1000) return res.status(409).json({ error: 'An extraction is already running.' });
  if (!session.folders.some(item => item.path === folder)) return res.status(400).json({ error: 'Select a valid Gmail folder.' });
  if (!Number.isInteger(start) || start < 1 || !Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) return res.status(400).json({ error: `Start must be at least 1 and limit must be from 1 to ${MAX_LIMIT}.` });
  if (!MODES.includes(mode)) return res.status(400).json({ error: 'Select a valid download mode.' });
  const now = Date.now();
  const job = { id: crypto.randomBytes(12).toString('base64url'), status: 'processing', phase: 'Connecting to Gmail', progress: 1, processed: 0, total: limit, error: null, createdAt: now, updatedAt: now };
  session.job = job; session.result = null;
  jobs.set(job.id, { job, sessionId: session.id, createdAt: now });
  console.log(`[extract:${job.id}] accepted ${mode} ${folder} ${start}:${limit}`);
  res.status(202).json({ jobId: job.id });
  setTimeout(() => { void runExtraction(session, job, { folder, start, limit, mode, options: req.body.options || {} }); }, 0);
});
app.get('/api/extract/progress', (req, res) => {
  const id = String(req.query.jobId || '');
  const job = jobs.get(id)?.job;
  if (!job) return res.status(404).json({ error: 'Extraction job not found. Reconnect Gmail and retry.' });
  res.json(publicJob(job));
});
app.post('/api/extract/reset', (req, res) => {
  const session = getSession(req, res, false);
  if (session?.job?.status === 'processing') { session.job.status = 'failed'; session.job.phase = 'Cancelled'; session.job.error = 'Extraction was reset. Please retry.'; }
  session && (session.job = null);
  res.json({ ok: true });
});

async function sendCombined(result, res, download) {
  const names = { clean: 'clean-headers', text: 'text-only', original: 'newsletter-original', headers: 'headers-only', body: 'body-only', received: 'received-only' };
  res.setHeader('Content-Type', 'text/plain; charset=utf-8'); res.setHeader('Content-Length', String(result.bytes));
  if (download) res.setHeader('Content-Disposition', `attachment; filename="${names[result.mode]}.txt"`);
  for (let index = 0; index < result.items.length; index++) {
    if (index > 0 && !res.write(COMBINED_SEPARATOR)) await once(res, 'drain');
    if (!res.write(result.items[index].content)) await once(res, 'drain');
  }
  res.end();
}
app.get('/api/download', async (req, res) => { const result = getSession(req, res, false)?.result; if (!result?.items?.length) return res.status(404).json({ error: 'No extraction result is available.' }); await sendCombined(result, res, true); });
app.get('/api/result-text', async (req, res) => { const result = getSession(req, res, false)?.result; if (!result?.items?.length) return res.status(404).json({ error: 'No extraction result is available.' }); await sendCombined(result, res, false); });

app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
app.get('/', (req, res) => { res.setHeader('Cache-Control', 'no-store'); res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'], maxAge: IS_PRODUCTION ? '5m' : 0 }));
app.use((req, res) => { res.setHeader('Cache-Control', 'no-store'); res.sendFile(path.join(__dirname, 'public', 'index.html')); });

setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL;
  for (const [id, session] of sessions) if (session.touchedAt < cutoff && session.job?.status !== 'processing') sessions.delete(id);
  for (const [id, entry] of jobs) {
    if (entry.job.status === 'processing' && Date.now() - entry.job.updatedAt > 10 * 60 * 1000) { entry.job.status = 'failed'; entry.job.phase = 'Extraction timed out'; entry.job.error = 'Extraction timed out. Reconnect Gmail and retry.'; }
    if (Date.now() - entry.createdAt > SESSION_TTL) jobs.delete(id);
  }
}, 60_000).unref();
process.on('unhandledRejection', error => console.error('[unhandledRejection]', error?.stack || error));
process.on('uncaughtException', error => console.error('[uncaughtException]', error?.stack || error));
if (require.main === module) app.listen(PORT, '0.0.0.0', () => console.log(`Email Extraction CMH9 v5.2.0 running on http://0.0.0.0:${PORT}`));
module.exports = app;
