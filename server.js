'use strict';

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const archiver = require('archiver');
const { ImapFlow } = require('imapflow');
const { extractEmail, sanitizeFilename, MODES } = require('./lib/email-engine');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_LIMIT = Number(process.env.MAX_EXTRACTION_LIMIT || 100);
const SESSION_TTL = 30 * 60 * 1000;
const sessions = new Map();
const encryptionKey = crypto.randomBytes(32);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"] } } }));
app.use(express.json({ limit: '64kb' }));
app.use('/api/connect', rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false }));
app.use('/api', rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false }));

function cookieMap(value = '') { return Object.fromEntries(value.split(';').map(v => v.trim().split(/=(.*)/s)).filter(v => v[0]).map(([k,v]) => [k, decodeURIComponent(v || '')])); }
function getSession(req, res, create = true) {
  const id = cookieMap(req.headers.cookie).cmh9_session;
  let session = id && sessions.get(id);
  if (session && Date.now() - session.touchedAt > SESSION_TTL) { sessions.delete(id); session = null; }
  if (!session && create) {
    const newId = crypto.randomBytes(24).toString('base64url');
    session = { id: newId, touchedAt: Date.now(), credentials: null, folders: [], result: null };
    sessions.set(newId, session);
    res.setHeader('Set-Cookie', `cmh9_session=${newId}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
  }
  if (session) session.touchedAt = Date.now();
  return session;
}
function encrypt(text) { const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv); const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]); return { iv: iv.toString('base64'), data: data.toString('base64'), tag: cipher.getAuthTag().toString('base64') }; }
function decrypt(blob) { const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(blob.iv,'base64')); decipher.setAuthTag(Buffer.from(blob.tag,'base64')); return Buffer.concat([decipher.update(Buffer.from(blob.data,'base64')), decipher.final()]).toString('utf8'); }
function createClient(session) { if (!session?.credentials) throw Object.assign(new Error('Connect to Gmail first'), { status: 401 }); return new ImapFlow({ host:'imap.gmail.com', port:993, secure:true, auth:{ user: session.credentials.email, pass: decrypt(session.credentials.password) }, logger:false, emitLogs:false, disableAutoIdle:true, connectionTimeout:15000, greetingTimeout:15000, socketTimeout:60000 }); }
function safeError(error) { if (error?.authenticationFailed || /auth|credentials|login/i.test(error?.message || '')) return 'Gmail rejected the credentials. Confirm IMAP access and use a Google App Password.'; return error?.status === 401 ? error.message : 'The Gmail operation could not be completed. Please retry.'; }

app.post('/api/connect', async (req,res) => {
  const email = String(req.body.email || '').trim(); const password = String(req.body.password || '').replace(/\s/g,'');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8) return res.status(400).json({ error:'Enter a valid Gmail address and App Password.' });
  const session = getSession(req,res); let client;
  try {
    client = new ImapFlow({ host:'imap.gmail.com', port:993, secure:true, auth:{user:email,pass:password}, logger:false, emitLogs:false, connectionTimeout:15000, greetingTimeout:15000, socketTimeout:60000 });
    await client.connect();
    const boxes = await client.list();
    const folders = [];
    for (const box of boxes) {
      let count = 0;
      try { const status = await client.status(box.path, { messages:true }); count = status.messages || 0; } catch {}
      folders.push({ path:box.path, name:box.name || box.path, count, specialUse:box.specialUse || null });
    }
    folders.sort((a,b) => (a.specialUse === '\\Inbox' ? -1 : b.specialUse === '\\Inbox' ? 1 : a.name.localeCompare(b.name)));
    session.credentials = { email, password: encrypt(password) }; session.folders = folders; session.result = null;
    res.json({ connected:true, email, folders });
  } catch (error) { session.credentials = null; res.status(401).json({ error:safeError(error) }); }
  finally { if (client?.usable) await client.logout().catch(()=>{}); }
});

app.get('/api/status', (req,res) => { const session = getSession(req,res); res.json({ connected:Boolean(session.credentials), email:session.credentials?.email || null, folders:session.folders || [], hasResult:Boolean(session.result) }); });
app.post('/api/logout', (req,res) => { const session = getSession(req,res,false); if (session) sessions.delete(session.id); res.setHeader('Set-Cookie','cmh9_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); res.json({ok:true}); });

app.post('/api/extract', async (req,res) => {
  const session = getSession(req,res); const folder = String(req.body.folder || ''); const start = Number(req.body.start); const limit = Number(req.body.limit); const mode = String(req.body.mode || '');
  if (!session.credentials) return res.status(401).json({error:'Connect to Gmail first.'});
  if (!session.folders.some(f => f.path === folder)) return res.status(400).json({error:'Select a valid Gmail folder.'});
  if (!Number.isInteger(start) || start < 1 || !Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) return res.status(400).json({error:`Start must be at least 1 and limit must be from 1 to ${MAX_LIMIT}.`});
  if (!MODES.includes(mode)) return res.status(400).json({error:'Select a valid download mode.'});
  const options = req.body.options || {}; let client; let lock;
  try {
    client = createClient(session); await client.connect(); lock = await client.getMailboxLock(folder);
    const total = client.mailbox.exists || 0;
    if (start > total) return res.status(400).json({error:`Start position exceeds the ${total} messages in this folder.`});
    const end = Math.min(total, start + limit - 1); const items = [];
    for await (const message of client.fetch(`${start}:${end}`, { source:true, envelope:true, uid:true })) {
      const extracted = await extractEmail(message.source, mode, options);
      const subject = message.envelope?.subject || `email-${message.uid}`;
      items.push({ uid:message.uid, subject, filename:`${String(items.length + 1).padStart(3,'0')}-${sanitizeFilename(subject)}.${extracted.extension}`, content:extracted.content, contentType:extracted.contentType });
    }
    const separator = '\r\n\r\n' + '='.repeat(72) + '\r\n\r\n';
    const display = items.map(i => i.content.toString('utf8')).join(separator);
    const bytes = items.reduce((sum,i)=>sum+i.content.length,0);
    session.result = { mode, items, display, bytes, createdAt:Date.now() };
    res.json({ count:items.length, bytes, display, downloadUrl:'/api/download' });
  } catch (error) { res.status(error.status || 502).json({error:safeError(error)}); }
  finally { if (lock) lock.release(); if (client?.usable) await client.logout().catch(()=>{}); }
});

app.get('/api/download', (req,res) => {
  const session = getSession(req,res,false); const result = session?.result;
  if (!result?.items?.length) return res.status(404).json({error:'No extraction result is available.'});
  const names = {clean:'clean-headers',text:'text-only',original:'newsletter-original',headers:'headers-only',body:'body-only',received:'received-only'};
  if (result.items.length === 1) {
    const item = result.items[0]; res.setHeader('Content-Type',item.contentType); res.setHeader('Content-Disposition',`attachment; filename="${names[result.mode]}.${item.filename.split('.').pop()}"`); return res.end(item.content);
  }
  res.setHeader('Content-Type','application/zip'); res.setHeader('Content-Disposition',`attachment; filename="${names[result.mode]}.zip"`);
  const archive = archiver('zip',{zlib:{level:9}}); archive.on('error',()=>res.destroy()); archive.pipe(res); result.items.forEach(item=>archive.append(item.content,{name:item.filename})); archive.finalize();
});

app.use(express.static(path.join(__dirname,'public'), { extensions:['html'], maxAge:process.env.NODE_ENV === 'production' ? '1h' : 0 }));
app.use((req,res) => res.sendFile(path.join(__dirname,'public','index.html')));

setInterval(()=>{ const cutoff=Date.now()-SESSION_TTL; for(const [id,s] of sessions) if(s.touchedAt<cutoff) sessions.delete(id); },60_000).unref();
if (require.main === module) app.listen(PORT,()=>console.log(`Email Extraction CMH9 running on http://localhost:${PORT}`));
module.exports = app;
