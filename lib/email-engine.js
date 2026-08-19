'use strict';

const MODES = Object.freeze(['clean','text','original','headers','body','received']);
const ADDRESS_HEADERS = new Set(['from','to','cc','bcc','reply-to','sender','resent-from','resent-to','resent-cc','return-path']);
// These transport/authentication headers are preserved only by Newsletter Original.
const NON_ORIGINAL_DROP_HEADERS = new Set(['delivered-to','x-received','return-path','received-spf','authentication-results','dkim-signature','x-google-dkim-signature','x-gm-message-state','x-google-smtp-source']);
function isRemovedOutsideOriginal(name) { return NON_ORIGINAL_DROP_HEADERS.has(name) || name.startsWith('arc-'); }
function isNoisyHeadersOnlyHeader(name) { return isRemovedOutsideOriginal(name); }

function splitRawMessage(rawInput) {
  const raw = Buffer.isBuffer(rawInput) ? rawInput : Buffer.from(String(rawInput));
  const text = raw.toString('binary');
  const match = /\r?\n\r?\n/.exec(text);
  if (!match) return { headerBuffer: raw, bodyBuffer: Buffer.alloc(0), separator: Buffer.from('\r\n\r\n') };
  const index = match.index;
  return {
    headerBuffer: raw.subarray(0, index),
    bodyBuffer: raw.subarray(index + match[0].length),
    separator: Buffer.from(match[0], 'binary')
  };
}

function parseHeaders(headerInput) {
  const source = Buffer.isBuffer(headerInput) ? headerInput.toString('binary') : String(headerInput);
  const lines = source.split(/\r?\n/);
  const headers = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1].rawLines.push(line);
      headers[headers.length - 1].value += `\r\n${line}`;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon < 1) {
      if (headers.length) {
        headers[headers.length - 1].rawLines.push(line);
        headers[headers.length - 1].value += `\r\n${line}`;
      }
      continue;
    }
    headers.push({ name: line.slice(0, colon), lowerName: line.slice(0, colon).toLowerCase(), value: line.slice(colon + 1), rawLines: [line] });
  }
  return headers;
}

function unfold(value) { return value.replace(/\r?\n[ \t]+/g, ' '); }
function line(name, value, noSpace = false) { return `${name}:${noSpace ? '' : ' '}${String(value).trimStart()}`; }

function replaceAddressDomains(value, replacement) {
  if (!replacement) return value;
  // Operates on header values only. It handles addr-specs inside or outside angle brackets.
  return value.replace(/([A-Z0-9.!#$%&'*+/=?^_`{|}~-]+)@([A-Z0-9.-]+\.[A-Z]{2,}|[A-Z0-9.-]+)/gi, (_, local) => `${local}@${replacement}`);
}

function tagMessageId(value, tag) {
  if (!tag) return value;
  return value.replace(/(<)?([^<>\s@]+)@([^<>\s]+)(>)?/g, (_, open, local, domain, close) => `${open || '<'}${local}${tag}@${domain}${close || '>'}`);
}

function transformHeaders(rawHeaders, options = {}) {
  const cfg = {
    domainReplacement: options.domainReplacement ?? '[RP]',
    messageIdTag: options.messageIdTag ?? '[EID]',
    replaceDate: Boolean(options.replaceDate), replaceTo: Boolean(options.replaceTo),
    keepReceived: Boolean(options.keepReceived), modernReceivedFormat: Boolean(options.modernReceivedFormat), keepReplyTo: Boolean(options.keepReplyTo),
    autoAddCc: Boolean(options.autoAddCc), addSender: Boolean(options.addSender),
    fromId: Boolean(options.fromId), subjectId: Boolean(options.subjectId),
    cleanTransportHeaders: Boolean(options.cleanTransportHeaders)
  };
  const headers = Array.isArray(rawHeaders) ? rawHeaders : parseHeaders(rawHeaders);
  const output = [];
  const hasCc = headers.some(header => header.lowerName === 'cc');
  const hasSender = headers.some(header => header.lowerName === 'sender');
  let senderAdded = hasSender;
  let ccAdded = false;

  const addSenderAfterFrom = () => {
    if (cfg.addSender && !senderAdded) { output.push('Sender: noreply@[RDNS]'); senderAdded = true; }
  };
  const addCcAfterTo = () => {
    if (cfg.autoAddCc && !hasCc && !ccAdded) { output.push('Cc: [*to]'); ccAdded = true; }
  };

  for (const header of headers) {
    const name = header.name;
    const lower = header.lowerName;
    let value = unfold(header.value).trimStart();
    if (cfg.cleanTransportHeaders && isRemovedOutsideOriginal(lower)) continue;
    if (lower === 'received' && !cfg.keepReceived) continue;
    if (lower === 'received' && !cfg.modernReceivedFormat) {
      output.push(header.rawLines.join('\r\n'));
      continue;
    }
    if (lower === 'reply-to' && !cfg.keepReplyTo) continue;
    if (lower === 'date' && cfg.replaceDate) value = '[DATE]';
    if (lower === 'to' && cfg.replaceTo) value = '[*to]';
    else if (ADDRESS_HEADERS.has(lower)) value = replaceAddressDomains(value, cfg.domainReplacement);
    if (lower === 'message-id') value = tagMessageId(value, cfg.messageIdTag);

    if (lower === 'from' && cfg.fromId) output.push(line(name, `[ID] ${value}`, true));
    else if (lower === 'subject' && cfg.subjectId) output.push(line(name, `[ID] ${value}`, true));
    else output.push(line(name, value));

    if (lower === 'from') addSenderAfterFrom();
    if (lower === 'to') addCcAfterTo();
  }
  if (!senderAdded && cfg.addSender) output.push('Sender: noreply@[RDNS]');
  if (!ccAdded && cfg.autoAddCc && !hasCc) output.push('Cc: [*to]');
  return output.join('\r\n');
}

function safeHeaderToken(value, fallback) {
  const cleaned = String(value ?? '').replace(/[\r\n]/g, '').trim();
  return cleaned || fallback;
}

function transformHeadersOnly(rawHeaders, options = {}) {
  const cfg = {
    fromName: safeHeaderToken(options.headerFromName, '[P_FRNAME]'),
    languageCode: safeHeaderToken(options.headerLanguageCode, '[6LAN]'),
    returnPath: safeHeaderToken(options.headerReturnPath, '[P_RPATH]'),
    subjectValue: safeHeaderToken(options.headerSubject, '[S]'),
    boundary: safeHeaderToken(options.headerBoundary, '[BND]'),
    addSender: Boolean(options.headersAddSender)
  };
  const headers = Array.isArray(rawHeaders) ? rawHeaders : parseHeaders(rawHeaders);
  const output = [];
  const hasCc = headers.some(header => header.lowerName === 'cc');
  let senderAdded = false;
  let ccAdded = false;

  for (const header of headers) {
    const lower = header.lowerName;
    if (isNoisyHeadersOnlyHeader(lower) || lower === 'sender') continue;

    if (lower === 'content-type') {
      output.push(`Content-Type: multipart/related;boundary="${cfg.boundary}";type="multipart/alternative"`);
      continue;
    }
    if (lower === 'date') {
      output.push('Date: [DATE]');
      continue;
    }
    if (lower === 'from') {
      output.push(`From: ${cfg.fromName} <noreply.${cfg.languageCode}@${cfg.returnPath}>`);
      if (cfg.addSender) {
        output.push(`Sender: noreply.${cfg.languageCode}@${cfg.returnPath}`);
        senderAdded = true;
      }
      continue;
    }
    if (lower === 'message-id') {
      output.push(line(header.name, tagMessageId(unfold(header.value).trimStart(), '[EID]')));
      continue;
    }
    if (lower === 'subject') {
      output.push(`Subject: ${cfg.subjectValue}`);
      output.push(...header.rawLines.slice(1));
      continue;
    }
    if (lower === 'to') {
      output.push('To: <[*to]>');
      if (!hasCc) { output.push('Cc: [*to]'); ccAdded = true; }
      continue;
    }
    if (lower === 'cc') {
      output.push('Cc: [*to]');
      ccAdded = true;
      continue;
    }
    output.push(header.rawLines.join('\r\n'));
  }

  if (cfg.addSender && !senderAdded) output.push(`Sender: noreply.${cfg.languageCode}@${cfg.returnPath}`);
  if (!hasCc && !ccAdded) output.push('Cc: [*to]');
  return output.join('\r\n');
}

function extractReceived(rawHeaders) {
  return parseHeaders(rawHeaders).filter(h => h.lowerName === 'received').map(h => h.rawLines.join('\r\n')).join('\r\n');
}

function sanitizeFilename(value, fallback = 'email') {
  const safe = String(value || fallback).normalize('NFKD').replace(/[^a-z0-9._-]+/gi, '-').replace(/^-+|-+$/g, '').slice(0, 72);
  return safe || fallback;
}

async function extractEmail(rawInput, mode, options = {}) {
  if (!MODES.includes(mode)) throw new Error('Unsupported download mode');
  const raw = Buffer.isBuffer(rawInput) ? rawInput : Buffer.from(rawInput);
  const { headerBuffer, bodyBuffer, separator } = splitRawMessage(raw);
  const rawHeaderText = headerBuffer.toString('binary');
  let content; let extension = 'txt'; let contentType = 'text/plain; charset=utf-8';

  if (mode === 'original') { content = raw; extension = 'eml'; contentType = 'message/rfc822'; }
  else if (mode === 'received') content = Buffer.from(extractReceived(rawHeaderText));
  else if (mode === 'headers') content = Buffer.from(transformHeadersOnly(rawHeaderText, options));
  else if (mode === 'clean') content = Buffer.concat([Buffer.from(transformHeaders(rawHeaderText, { ...options, cleanTransportHeaders: true })), separator, bodyBuffer]);
  else if (mode === 'body') {
    content = bodyBuffer;
    const header = rawHeaderText.toLowerCase();
    if (header.includes('content-type: text/html')) { extension = 'html'; contentType = 'text/html; charset=utf-8'; }
  } else {
    const { simpleParser } = require('mailparser');
    const parsed = await simpleParser(raw, { skipImageLinks: true, skipHtmlToText: false });
    const text = parsed.text || (typeof parsed.html === 'string' ? parsed.html.replace(/<style[\s\S]*?<\/style>/gi,'').replace(/<script[\s\S]*?<\/script>/gi,'').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim() : '');
    content = Buffer.from(text, 'utf8');
  }
  return { content, extension, contentType };
}

module.exports = { MODES, splitRawMessage, parseHeaders, replaceAddressDomains, tagMessageId, transformHeaders, transformHeadersOnly, extractReceived, extractEmail, sanitizeFilename };
