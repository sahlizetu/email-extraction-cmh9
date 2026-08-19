'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {extractEmail}=require('../lib/email-engine');
const forbidden=['Delivered-To','ARC-Seal','ARC-Message-Signature','ARC-Authentication-Results','Return-Path','Authentication-Results','DKIM-Signature'];
const raw=`Delivered-To: inbox@gmail.com\r\nARC-Seal: remove\r\nARC-Message-Signature: remove\r\nARC-Authentication-Results: remove\r\nReturn-Path: <bounce@example.com>\r\nAuthentication-Results: pass\r\nDKIM-Signature: remove\r\nReceived: by mx.google.com\r\nDate: Wed, 19 Aug 2026 10:00:00 +0000\r\nFrom: Brand <mail@example.com>\r\nTo: inbox@gmail.com\r\nMessage-ID: <id@example.com>\r\nSubject: Test\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBODY`;
const cleanOptions={replaceDate:true,replaceTo:true,keepReceived:true,keepReplyTo:true,autoAddCc:true,addSender:true,fromId:true,subjectId:true,domainReplacement:'[RP]',messageIdTag:'[EID]'};
const headersOptions={headerFromName:'[P_FRNAME]',headerLanguageCode:'[6LAN]',headerReturnPath:'[P_RPATH]',headerSubject:'[S]',headerBoundary:'[BND]',headersAddSender:false};
function assertForbiddenAbsent(value){for(const name of forbidden)assert.doesNotMatch(value,new RegExp(`^${name}:`,'mi'))}
test('Newsletter Original alone preserves transport authentication headers',async()=>{const result=await extractEmail(Buffer.from(raw),'original',{});for(const name of forbidden)assert.match(result.content.toString(),new RegExp(`^${name}:`,'mi'))});
test('Clean Headers removes all transport authentication headers',async()=>{const result=await extractEmail(Buffer.from(raw),'clean',cleanOptions);assertForbiddenAbsent(result.content.toString().split('\r\n\r\n')[0])});
test('Headers Only removes all transport authentication headers',async()=>{const result=await extractEmail(Buffer.from(raw),'headers',headersOptions);assertForbiddenAbsent(result.content.toString())});
test('Body and Received modes cannot expose removed outer headers',async()=>{const body=await extractEmail(Buffer.from(raw),'body',{});const received=await extractEmail(Buffer.from(raw),'received',{});assertForbiddenAbsent(body.content.toString());assert.equal(received.content.toString(),'Received: by mx.google.com')});
