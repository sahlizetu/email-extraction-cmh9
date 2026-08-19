'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {verifyTelegramLogin,createTelegramSessionToken,openTelegramSessionToken,isApprovedMember}=require('../lib/telegram-auth');
const botToken='123456:TEST_BOT_TOKEN';
function signedLogin(){const input={id:'12345',first_name:'Zakariae',username:'cmh9_user',auth_date:String(Math.floor(Date.now()/1000))};const check=Object.keys(input).sort().map(key=>`${key}=${input[key]}`).join('\n');const secret=crypto.createHash('sha256').update(botToken).digest();input.hash=crypto.createHmac('sha256',secret).update(check).digest('hex');return input}
test('verifies an authentic Telegram login payload',()=>{const user=verifyTelegramLogin(signedLogin(),botToken);assert.equal(user.id,'12345');assert.equal(user.username,'cmh9_user')});
test('rejects tampered Telegram login data',()=>{const input=signedLogin();input.id='999';assert.throws(()=>verifyTelegramLogin(input,botToken),/verification failed/)});
test('Telegram session token round trip and tamper rejection',()=>{const secret='a'.repeat(64);const token=createTelegramSessionToken({id:'123',first_name:'User'},secret,3600);assert.equal(openTelegramSessionToken(token,secret).id,'123');assert.equal(openTelegramSessionToken(`${token}x`,secret),null)});
test('recognizes approved Telegram membership states',()=>{for(const status of ['creator','administrator','member'])assert.equal(isApprovedMember({status}),true);assert.equal(isApprovedMember({status:'restricted',is_member:true}),true);for(const status of ['left','kicked'])assert.equal(isApprovedMember({status}),false)});
