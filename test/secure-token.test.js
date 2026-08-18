'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const{sealCredentials,openCredentials}=require('../lib/secure-token');
const secret='test-secret-that-is-at-least-thirty-two-characters-long';
test('persistent credential token round trip',()=>{const token=sealCredentials({email:'user@gmail.com',password:'app-password-1234'},secret);assert.deepEqual(openCredentials(token,secret),{email:'user@gmail.com',password:'app-password-1234'});assert.doesNotMatch(token,/user@gmail|app-password/)});
test('tampered credential token is rejected',()=>{const token=sealCredentials({email:'user@gmail.com',password:'secret-password'},secret);assert.equal(openCredentials(token.slice(0,-2)+'xx',secret),null)});
test('short session secret is rejected',()=>assert.throws(()=>sealCredentials({email:'a',password:'b'},'short'),/at least 32/));
