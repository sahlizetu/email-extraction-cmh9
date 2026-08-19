'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.join(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','index.html'),'utf8');
const app=fs.readFileSync(path.join(root,'public','app.js'),'utf8');
test('progress bar selector matches the rendered UI',()=>{
  assert.match(html,/class="progress-rail"/);
  assert.match(app,/querySelector\('\.progress-rail'\)/);
  assert.doesNotMatch(app,/querySelector\('\.progress-track'\)/);
});
test('browser assets use the current cache version',()=>{
  assert.match(html,/styles\.css\?v=5\.6/);
  assert.match(html,/app\.js\?v=5\.6/);
  assert.match(html,/v5\.6/);
});
test('Headers Only controls are present and Sender starts unchecked',()=>{
  for(const id of ['headerFromName','headerLanguageCode','headerReturnPath','headerSubject','headerBoundary','headersAddSender']) assert.match(html,new RegExp(`id="${id}"`));
  assert.match(html,/id="headersAddSender" type="checkbox">/);
  assert.doesNotMatch(html,/id="headersAddSender"[^>]*checked/);
});
test('Clean Headers defaults and mode locking are configured',()=>{
  const match=app.match(/const cleanDefaults=new Set\(\[([^\]]+)\]\)/);
  assert.ok(match);
  const defaults=[...match[1].matchAll(/'([^']+)'/g)].map(value=>value[1]);
  assert.deepEqual(defaults,['replaceDate','replaceTo','keepReceived','autoAddCc','keepReplyTo']);
  assert.match(app,/function setModeLock\(value\)/);
  assert.match(app,/setModeLock\(true\);setBusy\(true,'Extraction in progress…'\)/);
});
