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
  assert.match(html,/styles\.css\?v=5\.2/);
  assert.match(html,/app\.js\?v=5\.2/);
  assert.match(html,/v5\.2/);
});
