const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const context={URLSearchParams};vm.createContext(context);
vm.runInContext(fs.readFileSync('backend/qsuite/web/ui.js','utf8'),context);
const ui=context.QSuiteUI;
test('helper navigation contains no security/system pages',()=>{
  const pages=Array.from(ui.allowed(['minecraft.view','crafty.view','member_news.view','packages.view']),x=>x[0]);
  assert.deepEqual(pages,['dashboard','minecraft','crafty','membernews','packages','settings']);
});
test('log viewer gets only assigned log navigation',()=>{
  assert.deepEqual(Array.from(ui.allowed(['logs.minecraft.read']),x=>x[0]),['dashboard','logs','settings']);
});
test('required account setup prevents navigation into assigned admin tools',()=>{
  assert.deepEqual(Array.from(ui.allowed(['security.view','system.view'],true),x=>x[0]),['settings']);
});
test('custom roles use permission membership, not role names',()=>{
  assert.deepEqual(Array.from(ui.allowed(['member_news.view']),x=>x[0]),['dashboard','membernews','settings']);
});
test('legacy login navigation remains local and known',()=>{
  assert.equal(ui.page('/login','?next=%2Fpanel%2Fdashboard'),'dashboard');
  assert.equal(ui.page('/login','?next=https%3A%2F%2Fevil.example%2Fpanel%2Fsecurity'),'dashboard');
  assert.equal(ui.page('/panel/users'),'users');
  assert.equal(ui.page('/panel/unknown'),'dashboard');
});
test('reduced motion removes all animation and transition and mobile keeps safe dialogs',()=>{
  const css=fs.readFileSync('backend/qsuite/web/style.css','utf8');
  assert.match(css,/@media\(prefers-reduced-motion:reduce\).*animation:none!important;transition:none!important/s);
  assert.match(css,/max-height:calc\(100dvh - 36px\)/);
  assert.match(css,/\.table-wrap\{[^}]*overflow:auto/);
});
