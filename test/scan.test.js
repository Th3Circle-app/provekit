'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { scanText } = require('../src/scan');

const ids = (findings) => findings.map(f => f.id);

test('catches leaked secrets', () => {
  const f = scanText("const k = 'AKIAIOSFODNN7EXAMPLE';\nconst s = 'sk_live_" + "51H8xxxxxxxxxxxxxxxxxxxxx';", 'x.js');
  assert.ok(ids(f).includes('aws-access-key'));
  assert.ok(ids(f).includes('stripe-live-key'));
});

test('catches SSRF from user input', () => {
  const f = scanText('const r = await fetch(req.query.url);', 'x.js');
  assert.ok(ids(f).includes('ssrf-user-url'));
});

test('catches command injection and sql concat', () => {
  const f = scanText('exec(`ping ${req.query.host}`);\ndb.query("SELECT * FROM u WHERE n = \'" + name + "\'");', 'x.js');
  assert.ok(ids(f).includes('child-process-interp'));
  assert.ok(ids(f).includes('sql-string-concat'));
});

test('does NOT flag guarded / parameterized code (no false positives)', () => {
  const clean = [
    "const k = process.env.API_KEY;",
    "await assertPublicUrl(url); return fetch(url);",
    "db.query('SELECT * FROM u WHERE n = $1', [name]);",
    "const t = crypto.randomBytes(32).toString('hex');",
  ].join('\n');
  assert.strictEqual(scanText(clean, 'x.js').length, 0);
});

test('honors provekit-ignore', () => {
  const f = scanText("const k = 'AKIAIOSFODNN7EXAMPLE'; // provekit-ignore", 'x.js');
  assert.strictEqual(f.length, 0);
});
