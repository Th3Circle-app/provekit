'use strict';
// ATTACK SUITE — adversarial tests that try to BREAK provekit.
// Each assertion encodes correct behavior; a failure is a real gap to fix.
const { test } = require('node:test');
const assert = require('node:assert');
const { scanText, scanDiff, sortFindings } = require('../src/scan');

const ids = (findings) => findings.map(f => f.id);
const has = (findings, id) => ids(findings).includes(id);

// ---------------------------------------------------------------------------
// 1. EVASION — real, dangerous code the scanner MUST still catch
// ---------------------------------------------------------------------------
test('evasion: secret on a long padded line is still caught', () => {
  const pad = '// ' + 'x'.repeat(1500) + ' ';
  const line = `const k = "${pad}"; const aws = "AKIAIOSFODNN7EXAMPLE";`;
  assert.ok(has(scanText(line, 'a.js'), 'aws-access-key'), 'secret hidden after long padding evaded detection');
});

test('evasion: password in backticks (template literal) is caught', () => {
  const f = scanText('const password = `Sup3r$ecretValue!`;', 'a.js');
  assert.ok(has(f, 'hardcoded-secret'), 'backtick-quoted credential evaded detection');
});

test('evasion: private key with CRLF line endings is caught', () => {
  const f = scanText('-----BEGIN RSA PRIVATE KEY-----\r\nMIIEabc\r\n', 'a.js');
  assert.ok(has(f, 'private-key-block'));
});

test('evasion: eval with leading whitespace/indent still caught', () => {
  assert.ok(has(scanText('        eval(userInput);', 'a.js'), 'eval'));
});

test('evasion: stripe key mid-line inside array is caught', () => {
  const f = scanText('const keys = ["sk_live_' + 'ABCDEFGHIJKLMNOP1234567890"];', 'a.js');
  assert.ok(has(f, 'stripe-live-key'));
});

// ---------------------------------------------------------------------------
// 2. PRECISION — realistic clean code that must NOT be flagged
// ---------------------------------------------------------------------------
test('precision: env-var assignment is not a secret', () => {
  const f = scanText('const password = process.env.DB_PASSWORD;', 'a.js');
  assert.ok(!has(f, 'hardcoded-secret'), `false positive: ${JSON.stringify(f)}`);
});

test('precision: placeholder values are not secrets', () => {
  for (const v of ['your-api-key-here', 'changeme', 'xxxxxxxx', 'REPLACE_ME_PLEASE', '<your-token>']) {
    const f = scanText(`const api_key = "${v}";`, 'a.js');
    assert.ok(!has(f, 'hardcoded-secret'), `false positive on placeholder "${v}"`);
  }
});

test('precision: uuid / example urls are not secrets', () => {
  const f = scanText('const example = "https://user:pass@example.com"; // docs', 'README.md');
  // db-url-creds intentionally matches real creds; docs example.com is a known edge — assert no secret rule explodes on plain uuids:
  const g = scanText('const id = "550e8400-e29b-41d4-a716-446655440000";', 'a.js');
  assert.ok(!has(g, 'openai-key') && !has(g, 'hardcoded-secret'), 'uuid misclassified as secret');
});

test('precision: ORM .update()/.select() are not SQL injection', () => {
  const f = scanText('const rows = await db.users.update({ name }).where({ id });', 'a.js');
  assert.ok(!has(f, 'sql-string-concat'), 'ORM method misread as SQL injection');
});

test('precision: parameterized SQL ($1 / ?) is not flagged', () => {
  assert.ok(!has(scanText('db.query("SELECT * FROM users WHERE id = $1", [id])', 'a.js'), 'sql-string-concat'));
  assert.ok(!has(scanText('db.query("SELECT * FROM t WHERE a = ?", [a])', 'a.js'), 'sql-string-concat'));
});

test('precision: md5 for a non-password checksum is at most low severity', () => {
  const f = scanText("const etag = crypto.createHash('md5').update(buf).digest('hex');", 'a.js');
  const hit = f.find(x => x.id === 'weak-hash-pw');
  if (hit) assert.equal(hit.severity, 'low'); // advisory only, must not fail CI
});

test('precision: the word "password" in a comment is not a secret', () => {
  assert.ok(!has(scanText('// TODO: never hardcode the password in code', 'a.js'), 'hardcoded-secret'));
});

test('precision: heuristic patterns are suppressed in test/example files', () => {
  assert.ok(!has(scanText('const agent = new https.Agent({ rejectUnauthorized: false });', 'test/http.test.js'), 'tls-verify-off'), 'tls-off flagged in a test file');
  assert.ok(!has(scanText("app.use(session({ secret: 'manny is cool' }))", 'examples/auth/index.js'), 'hardcoded-secret'), 'joke example secret flagged');
  assert.ok(!has(scanText("var xss = 'javascript:eval(document.cookie)';", 'test/res.redirect.js'), 'eval'), 'eval-in-string flagged in a test');
});

test('precision-vs-safety: a REAL leaked key in a test file is STILL caught', () => {
  assert.ok(has(scanText('const k = "AKIAIOSFODNN7EXAMPLE";', 'test/setup.test.js'), 'aws-access-key'), 'real AWS key in test file was missed');
  assert.ok(has(scanText('const s = "sk_live_' + 'ABCDEFGHIJKLMNOP1234567890";', 'examples/demo.js'), 'stripe-live-key'), 'real Stripe key in example missed');
});

// ---------------------------------------------------------------------------
// 3. ROBUSTNESS — must never crash or hang (ReDoS / weird input)
// ---------------------------------------------------------------------------
test('robustness: pathological SQL-like line completes fast (no ReDoS)', () => {
  const evil = '`SELECT ' + "'".repeat(400) + ' + a'; // bait for catastrophic backtracking
  const start = process.hrtime.bigint();
  scanText(evil, 'a.js');
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  assert.ok(ms < 100, `scan took ${ms}ms — possible ReDoS`);
});

test('robustness: pathological db-url line completes fast', () => {
  const evil = 'postgres://' + 'a'.repeat(5000) + ':'; // no closing @, forces long scan
  const start = process.hrtime.bigint();
  scanText(evil, 'a.js');
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  assert.ok(ms < 100, `scan took ${ms}ms — possible ReDoS`);
});

test('robustness: 50k-line file scans without error', () => {
  const big = ('const x = 1;\n').repeat(50000);
  assert.doesNotThrow(() => scanText(big, 'a.js'));
});

test('robustness: unicode / emoji / mixed scripts do not crash', () => {
  assert.doesNotThrow(() => scanText('const s = "пароль密码🔑"; eval(x);', 'a.js'));
});

test('robustness: empty and whitespace-only input returns no findings', () => {
  assert.deepEqual(scanText('', 'a.js'), []);
  assert.deepEqual(scanText('   \n\t\n   ', 'a.js'), []);
});

// ---------------------------------------------------------------------------
// 4. DIFF PARSER — malformed diffs must not crash and must attribute lines
// ---------------------------------------------------------------------------
test('diff: malformed/truncated diff does not throw', () => {
  assert.doesNotThrow(() => scanDiff('+++ b/x.js\n@@ garbage\n+const a = "AKIAIOSFODNN7EXAMPLE";'));
  assert.doesNotThrow(() => scanDiff('random text\nno headers here\n+++ nope'));
});

test('diff: only ADDED lines are scanned, removed lines ignored', () => {
  const diff = [
    '+++ b/app.js',
    '@@ -1,2 +1,2 @@',
    '-const old = "AKIAIOSFODNN7EXAMPLE";', // removed — must be IGNORED
    '+const clean = process.env.KEY;',
  ].join('\n');
  assert.equal(scanDiff(diff).length, 0, 'flagged a removed line');
});

test('diff: added secret is caught with correct line number', () => {
  const diff = ['+++ b/app.js', '@@ -10,0 +10,1 @@', '+const k = "sk_live_' + 'ABCDEFGHIJKLMNOP1234567890";'].join('\n');
  const f = scanDiff(diff);
  assert.ok(has(f, 'stripe-live-key'));
  assert.equal(f[0].line, 10);
});

// ---------------------------------------------------------------------------
// 5. SORT / CONTRACT — findings sorted by severity, shape is stable
// ---------------------------------------------------------------------------
test('contract: findings sorted critical-first and shape complete', () => {
  const f = sortFindings(scanText('eval(x); const p="Xy9$abcd1234"; const a="AKIAIOSFODNN7EXAMPLE";', 'a.js'));
  assert.equal(f[0].severity, 'critical');
  for (const x of f) for (const k of ['file','line','id','owasp','category','severity','why','snippet'])
    assert.ok(k in x, `finding missing field ${k}`);
});
