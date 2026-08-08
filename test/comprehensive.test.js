'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { scanText, scanDiff, sortFindings } = require('../src/scan');

const ids = (f) => f.map(x => x.id);
const has = (text, id) => ids(scanText(text, 'x.js')).includes(id);
const clean = (text) => assert.strictEqual(scanText(text, 'x.js').length, 0, `expected 0 findings for: ${text}`);

// ---------- SECRETS: each rule fires on a true positive ----------
test('secret: aws access key', () => assert.ok(has("x = 'AKIAIOSFODNN7EXAMPLE'", 'aws-access-key')));
test('secret: aws secret key', () => assert.ok(has("aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'", 'aws-secret-key')));
test('secret: private key block', () => assert.ok(has('-----BEGIN RSA PRIVATE KEY-----', 'private-key-block')));
test('secret: github token', () => assert.ok(has('ghp_1234567890abcdefghijklmnopqrstuvwxyz', 'github-token')));
test('secret: stripe live', () => assert.ok(has("sk_live_" + "51H8xAbCdEfGhIjKlMnOpQrSt", 'stripe-live-key')));
test('secret: openai', () => assert.ok(has("key='sk-abcdef1234567890ABCDEFGHIJ'", 'openai-key')));
test('secret: anthropic', () => assert.ok(has("k='sk-ant-api03-abcdefghij1234567890'", 'anthropic-key')));
test('secret: slack', () => assert.ok(has('xoxb-123456789012-abcdefghijkl', 'slack-token')));
test('secret: google api', () => assert.ok(has('AIzaSyA1234567890abcdefghijklmnopqrstuv', 'google-api-key')));
test('secret: db url creds', () => assert.ok(has("url='postgres://admin:hunter2@db:5432/prod'", 'db-url-creds')));
test('secret: hardcoded password', () => assert.ok(has("const password = 'super-secret-value'", 'hardcoded-secret')));

// ---------- SECRETS: negatives (must NOT fire) ----------
test('safe: env var, not literal', () => clean("const key = process.env.API_KEY;"));
test('safe: db url from env', () => clean("const url = process.env.DATABASE_URL;"));
test('safe: password field name only', () => clean("const passwordField = getField('password');"));
test('safe: type annotation', () => clean("interface Cfg { password: string; apiKey: string }"));
test('safe: short value below threshold', () => clean("const secret = 'abc';"));

// ---------- PATTERNS: positives ----------
test('vuln: ssrf from user input', () => assert.ok(has('await fetch(req.query.url)', 'ssrf-user-url')));
test('vuln: ssrf axios body', () => assert.ok(has('axios.get(request.body.endpoint)', 'ssrf-user-url')));
test('vuln: eval', () => assert.ok(has('eval(userInput)', 'eval')));
test('vuln: new Function', () => assert.ok(has('const f = new Function("return 1")', 'new-function')));
test('vuln: command injection', () => assert.ok(has('exec(`ls ${dir}`)', 'child-process-interp')));
test('vuln: sql concat', () => assert.ok(has('db.query("SELECT * FROM u WHERE n=\'" + n + "\'")', 'sql-string-concat')));
test('vuln: sql template', () => assert.ok(has('db.query(`SELECT * FROM u WHERE id=${id}`)', 'sql-string-concat')));
test('vuln: tls off', () => assert.ok(has('const a = { rejectUnauthorized: false }', 'tls-verify-off')));
test('vuln: innerHTML', () => assert.ok(has('el.innerHTML = userData', 'dangerous-html')));
test('vuln: weak hash', () => assert.ok(has("crypto.createHash('md5')", 'weak-hash-pw')));
test('vuln: insecure random token', () => assert.ok(has("const token = 'x' + Math.random()", 'insecure-random-token')));
test('vuln: cors wildcard', () => assert.ok(has("'Access-Control-Allow-Origin': '*'", 'cors-wildcard')));

// ---------- PATTERNS: negatives (the credibility cases) ----------
test('safe: fetch of local var (guarded elsewhere)', () => clean('return fetch(url);'));
test('safe: fetch of literal', () => clean("fetch('https://api.example.com/v1')"));
test('safe: parameterized sql', () => clean("db.query('SELECT * FROM u WHERE n=$1', [name])"));
test('safe: parameterized sql ?', () => clean("db.query('SELECT * FROM u WHERE n = ?', [name])"));
test('safe: secure random', () => clean("const token = crypto.randomBytes(32).toString('hex')"));
test('safe: tls on', () => clean('const a = { rejectUnauthorized: true }'));
test('safe: exec no interpolation', () => clean('exec("ls -la", cb)'));
test('safe: textContent not innerHTML', () => clean('el.textContent = userData'));
test('safe: sha256', () => clean("crypto.createHash('sha256')"));

// ---------- EDGE CASES: must not crash / must behave ----------
test('edge: empty string', () => clean(''));
test('edge: whitespace only', () => clean('   \n\t\n   '));
test('edge: secret on a long line is still caught (no evasion); only pathological >20k lines are skipped', () => {
  const f = scanText('x'.repeat(2000) + " 'AKIAIOSFODNN7EXAMPLE'", 'x.js');
  assert.ok(f.some(x => x.id === 'aws-access-key'), 'long-line secret evaded detection');
  clean('x'.repeat(20001) + " 'AKIAIOSFODNN7EXAMPLE'"); // >20k chars = skipped as pathological (DoS guard)
});
test('edge: unicode does not crash', () => { assert.doesNotThrow(() => scanText('const 变量 = "日本語テスト 🔒";\nconst emoji = "🚀🔥";', 'x.js')); });
test('edge: ignore comment suppresses', () => clean("x = 'AKIAIOSFODNN7EXAMPLE' // provekit-ignore"));
test('edge: multiple findings one line', () => {
  const f = scanText("const k='AKIAIOSFODNN7EXAMPLE'; eval(x)", 'x.js');
  assert.ok(f.length >= 2);
});
test('edge: 100k lines does not hang', () => {
  const big = ("const x = 1;\n").repeat(100000) + "const k='AKIAIOSFODNN7EXAMPLE';";
  const f = scanText(big, 'x.js');
  assert.ok(ids(f).includes('aws-access-key'));
});

// ---------- DIFF PARSER ----------
test('diff: correct line number on added line', () => {
  const diff = [
    'diff --git a/app.js b/app.js',
    '--- a/app.js',
    '+++ b/app.js',
    '@@ -10,0 +11,2 @@',
    "+const k = 'AKIAIOSFODNN7EXAMPLE';",
    '+const ok = 1;',
  ].join('\n');
  const f = scanDiff(diff);
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].line, 11);
  assert.strictEqual(f[0].file, 'app.js');
});
test('diff: ignores removed lines', () => {
  const diff = ['+++ b/x.js', '@@ -1 +1 @@', "-const k = 'AKIAIOSFODNN7EXAMPLE';", '+const k = process.env.K;'].join('\n');
  assert.strictEqual(scanDiff(diff).length, 0);
});
test('diff: multiple files attributed correctly', () => {
  const diff = [
    '+++ b/a.js', '@@ -0,0 +1 @@', "+eval(x)",
    '+++ b/b.js', '@@ -0,0 +5 @@', "+db.query(`SELECT ${x}`)",
  ].join('\n');
  const f = scanDiff(diff);
  assert.deepStrictEqual(f.map(x => x.file).sort(), ['a.js', 'b.js']);
});
test('diff: skips node_modules paths', () => {
  const diff = ['+++ b/node_modules/pkg/index.js', '@@ -0,0 +1 @@', "+const k='AKIAIOSFODNN7EXAMPLE';"].join('\n');
  assert.strictEqual(scanDiff(diff).length, 0);
});

// ---------- SORT ----------
test('sort: critical before high before medium', () => {
  const f = sortFindings(scanText("const p='longenoughvalue'; const k='AKIAIOSFODNN7EXAMPLE'; el.innerHTML=x", 'x.js'));
  const sevs = f.map(x => x.severity);
  const rank = { critical: 3, high: 2, medium: 1, low: 0 };
  for (let i = 1; i < sevs.length; i++) assert.ok(rank[sevs[i-1]] >= rank[sevs[i]]);
});

// ---------- REGRESSIONS from real-world stress testing ----------
test('regression: bcrypt hash is NOT a leaked secret', () => clean('password: "$2a$12$1XdLGt8wKPV4YOsrpCHZX.abcdefghijklmnopqrstuv"'));
test('regression: "-hash" label value is not a secret', () => clean("const p = { password: 'stored-password-hash' };"));
test('regression: all-zeros placeholder is not a secret', () => clean("api_key: '00000000000000000000000000000000'"));
test('regression: generic secret skipped in test files', () => {
  assert.strictEqual(scanText("const password = 'Sup3r-Real-Looking!'", 'src/tests/auth.test.js').length, 0);
});
test('regression: real-looking secret in SOURCE file still flagged', () => {
  assert.ok(scanText("const password = 'Sup3r-Real-Looking!'", 'src/auth.js').some(f => f.id === 'hardcoded-secret'));
});
test('regression: .update() method call is not SQL injection', () => clean("await user.update(`${prefix}:${apiKey}`)"));
test('regression: escaped SQL interpolation is not flagged', () => clean("db.query(`SELECT id FROM u WHERE x = ${db.escape(v)}`)"));
test('regression: named-param SQL is not flagged', () => clean("db.query(`UPDATE t SET a=:val WHERE id=:id`)"));
