'use strict';

// A rule matches via `re` (a regex) OR `test(line)` (a function, for smarter logic).
// severity: 'critical' | 'high' | 'medium' | 'low'. Medium/low are advisory (don't fail CI by default).

// ---- Secret detectors: specific formats = near-zero false positives ----
const SECRETS = [
  { id: 'aws-access-key',   severity: 'critical', why: 'AWS access key ID committed to code', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'aws-secret-key',   severity: 'critical', why: 'Possible AWS secret access key in code', re: /\baws_secret_access_key\b\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/i },
  { id: 'private-key-block', severity: 'critical', why: 'Private key block committed to code', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { id: 'github-token',     severity: 'critical', why: 'GitHub token committed to code', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { id: 'stripe-live-key',  severity: 'critical', why: 'Live Stripe secret key committed to code', re: /\bsk_live_[A-Za-z0-9]{20,}\b/ },
  { id: 'anthropic-key',    severity: 'critical', why: 'Anthropic API key committed to code', re: /\bsk-ant-[A-Za-z0-9-]{20,}\b/ },
  { id: 'openai-key',       severity: 'critical', why: 'OpenAI API key committed to code', re: /\bsk-(?!ant-)[A-Za-z0-9]{20,}\b/ },
  { id: 'slack-token',      severity: 'high',     why: 'Slack token committed to code', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'google-api-key',   severity: 'high',     why: 'Google API key committed to code', re: /\bAIza[0-9A-Za-z_\-]{35}\b/ },
  { id: 'jwt',              severity: 'medium',   why: 'Hard-coded JWT in code', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { id: 'db-url-creds',     severity: 'high',     why: 'Database URL with inline credentials', re: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:'"]+:[^\s@'"]+@/i },

  // Generic "password/secret/key = literal" — high FP surface, so use a smart test.
  { id: 'hardcoded-secret', severity: 'high', why: 'Hard-coded credential assigned a literal value',
    test(line, file) {
      if (/(?:^|\/)(?:__tests__|__mocks__|fixtures?|e2e)\/|(?:^|\/)tests?\/|\.(?:test|spec)\.[jt]sx?$/i.test(file || '')) return false; // test fixtures aren't production secrets
      const m = line.match(/\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*(['"\x60])([^'"\x60]{8,})\1/i);
      if (!m) return false;
      const val = m[2];
      if (/^\$(?:2[aby]|argon2|scrypt|pbkdf2)/i.test(val)) return false;           // it's a HASH, not plaintext
      if (/hash$|^0+$|^(.)\1{5,}$/i.test(val)) return false;                        // label like "...-hash", all zeros, all-same-char
      if (/^(?:process\.env|import\.meta|os\.environ|Deno\.env)/.test(val)) return false;
      if (/^(?:your[-_ ]|xxx+|placeholder|redacted|change[-_ ]?me|replace[-_ ]?|example|sample|test|dummy|fake|invalid|none|null|n\/a|todo|fixme|<|\.\.\.|\$\{|\{\{)/i.test(val)) return false; // placeholder
      const hasDigit = /\d/.test(val), hasUpper = /[A-Z]/.test(val), symbols = (val.match(/[^A-Za-z0-9]/g) || []).length;
      if (!(hasDigit || hasUpper || symbols >= 2)) return false;                    // pure lowercase word (e.g. a default) → skip
      return true;
    } },
].map(r => ({ owasp: 'A07 / A02', category: 'Leaked secret', ...r }));

// ---- Insecure-pattern detectors ----
const PATTERNS = [
  { id: 'ssrf-user-url', owasp: 'A10', category: 'SSRF', severity: 'high',
    why: 'User-controlled input reaches a server-side HTTP request — SSRF risk unless the host is validated against an allowlist',
    re: /\b(?:fetch|axios(?:\.\w+)?|https?\.get|got|request|requests\.\w+)\s*\([^)]{0,120}\b(?:req|request|ctx|event)\.(?:query|params|body|headers)\b/i },
  { id: 'eval', owasp: 'A03', category: 'Injection', severity: 'high',
    why: 'Use of eval() executes arbitrary code — a classic injection vector', re: /(?<![\w.])eval\s*\(/ }, // provekit-ignore: this is the detection pattern, not a vuln
  { id: 'new-function', owasp: 'A03', category: 'Injection', severity: 'high',
    why: 'new Function(...) runs arbitrary code, same risk as eval', re: /new\s+Function\s*\(/ }, // provekit-ignore: detection pattern, not a vuln
  { id: 'child-process-interp', owasp: 'A03', category: 'Command injection', severity: 'critical',
    why: 'Shell command built with string interpolation — command injection risk', re: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*[`'"][^`'"]*\$\{/ },
  // SQL built from a string that STARTS with an (uppercase) SQL keyword and contains interpolation. Case-sensitive to avoid .update()/.select() methods.
  { id: 'sql-string-concat', owasp: 'A03', category: 'SQL injection', severity: 'medium',
    why: 'SQL query built with string interpolation/concatenation — verify it is parameterized, not user-injectable',
    test(line) {
      if (/\.(?:escape|escapeId)\s*\(|sequelize\.escape|\?\?|\$\d|:\w+\b/.test(line)) return false; // escaped/parameterized markers
      return /[`'"]\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE|ALTER|DROP)\b[\s\S]{0,160}?(?:\$\{|['"]{1,3}\s*\+\s*[A-Za-z_$])/.test(line);
    } },
  { id: 'tls-verify-off', owasp: 'A02', category: 'Broken crypto/transport', severity: 'high',
    why: 'TLS certificate verification disabled (rejectUnauthorized:false / verify=False)', re: /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/ }, // provekit-ignore: detection pattern, not a vuln
  { id: 'dangerous-html', owasp: 'A03', category: 'XSS', severity: 'medium',
    why: 'dangerouslySetInnerHTML / innerHTML with dynamic value — XSS risk', re: /dangerouslySetInnerHTML|\.innerHTML\s*=\s*(?!['"`])/ },
  { id: 'weak-hash-pw', owasp: 'A02', category: 'Weak crypto', severity: 'low',
    why: 'MD5/SHA1 used — insecure if hashing passwords or for integrity (fine for non-security checksums)', re: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/i },
  { id: 'insecure-random-token', owasp: 'A02', category: 'Weak randomness', severity: 'medium',
    why: 'Math.random() used to generate a token/secret/id — not cryptographically secure', re: /(?:token|secret|otp|nonce|api[_-]?key|session)\w*\s*[:=][^;\n]*Math\.random\s*\(/i },
  { id: 'cors-wildcard', owasp: 'A05', category: 'Misconfiguration', severity: 'medium',
    why: 'CORS Access-Control-Allow-Origin set to "*" — allows any site', re: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/i },
  { id: 'debug-true', owasp: 'A05', category: 'Misconfiguration', severity: 'low',
    why: 'Debug mode enabled — can leak stack traces in production', re: /\bdebug\s*[:=]\s*True\b|app\.debug\s*=\s*true/ },
];

module.exports = { SECRETS, PATTERNS, ALL: [...SECRETS, ...PATTERNS] };
