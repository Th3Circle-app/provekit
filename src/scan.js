'use strict';
const fs = require('fs');
const { ALL } = require('./rules');

const SEV_RANK = { critical: 3, high: 2, medium: 1, low: 0 };

const SKIP = /(?:^|\/)(?:node_modules|\.git|dist|build|vendor|\.next|coverage)\//;
const SKIP_EXT = /\.(?:png|jpe?g|gif|svg|webp|ico|pdf|lock|min\.js|map|woff2?|ttf|mp[34]|mov|zip)$/i;
const ALLOW = /provekit[-\s]?(?:ignore|allow|ok)|nosec|# noqa|eslint-disable/i;
const NULLBYTE = String.fromCharCode(0);

// "Low-trust" paths: test/example/fixture code legitimately does insecure things
// (disables TLS, uses fake secrets, evals payloads). There we keep the high-confidence
// secret FORMAT detectors on (a real leaked AWS key still matters) but suppress the
// heuristic pattern rules, which is where the noise comes from.
const LOW_TRUST = /(?:^|\/)(?:tests?|__tests__|__mocks__|specs?|fixtures?|examples?|samples?|e2e|demos?|benchmarks?|mocks?|stories)\//i;
const LOW_TRUST_FILE = /\.(?:test|spec|stories)\.[jt]sx?$|\.smoke\.|\.fixture\./i;
function isLowTrust(file) { return !!file && (LOW_TRUST.test(file) || LOW_TRUST_FILE.test(file)); }
// A rule survives in low-trust paths only if it's a specific-format secret detector (near-zero FP).
const highConfidenceSecret = (rule) => rule.category === 'Leaked secret' && !!rule.re;

function scanLine(line, file, lineNo, out, lowTrust) {
  if (!line) return;
  const len = line.length;
  if (len > 20000) return;              // pathological / minified / data line — skip (DoS guard)
  if (ALLOW.test(line)) return;
  const secretsOnly = len > 2000;       // long line: run only the cheap, anchored secret detectors (evasion-resistant, ReDoS-safe)
  for (const rule of ALL) {
    if (secretsOnly && rule.category !== 'Leaked secret') continue;
    if (lowTrust && !highConfidenceSecret(rule)) continue;
    const hit = rule.test ? rule.test(line, file) : rule.re.test(line);
    if (hit) {
      out.push({ file, line: lineNo, id: rule.id, owasp: rule.owasp,
        category: rule.category, severity: rule.severity, why: rule.why,
        snippet: line.trim().slice(0, 120) });
    }
  }
}

function scanText(text, file) {
  const out = [];
  const lowTrust = isLowTrust(file);
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) scanLine(lines[i], file, i + 1, out, lowTrust);
  return out;
}

function scanFile(file) {
  if (SKIP.test(file) || SKIP_EXT.test(file)) return [];
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return []; }
  if (text.indexOf(NULLBYTE) !== -1) return [];   // binary
  return scanText(text, file);
}

// Scan the added lines of a unified `git diff` (the AI-code / PR use case).
function scanDiff(diff) {
  const out = [];
  let file = null, newLine = 0, lowTrust = false;
  for (const raw of diff.split('\n')) {
    if (raw.startsWith('+++ b/')) { file = raw.slice(6); lowTrust = isLowTrust(file); newLine = 0; continue; }
    const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);
    if (hunk) { newLine = parseInt(hunk[1], 10); continue; }
    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      if (file && !SKIP.test(file) && !SKIP_EXT.test(file)) scanLine(raw.slice(1), file, newLine, out, lowTrust);
      newLine++;
    } else if (!raw.startsWith('-')) {
      newLine++;
    }
  }
  return out;
}

function sortFindings(f) {
  return f.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]
    || a.file.localeCompare(b.file) || a.line - b.line);
}

module.exports = { scanFile, scanText, scanDiff, sortFindings, SEV_RANK };
