'use strict';
const fs = require('fs');
const { ALL } = require('./rules');

const SEV_RANK = { critical: 3, high: 2, medium: 1, low: 0 };

const SKIP = /(?:^|\/)(?:node_modules|\.git|dist|build|vendor|\.next|coverage)\//;
const SKIP_EXT = /\.(?:png|jpe?g|gif|svg|webp|ico|pdf|lock|min\.js|map|woff2?|ttf|mp[34]|mov|zip)$/i;
const ALLOW = /agentguard[-\s]?(?:ignore|allow|ok)|nosec|# noqa|eslint-disable/i;
const NULLBYTE = String.fromCharCode(0);

function scanLine(line, file, lineNo, out) {
  if (!line || line.length > 1000) return;
  if (ALLOW.test(line)) return;
  for (const rule of ALL) {
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
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) scanLine(lines[i], file, i + 1, out);
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
  let file = null, newLine = 0;
  for (const raw of diff.split('\n')) {
    if (raw.startsWith('+++ b/')) { file = raw.slice(6); newLine = 0; continue; }
    const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);
    if (hunk) { newLine = parseInt(hunk[1], 10); continue; }
    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      if (file && !SKIP.test(file) && !SKIP_EXT.test(file)) scanLine(raw.slice(1), file, newLine, out);
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
