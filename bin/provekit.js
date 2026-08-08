#!/usr/bin/env node
'use strict';
const { execSync } = require('child_process');
const { scanFile, scanDiff, sortFindings, SEV_RANK } = require('../src/scan');

const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const val = (f, d) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : d; };
const files = args.filter(a => !a.startsWith('-') && a !== val('--diff') && a !== val('--fail-on'));

const C = process.stdout.isTTY ? {
  red: s => `\x1b[31m${s}\x1b[0m`, yel: s => `\x1b[33m${s}\x1b[0m`, blu: s => `\x1b[36m${s}\x1b[0m`,
  dim: s => `\x1b[2m${s}\x1b[0m`, bold: s => `\x1b[1m${s}\x1b[0m`, grn: s => `\x1b[32m${s}\x1b[0m`,
} : new Proxy({}, { get: () => (s => s) });

const SEV_COLOR = { critical: C.red, high: C.red, medium: C.yel, low: C.dim };

function git(cmd) { try { return execSync(`git ${cmd}`, { encoding: 'utf8', stdio: ['pipe','pipe','ignore'] }); } catch { return ''; } } // provekit-ignore: git runs the tool's own args at the user's own privilege — no attacker input crosses a trust boundary
function isGitRepo() { return git('rev-parse --is-inside-work-tree').trim() === 'true'; }

const fs = require('fs');
const path = require('path');
const SRC_EXT = /\.(?:js|jsx|ts|tsx|mjs|cjs|py|rb|go|php|java|cs|env|json|ya?ml|sh|sql)$/i;
const SKIP_DIR = /(?:^|\/)(?:node_modules|\.git|dist|build|vendor|\.next|coverage|\.venv)(?:\/|$)/;
function walk(dir, acc) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    const p = path.join(dir, e.name).replace(/^\.\//, '');
    if (SKIP_DIR.test('/' + p)) continue;
    if (e.isDirectory()) walk(p, acc);
    else if (SRC_EXT.test(e.name)) acc.push(p);
  }
  return acc;
}

function help() {
  console.log(`
${C.bold('provekit')} — attack-tested security scanning for AI-generated code
Catches leaked secrets and the insecure patterns AI agents love to introduce, mapped to the OWASP Top 10.

${C.bold('Usage')}
  provekit                 scan your uncommitted changes (git diff)  ${C.dim('← the AI-code use case')}
  provekit --staged        scan staged changes (great as a pre-commit hook)
  provekit --diff main      scan everything changed vs a branch/ref (great in CI on a PR)
  provekit <files...>      scan specific files
  provekit --all           scan every tracked source file

${C.bold('Options')}
  --fail-on <sev>   exit non-zero at this severity or above (default: high)
  --json            machine-readable output
  --help

Add ${C.dim('// provekit-ignore')} to a line to whitelist a false positive.
`);
}

function gather() {
  if (has('--help') || has('-h')) { help(); process.exit(0); }
  if (files.length) return files.flatMap(scanFile);
  const inGit = isGitRepo();
  if (has('--all') || !inGit) {  // scan every source file (git-tracked, or walk cwd when not a repo)
    const list = inGit ? git('ls-files').split('\n').filter(Boolean) : walk('.', []);
    return list.flatMap(scanFile);
  }
  let diff = '';
  if (has('--staged')) diff = git('diff --cached --unified=0');
  else if (has('--diff')) diff = git(`diff --unified=0 ${val('--diff')}...HEAD`) || git(`diff --unified=0 ${val('--diff')}`);
  else diff = git('diff --unified=0 HEAD') || git('diff --unified=0');
  if (!diff.trim()) { // nothing changed: fall back to all tracked files
    const tracked = git('ls-files').split('\n').filter(Boolean);
    if (tracked.length) return tracked.flatMap(scanFile);
  }
  return scanDiff(diff);
}

const findings = sortFindings(gather());
const failOn = val('--fail-on', 'high');
const threshold = SEV_RANK[failOn] ?? SEV_RANK.high;

if (has('--json')) { console.log(JSON.stringify({ findings, count: findings.length }, null, 2)); }
else if (!findings.length) { console.log(C.grn('\n✓ provekit: no security issues found in the scanned code.\n')); }
else {
  console.log(`\n${C.bold('provekit')} — ${findings.length} issue${findings.length>1?'s':''} found\n`);
  for (const f of findings) {
    const tag = SEV_COLOR[f.severity](f.severity.toUpperCase().padEnd(8));
    console.log(`${tag} ${C.blu(`${f.file}:${f.line}`)}  ${C.dim(`[${f.owasp} · ${f.category}]`)}`);
    console.log(`         ${f.why}`);
    console.log(`         ${C.dim(f.snippet)}\n`);
  }
  const counts = findings.reduce((a, f) => (a[f.severity] = (a[f.severity]||0)+1, a), {});
  console.log(C.bold('Summary: ') + ['critical','high','medium','low'].filter(s=>counts[s]).map(s=>`${counts[s]} ${s}`).join(', '));
}

const blocking = findings.filter(f => (SEV_RANK[f.severity] ?? 0) >= threshold).length;
if (blocking) {
  if (!has('--json')) console.log(C.red(`\n✗ ${blocking} issue(s) at or above "${failOn}" — failing.\n`));
  process.exit(1);
}
process.exit(0);
