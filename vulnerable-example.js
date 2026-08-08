// Demo file: the kind of code an AI agent happily writes. provekit flags every line below.
'use strict';
const express = require('express');
const { exec } = require('child_process');
const app = express();

// A02/A07 — secrets pasted in during a debugging session
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const pem = '-----BEGIN RSA PRIVATE KEY-----'; // pasted from a .pem during debugging
const dbUrl = 'postgres://admin:hunter2@db.internal:5432/prod';
const password = 'super-secret-password';

// A10 — SSRF: server fetches a user-supplied URL with no guard
app.get('/preview', async (req, res) => {
  const data = await fetch(req.query.url);   // <- user controls the host
  res.send(await data.text());
});

// A03 — command injection via string interpolation
app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (e, out) => res.send(out));
});

// A03 — SQL built by concatenation
function findUser(db, name) {
  return db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

// A02 — TLS verification disabled
const agent = { rejectUnauthorized: false };

// A02 — insecure token generation
const resetToken = 'reset_' + Math.random().toString(36);

app.listen(3000);
