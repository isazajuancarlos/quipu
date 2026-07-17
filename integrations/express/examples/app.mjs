// Runnable Express app: signup + login with OPRF-hardened passwords.
//
//   npm install express
//   QUIPU_OPRF_URL=http://127.0.0.1:8791 \
//   QUIPU_OPRF_API_KEY=<key> QUIPU_OPRF_PUBKEY=<64 hex> node examples/app.mjs
//
//   curl -X POST localhost:3000/signup -H 'content-type: application/json' \
//        -d '{"email":"a@b.c","password":"correcta"}'
//   curl -X POST localhost:3000/login  -H 'content-type: application/json' \
//        -d '{"email":"a@b.c","password":"correcta"}'
//
// Then kill the OPRF server and try to log in again: you get 503, not a
// "wrong password". That is the whole point -- see the catch block below.

import express from 'express';
import { OprfArgon2Hasher, OprfUnavailable, OprfRejected } from '../src/index.js';

const hasher = new OprfArgon2Hasher({
  baseUrl: process.env.QUIPU_OPRF_URL,
  apiKey: process.env.QUIPU_OPRF_API_KEY,
  serverPublicKey: process.env.QUIPU_OPRF_PUBKEY, // pinned out of band, once
});

const users = new Map(); // a real app uses a database
const app = express();
app.use(express.json());

// Both routes fail closed the same way, so the handling lives in one place.
// An outage must never look like a wrong password.
function onOprfError(e, res) {
  if (e instanceof OprfRejected) {
    // The server is not the one we pinned, or its key rotated. Someone should
    // look at this now; retrying will not fix it.
    console.error('OPRF REJECTED -- pinned key mismatch:', e.message);
    return res.status(503).json({ error: 'auth unavailable' });
  }
  if (e instanceof OprfUnavailable) {
    console.warn('OPRF unavailable:', e.message);
    return res.status(503).json({ error: 'auth unavailable, retry shortly' });
  }
  throw e;
}

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  if (users.has(email)) return res.status(409).json({ error: 'already registered' });
  try {
    users.set(email, await hasher.hash(password));
    res.status(201).json({ ok: true });
  } catch (e) {
    onOprfError(e, res);
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const stored = users.get(email);
  // Note we still call verify for an unknown email in a real app (against a
  // dummy hash) so response time does not leak whether the account exists.
  if (!stored) return res.status(401).json({ error: 'bad credentials' });
  try {
    const ok = await hasher.verify(password, stored);
    res.status(ok ? 200 : 401).json(ok ? { ok: true } : { error: 'bad credentials' });
  } catch (e) {
    onOprfError(e, res);
  }
});

app.listen(3000, () => console.log('http://localhost:3000  (signup, login)'));
