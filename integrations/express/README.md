# quipu-oprf-express

OPRF-hardened password hashing for Express / Node.

```
Argon2 alone:  steal the DB -> offline brute force, at your GPU's speed.
With OPRF:     steal the DB -> you can derive nothing without the server's key.
               Every guess costs a request you can see, rate-limit and cut off.
```

The password never leaves your process in the clear: it is blinded before it
goes out, so the OPRF server cannot see it. And the server cannot lie about the
result: it returns a DLEQ proof, verified against a public key **you pinned**.

## Install

```bash
npm install quipu-oprf-express
```

> **Not published yet.** It depends on `quipu-crypto` >= 0.8.0, which does not
> exist on npm — `voprfBlind`/`voprfFinalize` live in the repo, unreleased. The
> binding ships first. The licence is also unresolved (see `package.json`).

## Use

```js
import { OprfArgon2Hasher } from 'quipu-oprf-express';

const hasher = new OprfArgon2Hasher({
  baseUrl:         process.env.QUIPU_OPRF_URL,     // https://oprf.xiliux.com
  apiKey:          process.env.QUIPU_OPRF_API_KEY,
  serverPublicKey: process.env.QUIPU_OPRF_PUBKEY,  // 64 hex, PINNED
});

// signup
await db.users.insert({ email, password: await hasher.hash(password) });

// login
const user = await db.users.findOne({ email });
if (user && await hasher.verify(password, user.password)) { /* ok */ }
```

There is no middleware, on purpose. Hardening happens at signup and login, not
on every request, so a middleware would be the wrong shape. Django's version of
this integration *is* invisible, because Django has `PASSWORD_HASHERS` — a real
extension point. Express ships no auth and has nothing to hook. So you call it.

## Pin the key

```bash
curl https://oprf.xiliux.com/v1/public-key
```

Do that **once**, out of band, and ship the value as config. The client refuses
to fetch it at call time and will throw if you omit it. This is not pedantry: a
server that supplies the key it is checked against cannot be checked at all — a
malicious server (or a MITM) hands you *its* key, the proof verifies against it,
and hardening reports success while the password went somewhere you did not
choose. The proof answers "is this the server I pinned?". Only you can pin it.

## It fails closed

| Throws | Means | Do |
|---|---|---|
| `OprfUnavailable` | no answer, timeout, 5xx, or the API key was refused | retry, or return 503 |
| `OprfRejected` | the DLEQ proof failed against your pinned key | **investigate.** Never retry blindly |

`verify()` returns `false` only for a genuinely wrong password. An outage
throws instead — returning `false` would tell a user with the *right* password
that it was wrong, and they would reset a password that was never broken.

Neither call ever falls back to the unhardened password. That would mint a hash
matching nothing and hide the loss of the guarantee at the moment it matters.

```js
import { OprfUnavailable, OprfRejected } from 'quipu-oprf-express';

try {
  ok = await hasher.verify(password, user.password);
} catch (e) {
  if (e instanceof OprfRejected)    { alert_someone(e); return res.sendStatus(503); }
  if (e instanceof OprfUnavailable) { return res.sendStatus(503); }
  throw e;
}
```

## Migration

Existing users migrate lazily, on login — no batch script, no forced reset.
Unlike Django, Express cannot do this for you: you keep verifying old rows with
whatever produced them, and re-hash on the way past.

```js
import bcrypt from 'bcrypt';

async function login(user, password) {
  if (hasher.needsRehash(user.password)) {
    // Legacy row: verify with the old library...
    if (!await bcrypt.compare(password, user.password)) return false;
    // ...and upgrade it now that we know the password is right.
    await db.users.update(user.id, { password: await hasher.hash(password) });
    return true;
  }
  return hasher.verify(password, user.password);
}
```

Users who never log in again keep their old hash. That is fine: it is exactly as
safe as it was yesterday, and hardening it is impossible without the password.

## Argon2 is still there

The OPRF output is hashed with Argon2id (OWASP's 19 MiB / t=2 / p=1 profile)
before storage. That is deliberate defence in depth: the OPRF already makes
offline guessing useless while the server key stays secret, and Argon2 is what
stands between an attacker and your users on the day that key leaks too.

Override with `new OprfArgon2Hasher({ ..., argon2: { memoryCost: 65536 } })`.

## Test

The suite runs against a **real** `quipu-oprf-server` on localhost — no fakes in
any layer:

```bash
export QUIPU_OPRF_DB=$PWD/oprf.db QUIPU_OPRF_SEED=$(openssl rand -hex 32)
quipu-oprf-server init && quipu-oprf-server issue test   # prints the API key
QUIPU_OPRF_ADDR=127.0.0.1:8791 quipu-oprf-server serve &

QUIPU_OPRF_URL=http://127.0.0.1:8791 QUIPU_OPRF_API_KEY=<key> npm test
```

## Licence

AGPL-3.0-or-later, **provisionally** — unresolved, see `package.json`. It
imports the AGPL core, so today the copyleft would reach any SaaS that installs
it. Do not build a product on this licence assumption yet.
