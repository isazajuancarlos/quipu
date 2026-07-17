/**
 * OPRF-hardened password hashing for Express / Node.
 *
 * What changes versus plain Argon2:
 *
 *     Argon2 alone:  steal the DB -> offline brute force, at your GPU's speed.
 *     With OPRF:     steal the DB -> you can derive nothing without the server's
 *                    key. Every guess costs a request you can see, rate-limit
 *                    and cut off.
 *
 * The server never sees the password (it arrives blinded) and cannot lie about
 * the result (a DLEQ proof is verified against a key you pinned out of band).
 *
 * Why this is a class you call, and not middleware: hardening happens at signup
 * and at login, not on every request. Express ships no auth and has no hasher
 * registry to hook -- unlike Django, where this same integration is invisible
 * because `PASSWORD_HASHERS` is a real extension point. So here you call it.
 *
 *     import { OprfArgon2Hasher } from 'quipu-oprf-express';
 *
 *     const hasher = new OprfArgon2Hasher({
 *       baseUrl:         process.env.QUIPU_OPRF_URL,
 *       apiKey:          process.env.QUIPU_OPRF_API_KEY,
 *       serverPublicKey: process.env.QUIPU_OPRF_PUBKEY,  // 64 hex, PINNED
 *     });
 *
 *     const encoded = await hasher.hash(password);        // store this
 *     const ok      = await hasher.verify(password, encoded);
 *
 * Both throw OprfUnavailable / OprfRejected rather than failing open. See
 * README.md for the migration recipe for existing bcrypt/argon2 users.
 */

import { hash as argon2Hash, verify as argon2Verify, Algorithm } from '@node-rs/argon2';
import { oprfHarden, OprfUnavailable, OprfRejected, OprfError } from 'quipu-crypto';

export { OprfError, OprfUnavailable, OprfRejected };

/** Marks our encoding so `needsRehash` can spot rows that predate the OPRF. */
export const ALGORITHM = 'quipu_oprf_argon2';

// OWASP's second recommended Argon2id profile (19 MiB, t=2, p=1). These are a
// second line, not the first: the OPRF already makes offline guessing useless
// while the server key stays secret. Argon2 is what stands between an attacker
// and the passwords on the day that key leaks too.
const ARGON2_DEFAULTS = { memoryCost: 19456, timeCost: 2, parallelism: 1, algorithm: Algorithm.Argon2id };

function pinnedKey(serverPublicKey) {
  const buf =
    typeof serverPublicKey === 'string'
      ? Buffer.from(serverPublicKey.trim(), 'hex')
      : serverPublicKey;
  if (!Buffer.isBuffer(buf) || buf.length !== 32) {
    throw new TypeError(
      'serverPublicKey must be 32 bytes (64 hex chars), pinned out of band. ' +
      'Fetch it once with `curl <baseUrl>/v1/public-key` and ship it as config. ' +
      'It is deliberately never fetched at call time: a server that supplies the ' +
      'key it is checked against cannot be checked at all.',
    );
  }
  return buf;
}

export class OprfArgon2Hasher {
  /**
   * @param {object} opts
   * @param {string} opts.baseUrl          e.g. 'https://oprf.xiliux.com'
   * @param {string} opts.apiKey           issued by the OPRF server
   * @param {string|Buffer} opts.serverPublicKey  32 bytes / 64 hex, PINNED
   * @param {number} [opts.timeoutMs=5000]
   * @param {object} [opts.argon2]         overrides for ARGON2_DEFAULTS
   */
  constructor({ baseUrl, apiKey, serverPublicKey, timeoutMs = 5000, argon2 = {} } = {}) {
    if (!baseUrl) throw new TypeError('baseUrl is required');
    if (!apiKey) throw new TypeError('apiKey is required');
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
    this.serverPublicKey = pinnedKey(serverPublicKey);
    this.timeoutMs = timeoutMs;
    this.argon2 = { ...ARGON2_DEFAULTS, ...argon2 };
  }

  /**
   * Password -> the 32-byte hardened secret, which is what Argon2 then sees.
   *
   * Fails CLOSED. If the service is down or the proof does not verify, this
   * throws. It never falls back to the raw password: that would mint a hash
   * matching nothing, and would hide the loss of the guarantee at the exact
   * moment it matters.
   * @private
   */
  async #harden(password) {
    const buf = typeof password === 'string' ? Buffer.from(password, 'utf8') : password;
    const secret = await oprfHarden({
      baseUrl: this.baseUrl,
      apiKey: this.apiKey,
      password: buf,
      serverPublicKey: this.serverPublicKey,
      timeoutMs: this.timeoutMs,
    });
    return secret.toString('hex');
  }

  /** Hash a password. Returns the string to store. */
  async hash(password) {
    const phc = await argon2Hash(await this.#harden(password), this.argon2);
    return ALGORITHM + phc; // phc already starts with '$'
  }

  /**
   * Check a password against a stored value.
   *
   * Returns false only for a genuinely wrong password. A service outage is NOT
   * a wrong password and propagates as OprfUnavailable -- returning false there
   * would tell users "bad credentials" during an outage, and they would reset a
   * password that was never wrong.
   *
   * Throws TypeError on a value this hasher did not produce; verifying legacy
   * rows is your existing code's job (see README: migration).
   */
  async verify(password, encoded) {
    if (!this.identify(encoded)) {
      throw new TypeError(
        `not a ${ALGORITHM} value. Verify legacy hashes with the library that ` +
        'produced them, then re-hash with this one. See README: migration.',
      );
    }
    return argon2Verify(encoded.slice(ALGORITHM.length), await this.#harden(password));
  }

  /** True if `encoded` was produced by this hasher. */
  identify(encoded) {
    return typeof encoded === 'string' && encoded.startsWith(ALGORITHM + '$');
  }

  /**
   * True if this stored value should be replaced by a fresh `hash()` after the
   * user's next successful login -- i.e. it is a legacy bcrypt/argon2 row that
   * has never been hardened. This is how existing users migrate: lazily, on
   * login, with no batch script and no password reset.
   */
  needsRehash(encoded) {
    return !this.identify(encoded);
  }
}
