const CODE_FOR_STATUS = {
  '-1': 'NULL_ARG',
  '-2': 'AUTH',
  '-3': 'KEY',
  '-4': 'CHUNK',
  '-5': 'INTERNAL',
};
const MESSAGE = {
  NULL_ARG: 'invalid argument',
  AUTH: 'authentication failed',
  KEY: 'malformed key or container',
  CHUNK: 'chunk size out of range',
  INTERNAL: 'internal error',
};

export class QuipuError extends Error {
  constructor(code) {
    super(`quipu: ${MESSAGE[code] ?? 'unknown error'}`);
    this.name = 'QuipuError';
    this.code = code;
  }
}

// A QuipuError for a non-zero status, or null for QUIPU_OK (0).
export function errorFor(rc) {
  if (rc === 0) return null;
  return new QuipuError(CODE_FOR_STATUS[String(rc)] ?? 'INTERNAL');
}

// --- OPRF hardening errors ---
//
// Two classes, never one. They demand opposite reactions, so collapsing them
// into a generic Error pushes that decision onto callers who lack the context
// to make it. Mirrors the Python client (integrations/django).

export class OprfError extends Error {}

// The service did not answer (network, timeout, 5xx) or refused the API key.
// RECOVERABLE: retry, or fail closed. Never degrade to storing an unhardened
// password -- that silently voids the guarantee the whole service exists for.
// See R2 of MODELO_DE_AMENAZA.txt.
export class OprfUnavailable extends OprfError {
  constructor(message, { cause } = {}) {
    super(message, { cause });
    this.name = 'OprfUnavailable';
  }
}

// The DLEQ proof does not verify against the pinned public key. This is NOT a
// network fault: either the server used a different key, or something is
// impersonating it. Never retry blindly, never ignore.
export class OprfRejected extends OprfError {
  constructor(message, { cause } = {}) {
    super(message, { cause });
    this.name = 'OprfRejected';
  }
}
