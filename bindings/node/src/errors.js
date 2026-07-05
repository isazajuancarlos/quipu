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
