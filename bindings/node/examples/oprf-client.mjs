// Cliente OPRF de referencia (Node) para un quipu-oprf-server.
//
// Flujo verificable: blind -> POST /v1/oprf/evaluate -> finalize (verifica la
// prueba DLEQ contra la clave pública fijada) -> secreto endurecido.
//
//   QUIPU_OPRF_URL=https://oprf.tudominio.com \
//   QUIPU_OPRF_API_KEY=quipu_live_... \
//   node examples/oprf-client.mjs "mi-contraseña"
//
// En producción, FIJA (pin) la clave pública fuera de banda (QUIPU_OPRF_PUBKEY)
// en vez de pedirla al servidor.

import { oprfHarden } from '../src/index.js';

const password = process.argv[2];
if (!password) {
  console.error('uso: node oprf-client.mjs <contraseña>');
  process.exit(1);
}

const baseUrl = process.env.QUIPU_OPRF_URL ?? 'http://127.0.0.1:8787';
const apiKey = process.env.QUIPU_OPRF_API_KEY;
if (!apiKey) {
  console.error('falta QUIPU_OPRF_API_KEY');
  process.exit(1);
}
const pinned = process.env.QUIPU_OPRF_PUBKEY;
const serverPublicKey = pinned ? Buffer.from(pinned, 'hex') : undefined;

const secret = await oprfHarden({
  baseUrl,
  apiKey,
  password: Buffer.from(password, 'utf8'),
  serverPublicKey,
});
console.log('secreto endurecido:', secret.toString('hex'));
