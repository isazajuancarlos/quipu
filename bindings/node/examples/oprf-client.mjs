// Cliente OPRF de referencia (Node) para un quipu-oprf-server.
//
// Flujo verificable: blind -> POST /v1/oprf/evaluate -> finalize (verifica la
// prueba DLEQ contra la clave pública fijada) -> secreto endurecido.
//
// La clave pública se FIJA fuera de banda. Pídesela al servidor UNA vez:
//
//   curl -s $QUIPU_OPRF_URL/v1/public-key
//
// y pásala como configuración. No se pide en cada llamada, a propósito: un
// servidor que te entrega la clave contra la que se le verifica no queda
// verificado en absoluto. La prueba DLEQ responde "¿es este el servidor que
// fijé?"; preguntárselo a él no es una respuesta.
//
//   QUIPU_OPRF_URL=https://oprf.tudominio.com \
//   QUIPU_OPRF_API_KEY=quipu_live_... \
//   QUIPU_OPRF_PUBKEY=<64 hex> \
//   node examples/oprf-client.mjs "mi-contraseña"

import { oprfHarden, OprfUnavailable, OprfRejected } from '../src/index.js';

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
if (!pinned) {
  console.error(`falta QUIPU_OPRF_PUBKEY (64 hex). Obtenla una vez con:
  curl -s ${baseUrl}/v1/public-key`);
  process.exit(1);
}

try {
  const secret = await oprfHarden({
    baseUrl,
    apiKey,
    password: Buffer.from(password, 'utf8'),
    serverPublicKey: Buffer.from(pinned.trim(), 'hex'),
  });
  console.log('secreto endurecido:', secret.toString('hex'));
} catch (e) {
  // Dos fallos distintos que exigen reacciones opuestas.
  if (e instanceof OprfRejected) {
    console.error('RECHAZADO: la prueba no valida contra la clave que fijaste.');
    console.error('No es la red. O el servidor rotó su clave, o no es el que crees.');
  } else if (e instanceof OprfUnavailable) {
    console.error('NO DISPONIBLE:', e.message);
    console.error('Reintentable. Nunca degrades a guardar la contraseña sin endurecer.');
  } else {
    throw e;
  }
  process.exit(1);
}
