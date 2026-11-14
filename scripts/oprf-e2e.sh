#!/usr/bin/env bash
# End-to-end del servidor OPRF y sus dos clientes. Construye el servidor, emite
# una API key, lo arranca de verdad y le habla por HTTP como le habla el mundo.
# Ejecutar desde la raíz del repo.
#
# Prerrequisitos: Rust (cargo) para el servidor y su cliente; Python (maturin +
# venv activo) para el suyo, que es best-effort — si el módulo no está, se salta
# diciéndolo.
#
# Hasta el 2026-08-05 este guion también construía `quipu-capi` y corría clientes
# de Node y de Go. Los tres se ELIMINARON en la 0.10, así que el guion moría en
# su primera orden (`cargo build -p quipu-capi` → exit 1) y llevaba meses sin
# poder ejecutarse — publicándose igual dentro del .crate. Es el mismo defecto
# que sacó `docs/superpowers/` del paquete, aplicado a medias: aquella pasada
# quitó los DOCUMENTOS muertos y dejó dentro el GUION muerto.
set -uo pipefail

ADDR="127.0.0.1:18787"
URL="http://${ADDR}"
PW="contrasena-de-prueba-e2e"
# Directorio propio y no `mktemp -u`: la bandera `-u` inventa un nombre y NO lo
# crea, así que entre esa línea y el momento en que SQLite abre el archivo hay
# una ventana en la que cualquier usuario de la máquina puede plantar ahí un
# enlace. `mktemp -d` crea el directorio en el acto y en modo 700.
E2E_DIR="$(mktemp -d)"
DB="$E2E_DIR/quipu-oprf.db"
export QUIPU_OPRF_DB="$DB"
export QUIPU_OPRF_SEED="$(openssl rand -hex 32)"
export QUIPU_OPRF_ADMIN_TOKEN="$(openssl rand -hex 32)"

SRV_PID=""
cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
  rm -rf "$E2E_DIR"
}
trap cleanup EXIT

section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
run_client() {
  # run_client <nombre> <comando...>
  # DEVUELVE el estado del cliente. Hasta el 2026-08-05 se lo tragaba, y con la
  # última orden del guion siendo un `echo` eso significaba que este e2e salía
  # con 0 pasara lo que pasara: no podía ponerse rojo ni con el servidor caído.
  # Un banco que no discrimina no es un banco (directiva 33).
  local name="$1"; shift
  section "Cliente: $name"
  if "$@"; then
    printf '\033[32m✓ %s OK\033[0m\n' "$name"
    return 0
  fi
  printf '\033[31m✗ %s FALLÓ\033[0m\n' "$name"
  return 1
}

section "Construir el servidor"
cargo build -p quipu-oprf-server --release || { echo "fallo al construir el servidor"; exit 1; }

section "Emitir API key (plan pro)"
API_KEY="$(./target/release/quipu-oprf-server issue test@example.com pro | awk '/API KEY/{print $NF}')"
if [ -z "$API_KEY" ]; then echo "no se pudo emitir la key"; exit 1; fi
echo "key: ${API_KEY:0:18}…"
export QUIPU_OPRF_API_KEY="$API_KEY"
export QUIPU_OPRF_URL="$URL"
export QUIPU_OPRF_ADDR="$ADDR"

section "Arrancar servidor en $ADDR"
./target/release/quipu-oprf-server serve "$ADDR" &
SRV_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "${URL}/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "${URL}/healthz" >/dev/null 2>&1 || { echo "el servidor no respondió"; exit 1; }
echo "servidor listo (pid $SRV_PID)"

# ── EL ANCLA DE LA CLAVE PÚBLICA, y es lo que este guion medía mal ──────────
#
# Hasta el 2026-08-17 esta variable NO se exportaba, así que `examples/client.rs`
# caía a su antiguo `fetch_public_key(&addr)` y verificaba la prueba DLEQ contra
# una clave que le daba el propio servidor. O sea: el único extremo a extremo del
# producto corría con la garantía central DESACTIVADA, y salía verde. Lo cazó una
# auditoría independiente.
#
# Aquí la descarga es legítima y no es TOFU: el servidor lo acabamos de arrancar
# NOSOTROS tres líneas más arriba, con nuestra propia base y nuestra propia
# semilla. Esto es el momento en que se ESTABLECE el ancla, no el momento en que
# se confía en un desconocido. En producción la clave se fija fuera de banda.
QUIPU_OPRF_PUBKEY="$(curl -fsS "${URL}/v1/public-key" \
  | sed -n 's/.*"public_key"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p')"
if [ ${#QUIPU_OPRF_PUBKEY} -ne 64 ]; then
  echo "no se pudo fijar la clave pública (recibido: '${QUIPU_OPRF_PUBKEY}')"; exit 1
fi
export QUIPU_OPRF_PUBKEY
echo "clave pública fijada: ${QUIPU_OPRF_PUBKEY:0:16}…"

# EL CONTROL NEGATIVO, sin el cual lo de arriba no prueba nada: con una clave
# pública EQUIVOCADA el cliente tiene que NEGARSE.
#
# **LA CLAVE ES EL PUNTO BASE, Y NO 64 CEROS.** La primera versión de este
# control usaba ceros, y la revisión de seguridad demostró con un mutante que NO
# medía nada: 64 ceros son la codificación canónica de la IDENTIDAD de
# ristretto255, y `finalize` la rechaza en una guarda que está ANTES de
# `verify_proof`. Con la verificación DLEQ cableada a `true` —o sea, desactivada
# del todo— el control seguía pasando. Un control que sale verde con la garantía
# apagada reproduce, una capa más arriba, el defecto que venía a cerrar.
#
# `e2f2ae0a…d2d76` es el punto base de ristretto255: un punto VÁLIDO, distinto de
# la identidad y distinto de la clave del servidor. Con él, `finalize` atraviesa
# las guardas de forma y llega de verdad a comprobar la prueba, que es donde
# tiene que fallar.
PUNTO_BASE=e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76
if QUIPU_OPRF_PUBKEY="$PUNTO_BASE" \
   cargo run -q -p quipu-oprf-server --example client -- "control" >/dev/null 2>&1; then
  echo "FALLO: el cliente aceptó una clave pública válida pero AJENA — la prueba DLEQ no se verifica"
  exit 1
fi
echo "control: con una clave válida pero ajena el cliente se niega ✔"

# --- Clientes ---
# El cliente de Rust es OBLIGATORIO: viaja en el repo, se compila con el mismo
# toolchain que el servidor y no depende de nada externo, así que si falla es un
# fallo de verdad y el guion tiene que decirlo con su código de salida.
run_client "Rust" cargo run -q -p quipu-oprf-server --example client -- "$PW" \
  || { echo "el cliente de Rust falló: el extremo a extremo NO pasa"; exit 1; }


# NO HAY CLIENTE DE PYTHON, y es a propósito desde el 2026-08-17.
# El binding `quipu_voprf` (PyO3) se retiró el 14 de agosto al dejar quipu en
# Rust puro, y los dos clientes Python que lo importaban —`examples/oprf_client.py`
# y la integración de Django— se retiraron el 17: nadie los consumía, sus pruebas
# monkeypatcheaban la cripto (así que nunca corrieron de verdad), y reescribirlos
# metía una dependencia de libsodium por una vía hipotética. El cliente de
# referencia es el de Rust, de arriba, que ancla la clave pública correctamente.
# Si algún día hay un consumidor Python real, se escribe entonces —Python puro
# sobre libsodium del sistema, no PyO3— con su motivo. Ver PENDIENTES.
section "Listo"
echo "Extremo a extremo en verde: el servidor arrancó de verdad y cada cliente"
echo "que NO diga SALTADO imprimió su secreto endurecido."
