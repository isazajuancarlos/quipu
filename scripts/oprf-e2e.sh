#!/usr/bin/env bash
# End-to-end del servidor OPRF y sus clientes en todos los lenguajes.
# Construye el C ABI + el servidor, emite una API key, arranca el servidor y
# corre el cliente de cada binding contra él. Ejecutar desde la raíz del repo.
#
# Prerrequisitos por sección (cada una es best-effort; si falta el toolchain, se
# salta): Rust (cargo), Python (maturin + venv activo), Node (npm), Go (go).
set -uo pipefail

ADDR="127.0.0.1:18787"
URL="http://${ADDR}"
PW="contrasena-de-prueba-e2e"
DB="$(mktemp -u /tmp/quipu-oprf-XXXXXX.db)"
export QUIPU_OPRF_DB="$DB"
export QUIPU_OPRF_SEED="$(openssl rand -hex 32)"
export QUIPU_OPRF_ADMIN_TOKEN="$(openssl rand -hex 32)"

SRV_PID=""
cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
  rm -f "$DB"
}
trap cleanup EXIT

section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
run_client() {
  # run_client <nombre> <comando...>
  local name="$1"; shift
  section "Cliente: $name"
  if "$@"; then
    printf '\033[32m✓ %s OK\033[0m\n' "$name"
  else
    printf '\033[33m⚠ %s falló o se saltó\033[0m\n' "$name"
  fi
}

section "Construir C ABI + servidor"
cargo build -p quipu-capi --release || { echo "fallo al construir quipu-capi"; exit 1; }
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

# --- Clientes ---
run_client "Rust" cargo run -q -p quipu-oprf-server --example client -- "$PW"

if python -c "import quipu" >/dev/null 2>&1; then
  run_client "Python" python examples/oprf_client.py "$PW"
else
  section "Cliente: Python"
  echo "⚠ módulo 'quipu' no instalado — corre: maturin develop --features python"
fi

if command -v npm >/dev/null 2>&1; then
  ( cd bindings/node && npm run build >/dev/null 2>&1 )
  run_client "Node" bash -c "cd bindings/node && node examples/oprf-client.mjs '$PW'"
else
  section "Cliente: Node"; echo "⚠ npm no encontrado"
fi

if command -v go >/dev/null 2>&1; then
  run_client "Go" bash -c "cd bindings/go && go run ./cmd/oprf-client '$PW'"
else
  section "Cliente: Go"; echo "⚠ go no encontrado"
fi

section "Listo"
echo "Todos los clientes que imprimieron un 'secreto endurecido' funcionan."
