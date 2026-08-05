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

# --- Clientes ---
# El cliente de Rust es OBLIGATORIO: viaja en el repo, se compila con el mismo
# toolchain que el servidor y no depende de nada externo, así que si falla es un
# fallo de verdad y el guion tiene que decirlo con su código de salida.
run_client "Rust" cargo run -q -p quipu-oprf-server --example client -- "$PW" \
  || { echo "el cliente de Rust falló: el extremo a extremo NO pasa"; exit 1; }

# El de Python sí es best-effort, y esa asimetría es deliberada: necesita la
# rueda instalada en el entorno (`maturin develop --features python`), que no es
# parte de este repo. Se SALTA diciéndolo; nunca se da por pasado en silencio.
if python -c "import quipu" >/dev/null 2>&1; then
  run_client "Python" python examples/oprf_client.py "$PW" \
    || { echo "el cliente de Python falló CON el módulo instalado: eso sí cuenta"; exit 1; }
else
  section "Cliente: Python"
  echo "⚠ SALTADO — módulo 'quipu' no instalado; corre: maturin develop --features python"
fi

section "Listo"
echo "Extremo a extremo en verde: el servidor arrancó de verdad y cada cliente"
echo "que NO diga SALTADO imprimió su secreto endurecido."
