#!/usr/bin/env bash
# Construye y ejecuta el banco offline del Quipu Security Lab dentro de una jaula:
#   - sin red         (--network none): no puede exfiltrar ni descargar payloads
#   - solo lectura     (--read-only): no puede modificar la imagen
#   - usuario no-root  (definido en el Dockerfile)
#   - sin claves reales: NO se monta oprf_seed.bin ni ningún secreto
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -t quipu-lab -f lab/Dockerfile .
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  quipu-lab
