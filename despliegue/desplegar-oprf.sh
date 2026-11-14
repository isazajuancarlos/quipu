#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza
#
# Despliegue del servidor OPRF de Quipu al VPS, con vuelta atrás.
#
# La secuencia ENTERA en un guion y no en seis órdenes sueltas, porque el
# despliegue se anuncia antes con su vuelta atrás y eso solo es verificable si
# es una cosa sola. Cada paso comprueba lo suyo y aborta si no cuadra.
#
#   uso:  ./despliegue/desplegar-oprf.sh            (despliega)
#         ./despliegue/desplegar-oprf.sh --probar   (todo menos tocar el VPS)
set -euo pipefail

VPS="debian@192.99.42.108"
DOMINIO="https://oprf.xiliux.com"
REMOTO="/usr/local/bin/quipu-oprf-server"
LOCAL="target/release/quipu-oprf-server"
SELLO="$(date +%Y%m%d-%H%M%S)"
SOLO_PROBAR="${1:-}"

paso() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
abortar() { printf '\n\033[31mABORTADO: %s\033[0m\n' "$*" >&2; exit 1; }

cd "$(dirname "$0")/.."

paso "1. Compilar en release"
cargo build --release -p quipu-oprf-server --bin quipu-oprf-server
[ -f "$LOCAL" ] || abortar "no se produjo $LOCAL"
MD5_LOCAL=$(md5sum "$LOCAL" | cut -d' ' -f1)
echo "   md5 local: $MD5_LOCAL"

paso "2. Comprobar que el binario PUEDE correr en el VPS"
# glibc es compatible hacia atrás, no hacia adelante: el binario no puede exigir
# una versión mayor que la del servidor. Se comprueba, no se supone.
MAX_LOCAL=$(objdump -T "$LOCAL" | grep -oE 'GLIBC_[0-9.]+' | sort -Vu | tail -1 | tr -d 'GLIBC_')
MAX_VPS=$(ssh "$VPS" "ldd --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | tail -1")
echo "   el binario exige glibc <= $MAX_LOCAL ; el VPS tiene $MAX_VPS"
[ "$(printf '%s\n%s\n' "$MAX_LOCAL" "$MAX_VPS" | sort -V | tail -1)" = "$MAX_VPS" ] \
  || abortar "el binario exige glibc $MAX_LOCAL y el VPS tiene $MAX_VPS"

paso "3. Estado ANTES, para poder compararlo después"
ANTES_KEY=$(curl -fsS --max-time 15 "$DOMINIO/v1/public-key")
echo "   clave pública ANTES: $ANTES_KEY"
ANTES_MD5=$(ssh "$VPS" "md5sum $REMOTO | cut -d' ' -f1")
echo "   md5 en producción:   $ANTES_MD5"
[ "$ANTES_MD5" != "$MD5_LOCAL" ] || { echo "   ya está desplegado este binario; nada que hacer"; exit 0; }

if [ "$SOLO_PROBAR" = "--probar" ]; then
  echo; echo "--probar: hasta aquí. No se ha tocado el VPS."; exit 0
fi

paso "4. RESPALDO con marca de tiempo (la vuelta atrás)"
ssh "$VPS" "sudo cp -a $REMOTO ${REMOTO}.bak-$SELLO && sudo ls -la ${REMOTO}.bak-$SELLO"
# La base guarda las claves de API de los suscriptores: se respalda aunque el
# despliegue no la toque. Un respaldo que no se hizo no existe.
ssh "$VPS" "sudo -u quipu cp -a /var/lib/quipu/oprf.db /var/lib/quipu/oprf.db.bak-$SELLO && sudo ls -la /var/lib/quipu/oprf.db.bak-$SELLO"
echo
echo "   VUELTA ATRÁS, si algo sale mal:"
echo "     ssh $VPS 'sudo cp -a ${REMOTO}.bak-$SELLO $REMOTO && sudo systemctl restart quipu-oprf-server'"

paso "5. Subir (a /tmp primero: no se pisa el binario vivo)"
scp "$LOCAL" "$VPS:/tmp/quipu-oprf-server.nuevo"
REMOTO_MD5=$(ssh "$VPS" "md5sum /tmp/quipu-oprf-server.nuevo | cut -d' ' -f1")
[ "$REMOTO_MD5" = "$MD5_LOCAL" ] || abortar "la subida se corrompió: $REMOTO_MD5 != $MD5_LOCAL"
echo "   md5 tras subir: OK"

paso "6. Instalar y reiniciar"
ssh "$VPS" "sudo install -o root -g root -m 755 /tmp/quipu-oprf-server.nuevo $REMOTO && rm -f /tmp/quipu-oprf-server.nuevo && sudo systemctl restart quipu-oprf-server"

paso "7. Verificar CONTRA EL DOMINIO, que es la verdad de lo desplegado"
sleep 3
ssh "$VPS" "systemctl is-active quipu-oprf-server" | grep -qx active || abortar "el servicio no quedó activo"
INSTALADO=$(ssh "$VPS" "md5sum $REMOTO | cut -d' ' -f1")
[ "$INSTALADO" = "$MD5_LOCAL" ] || abortar "lo instalado no es lo compilado"
curl -fsS --max-time 15 -o /dev/null -w "   /healthz -> %{http_code}\n" "$DOMINIO/healthz"
DESPUES_KEY=$(curl -fsS --max-time 15 "$DOMINIO/v1/public-key")
echo "   clave pública DESPUÉS: $DESPUES_KEY"

# EL INVARIANTE QUE NO SE PUEDE ROMPER. Los clientes FIJAN esta clave (suposición
# S5 del modelo de amenaza): si cambia, todos dejan de poder verificar la prueba
# DLEQ y el modo online se cae para todo el mundo. Sale del seed de
# /etc/quipu/oprf.env, que este guion no toca — pero eso se comprueba, no se supone.
[ "$DESPUES_KEY" = "$ANTES_KEY" ] || abortar "LA CLAVE PÚBLICA CAMBIÓ. Vuelve atrás YA con el comando del paso 4"

paso "LISTO"
echo "   binario $MD5_LOCAL en producción, clave pública intacta, /healthz en 200."
echo "   respaldo: ${REMOTO}.bak-$SELLO"
