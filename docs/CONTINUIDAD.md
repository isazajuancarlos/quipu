<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
-->

# Continuidad y modo degradado

Cierra la mitad que faltaba de **I7** («la superficie desplegada responde por sí
misma») en `ATAQUES_TAXONOMIA.md`. Es el invariante donde de verdad pasan las
cosas: de los incidentes reales contrastados en `THREAT_MODEL.md` §10, ninguno
atacó la criptografía — fueron denegación de servicio, ransomware por un
proveedor y acceso comprometido.

Todo lo de aquí está **verificado leyendo el código**, no supuesto. Lo que no se
ha comprobado se dice.

---

## El hecho que ordena todo lo demás

**Con el modo online, el servidor hace falta para DESCIFRAR, no solo para
cifrar.** `src/api.rs` lo dice en la documentación de `encode_online` —«tanto
encode como decode deben hablar con el mismo servidor»— y `decode_online` llama a
`harden` igual que su pareja.

La consecuencia hay que decirla entera, porque cambia la naturaleza del riesgo:

> Para un cliente que usa endurecimiento online, **la disponibilidad de
> `oprf.xiliux.com` es la disponibilidad de sus datos**. Mientras el servicio
> esté caído, no puede abrir lo que ya tenía cifrado.

Eso no es un defecto de diseño: es el precio del rate-limit real, que es
justamente lo que se vende. Un atacante con el contenedor en la mano tampoco
puede probar contraseñas sin pasar por el servidor. Pero convierte la
disponibilidad en una propiedad de seguridad, y obliga a que el cliente sepa
elegir.

**Y explica por qué `k` no rota jamás con la dureza con que se dice:** perder el
*seed* no significa «reemitir claves». Significa que lo que los clientes
derivaron con la clave anterior **no se recupera**. No hay respaldo posible del
lado del servidor que arregle eso a posteriori.

---

## Inventario: qué depende de qué

| Pieza | Dónde vive | Si se pierde | Reconstruible |
|---|---|---|---|
| **Seed VOPRF** (`QUIPU_OPRF_SEED`) | variable de entorno del VPS | Todo lo endurecido por los clientes queda **irrecuperable** | **NO. Nunca.** |
| Base de datos (`QUIPU_OPRF_DB`, SQLite) | disco del VPS | Se pierden clientes, keys y contadores de cuota | Sí: reemitir keys. Molesto, no fatal |
| Token de admin (`QUIPU_OPRF_ADMIN_TOKEN`) | variable de entorno | No se pueden emitir ni revocar keys | Sí: generar otro |
| Proceso / VPS | `oprf.xiliux.com` | Los clientes online no cifran **ni descifran** | Sí, si el seed sobrevive |
| Dominio | DNS | Los clientes tienen la dirección fijada | **NO** — por eso tampoco rota |
| PayPal | externo | No entran altas nuevas | Sí; no afecta al servicio en marcha |

La asimetría es el mensaje: **una sola fila es irreversible**, y no es la base de
datos. El respaldo que importa es el del seed y no está en la máquina que lo usa.

---

## Qué hacer cuando cae cada cosa

### El proceso está muerto o el VPS no responde

1. Comprobar la postura desde fuera, no desde dentro:
   `python3 herramientas/verificar.py desplegado`. Distingue un backend caído de
   un `/admin` abierto: **solo un 2xx es ABIERTO**, un 502 es una caída.
2. Reiniciar con el seed en el entorno. **Confirmar que arrancó con la clave
   buena**: `GET /v1/plans` debe responder 200 y la clave pública publicada debe
   ser la de siempre.
3. Si la clave pública cambió, **parar el servicio**. Es peor servir con una
   clave nueva que no servir: cada evaluación que se entregue con la clave
   equivocada es un cliente que fija un valor inútil.

### El seed falta o está mal escrito

Desde el 2026-07-27 esto **ya no puede degradar en silencio** — antes sí, y era
el peor camino del servicio:

- **Variable ausente** → clave efímera y aviso. Es el desarrollo local de
  siempre, y es legítimo.
- **Variable presente pero inválida** (63 dígitos, un salto de línea de más) →
  **el proceso no arranca**, `exit(1)`. Quien define la variable está declarando
  que quiere la clave persistente; arrancar con otra invalidaría todo lo
  derivado. Un aviso en `stderr` no cuenta como fallar.

Verificado con los tres caminos: seed válido arranca, seed inválido sale con 1 y
el mensaje explica por qué, sin seed sigue siendo efímero.

### La base de datos se corrompe o se pierde

El servicio no arranca (`abrir BD`). Restaurar del respaldo; si no lo hay,
`init` crea el esquema vacío y hay que reemitir las keys. Los clientes pierden
su key, **no sus datos**: lo que endurecieron depende del seed, no de la BD.

### Ransomware o proveedor comprometido

El caso que los invariantes criptográficos no cubren. Lo único que lo mitiga es
que el seed exista **fuera** de la máquina comprometida. Ver «lo que no está
resuelto».

---

## Modo degradado: qué sigue funcionando sin servidor

Esta es la parte que hay que saber vender y saber advertir.

| Capacidad | ¿Sobrevive a que el servidor caiga? |
|---|---|
| Cifrado y descifrado **local** (`encode`/`decode`, contenedor, streaming) | **Sí, entero.** No toca la red |
| Firma y verificación (Ed25519 ∧ ML-DSA-87) | **Sí** |
| Modo asimétrico (X25519 + ML-KEM-1024) | **Sí** |
| Custodia por umbral (Shamir), HSM | **Sí** |
| Honey | **Sí** |
| **Endurecimiento online** (`encode_online` / `decode_online`) | **No.** Ni cifrar ni descifrar |

**El modo degradado, por tanto, es «todo Quipu menos el endurecimiento
online».** No hay que construirlo: existe por la arquitectura, porque el núcleo
nunca dependió de la red. Lo que hay que hacer es **decirlo**, para que quien
integre elija con los ojos abiertos:

- Si el secreto tiene entropía suficiente, el modo local ya es fuerte y no
  cambia nada.
- Si el secreto es una contraseña humana, el modo online es lo que lo vuelve
  defendible — y la contrapartida es esta dependencia.

Lo que **no** existe y conviene no prometer: no hay un camino de «desconectarse»
que permita abrir sin el servidor un contenedor creado con `encode_online`. Sería
exactamente el oráculo offline que el modo existe para impedir.

---

---

## Custodia del seed: el procedimiento

El seed es la única fila irreversible del inventario, así que su respaldo no
puede ser una copia en otro disco: eso cambia un punto único de **fallo** por
dos puntos únicos de **compromiso**. Se reparte con Shamir k-de-n — hacen falta
`k` partes para reconstruir y `k-1` no revelan **nada**, que es la propiedad de
seguridad perfecta del esquema, no una aproximación.

La herramienta vive tras una feature no-default del crate del servidor, para que
no viaje en el binario que corre como servicio:

```bash
cargo build -p quipu-oprf-server --features custodia   # deja target/…/custodia-seed
```

**El material sensible entra siempre por `stdin`, nunca como argumento.** Un
argumento es público en la máquina: aparece en `ps aux` para cualquier usuario
mientras el proceso vive, y queda en el historial del shell para siempre. Un
seed que pasa una vez por ahí hay que darlo por comprometido. El comando además
se niega a leer de una terminal, para que nadie lo teclee.

### Respaldar

Se hace **en el VPS**, para que el seed no salga de la máquina donde ya está;
lo que sale son comparticiones, y hace falta más de una.

```bash
printenv QUIPU_OPRF_SEED | custodia-seed repartir --umbral 2 --partes 3
```

Imprime la **clave pública** —anótala, es la huella que verificará cualquier
restauración futura, y no es secreta— y las tres comparticiones. El comando
**verifica el reparto antes de entregarlo**: reconstruye con un subconjunto del
tamaño del umbral y comprueba que deriva la misma clave. Si no cuadra, no
entrega nada.

Después, cada compartición a un **sitio distinto** y ninguna al VPS. Con 2-de-3,
perder un sitio no cuesta nada y comprometer uno tampoco. Borra el scrollback
cuando las hayas movido.

### Comprobar que el respaldo sirve (sin restaurar nada)

Conviene repetirlo de vez en cuando: un respaldo que nadie ha probado a
restaurar no es un respaldo.

```bash
custodia-seed restaurar --clave-publica <64hex>   # comparticiones por stdin
```

Sin más banderas **solo comprueba**: dice si el material reconstruye y si deriva
la clave esperada. No imprime el seed.

### Restaurar de verdad

**El criterio no es «el fichero se recuperó», es que la clave pública coincida.**
Un seed que se restaura íntegro pero deriva otra clave es peor que perderlo: el
servicio arranca, responde 200 e invalida a todos los clientes en silencio.

```bash
custodia-seed restaurar --clave-publica <64hex> --mostrar-seed > /ruta/segura
```

La bandera es explícita a propósito: sin ella el comando comprueba, con ella
entrega. Y después, confirmarlo contra el proceso — levantar con ese seed y ver
que `GET /v1/public-key` devuelve la clave de siempre.

### Qué garantiza la prueba, y qué no

`tests/restauracion_del_seed.rs` ejecuta el ciclo entero **contra el binario
real** —repartir, perder el original, reconstruir con dos de tres, arrancar el
servicio— y exige que sirva la misma clave. Lleva su control negativo: un seed
distinto por un solo bit levanta un servicio que arranca **perfectamente** y
sirve otra clave. Sin ese control, la prueba no distinguiría «restauré bien» de
«arrancó algo».

Lo que NO garantiza: que las comparticiones existan de verdad, estén donde deben
y sean legibles. Eso es operación, no código, y es el punto 1 de la lista de
abajo.

---

## Lo que NO está resuelto

Se dice para que nadie lo lea como una garantía:

1. **NO EXISTE respaldo del seed fuera del VPS.** Confirmado por Juan el
   2026-07-27 — no es «no consta»: no lo hay. El servicio está cobrando con un
   punto único de fallo total, y mientras eso siga así, la pérdida del VPS es
   la pérdida de los datos de los clientes.

   El mecanismo, el procedimiento y la herramienta ya están arriba y probados.
   **Lo que falta es ejecutarlos una vez**, y eso toca producción, así que lo
   hace Juan. Es la línea más urgente de este documento y la única cuyo coste
   crece cada día que pasa.
2. **No hay réplica ni conmutación por error.** Una caída del VPS es una caída
   del servicio, y su duración es el tiempo de reacción de una persona.
3. **No hay objetivo de disponibilidad declarado** — ni RTO ni RPO — así que hoy
   no se le puede prometer un número a ningún cliente.
4. **No hay alerta automática de caída.** `verificar.py desplegado` existe, pero
   alguien tiene que ejecutarlo: nadie lo corre solo.
5. La postura HTTP comprobada es HSTS y que `/admin/keys` no responda 2xx.
   Deliberadamente **no** se exigen CSP, X-Frame-Options ni Permissions-Policy:
   el servicio devuelve JSON, no HTML.
