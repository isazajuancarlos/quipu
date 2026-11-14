# quipu-cbom — la radiografía criptográfica de Quipu

Genera el **CBOM** (Cryptography Bill of Materials, CycloneDX 1.6) de un perfil de
Quipu: la lista firmable de todos sus activos criptográficos, con su nivel de
seguridad clásico y su categoría frente a la amenaza cuántica.

Es el **Ángulo A** del plan CBOM: Quipu se describe a sí mismo. Su valor es de
**portafolio/venta** — casi todos los CBOM del mundo se generan para *descubrir*
criptografía vulnerable que hay que migrar; el de `quipu-cnsa` demuestra lo
contrario: **0 primitivas cuántico-vulnerables entre las requeridas por CNSA 2.0**.

No es un crate de la familia `quipu` (no produce cifrado): es **tooling del repo**,
con su propio workspace, y no toca el lockfile del core.

## Uso

```sh
cargo build --release
./target/release/quipu-cbom descriptor.json > cbom.json
# reproducible: fija la fecha para obtener un artefacto byte-idéntico
SOURCE_DATE_EPOCH=$(date -u -d '2026-09-01T23:00:00Z' +%s) \
  ./target/release/quipu-cbom > cbom.json
```

## Arquitectura (y por qué importa)

- **`descriptor.json`** — el DATO curado: lo que Quipu declara de sí mismo (qué
  primitivas, qué OID, qué nivel PQ, qué exige CNSA de cada una). Es la fuente de
  verdad y lo que requiere criterio.
- **`src/main.rs`** — solo envuelve el descriptor en CycloneDX 1.6 válido
  (serialNumber determinista, fecha reproducible, sin deps de red). Transcribe;
  no juzga.

## Limitación honesta

Este generador **no escanea nada**: refleja fielmente el descriptor. Por tanto el
CBOM es tan veraz como el descriptor, que se mantiene a mano junto al crate. Eso
es correcto para el Ángulo A (autodescripción) y es la línea que lo separa del
**Ángulo B** —escanear el software de un tercero para *descubrir* su criptografía—,
que es un proyecto aparte y vive en `nexus` (`nexus cbom` → `nexus dictamen`),
no aquí. Confundir los dos vendería como "detección" lo que es "declaración".

## Los dos perfiles (y su contraste, que es el argumento de venta)

| Perfil | Descriptor / CBOM | Invariante que demuestra |
|---|---|---|
| `quipu-cnsa` | `descriptor.json` / `cbom.json` | **0 primitivas cuántico-vulnerables** entre las requeridas por CNSA 2.0 (puro PQ) |
| `quipu` (híbrido) | `descriptor-quipu.json` / `cbom-quipu.json` | **Ningún canal depende solo de lo clásico**: cifrado, KEM y firma emparejan una primitiva clásica con una PQ |

El contraste es la pieza: el perfil CNSA es puro (cumple el mandato, pero si una
familia PQ cae no queda socio); el híbrido resiste aunque caiga una de las dos
familias. El CBOM lo hace **medible y verificable**, no un adjetivo.

Cada activo del perfil híbrido lleva `quipu:rol` (clasico|pq|simetrico) y
`quipu:canal` (cifrado|kem|firma|kdf|hash|drbg), y el invariante se comprueba por
canal — con su caso rojo (quitar el socio PQ de un canal lo marca roto).

## Firma (verificable, no solo legible)

Cada CBOM se firma con la **firma híbrida de Quipu** (Ed25519 + ML-DSA-87, 4691 B),
emitiendo `<cbom>.sig.json` detached, atado al **SHA-256** del artefacto exacto
(D31: la firma se ancla al artefacto). El firmador y el verificador viven en
`quipu/examples/`, no aquí, porque la firma es del core:

```sh
# firmar
cargo run --release --example firmar_cbom -- herramientas/cbom/cbom.json herramientas/cbom/cbom-quipu.json
# verificar de forma INDEPENDIENTE (lee el .sig, reconstruye la clave pública, comprueba)
cargo run --release --example verificar_cbom -- herramientas/cbom/cbom.json
```

Los dos ejemplos verifican por la vía real con su caso rojo: round-trip válido,
**CBOM alterado rechazado** y **clave ajena rechazada**.

**Limitación:** la clave del piloto es de **demostración**, generada en cada
corrida (las firmas no son reproducibles y la clave pública cambia). Para la pieza
de portafolio real hace falta una **clave de identidad estable de Xiliux**, con su
política de custodia y respaldo — decisión aparte.

## Vista de portafolio (HTML)

La **vista HTML presentable** del CBOM firmado, para el portafolio (D11: la prueba
de profundidad se muda al portafolio). Es UNA página autocontenida —CSS propio
embebido, sin CDN ni red (D26)— que presenta cada perfil, su INVARIANTE computado
con verde/rojo, la tabla de activos y el estado de la firma:

```sh
SOURCE_DATE_EPOCH=$(date -u -d '2026-09-01T23:00:00Z' +%s) \
  ./target/release/quipu-cbom html cbom.json cbom-quipu.json > cbom.html
```

Lo que la vista computa (no lo copia del descriptor):

- **Perfil híbrido** — el invariante «ningún canal asimétrico depende solo de lo
  clásico»: agrupa los activos por canal (`kem`, `firma`) y marca ROTO el canal sin
  socio PQ. Es el caso rojo del generador, aquí hecho visible.
- **Perfil CNSA** — «0 primitivas cuántico-vulnerables entre las requeridas»: cuenta
  las asimétricas requeridas con nivel PQ 0.
- **Estado de la firma** — cruza el SHA-256 del `cbom.json` contra el que registra su
  `.sig.json` y dice **firma al día** / **firma vieja**. NO verifica cripto (eso es
  `examples/verificar_cbom` en el core); solo el cruce de SHA.

El invariante y el cruce de SHA nacen con su pareja de pruebas (`cargo test`):
canal con socio PQ pasa, canal sin él rompe (D33), y firma vieja se detecta.
