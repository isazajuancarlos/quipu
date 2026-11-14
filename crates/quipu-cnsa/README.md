<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza
-->

# quipu-cnsa

Perfil de [Quipu](https://github.com/isazajuancarlos/quipu) alineado con los
algoritmos de **CNSA 2.0** que cubre: AES-256-GCM y HKDF-SHA-384.

**Alcance desde el 2026-07-31: cifrado simétrico, FIRMA y CANAL DE
DESTINATARIO.** Se añadieron **ML-DSA-87** (módulo `firma`) y **ML-KEM-1024**
(módulo `destinatario`), que son los dos algoritmos que CNSA 2.0 exige para esas
funciones.

**Y van PUROS, no híbridos — eso es MÁS DÉBIL que `quipu`.** Aquel firma
Ed25519 **y** ML-DSA-87, y encapsula X25519 **y** ML-KEM-1024, de modo que
romperlo exige romper las dos familias. Aquí no hay socio clásico: si el
algoritmo de retículos cae, no queda nada sujetando. Es lo que dice el mandato,
que no pide híbrido — y es la razón por la que **si puedes elegir, usa `quipu`**.

La asimetría que conviene ver: una firma rota se explota el día que se rompe;
**un secreto cifrado hoy se guarda y se descifra mañana**. Contra «cosecha ahora,
descifra después» el híbrido protege y el puro no.

Hasta el 2026-07-27 el titular de este archivo y la descripción del crate
anunciaban ML-KEM-1024, y no estaba implementado en ninguna parte: la
documentación de dentro lo listaba entre lo que faltaba mientras la portada lo
daba por hecho. Se corrige diciéndolo, no borrándolo, porque este perfil se
sostiene sobre que su alcance sea comprobable — y una promesa de más habría
restado credibilidad justo a la afirmación que sí importa y sí es cierta: que
implementa los algoritmos pero **no está validado**.

## Antes de nada: alineación no es cumplimiento

**Esta librería implementa los algoritmos que exige CNSA 2.0. NO está validada
FIPS 140-3.**

No lo estará por escribir más código: la validación FIPS 140-3 es un proceso de
laboratorio acreditado con coste y calendario propios. **Y no está en el plan.**
La cola del CMVP promedió 542 días a principios de 2024 y el histórico va de 12 a
18 meses, así que un módulo enviado hoy llegaría con certificado después de enero
de 2027 —la fecha en que CNSA 2.0 muerde para adquisiciones nuevas—; un módulo
validado lo está en UNA versión, de modo que cada corrección obligaría a
revalidar; y quien exige FIPS es el gobierno federal estadounidense, que no es el
comprador de esta librería.

**Si tu pliego exige FIPS 140-3, la respuesta no es esperar a que validemos
esto: es poner debajo un dispositivo ya validado.** Y **este crate ya lo
soporta**: con la feature `hsm`, la clave de firma ML-DSA-87 vive y se usa
DENTRO de un dispositivo PKCS#11, y nunca sale de él en claro (módulo
`firmante`; la genera quien aprovisiona el token, no este crate). El
material sensible vive en un módulo con su propio certificado y esta librería no
lo toca. Es la vía que usa todo el mundo y no depende de nuestro calendario.

Hasta el 2026-08-13 esta respuesta existía solo en `quipu`, y eso tenía un
efecto que nadie había dicho en voz alta: el comprador con mandato CNSA que
siguiera nuestra propia recomendación acababa usando la firma **híbrida**
(Ed25519 + ML-DSA-87), o sea el asterisco que este perfil existe para no tener.
Ahora la custodia está en los dos, y aquí es pura.

Lo que sí se busca financiar es una **auditoría criptográfica independiente**,
que es lo que un tercero puede verificar y lo que un comité de seguridad sabe
leer. Preferimos que sepas la diferencia ahora y no cuando alguien la pregunte en
una revisión.

Esta advertencia está en la primera pantalla a propósito. No es letra pequeña.

## Qué relación tiene con `quipu`

La de Devuan con Debian: no una rama de mantenimiento, sino una distribución con
un **compromiso declarado** que comparte casi todo y tiene identidad propia.

| | `quipu` | `quipu-cnsa` |
|---|---|---|
| AEAD | XChaCha20-Poly1305 | **AES-256-GCM** |
| Nonce | 192 bits (extendido) | **96 bits** |
| Derivación de subclaves | HKDF-**SHA-256** | HKDF-**SHA-384** |
| Huella de codebook | SHA-256 | **SHA-384** |
| Cabecera del contenedor | 68 bytes | **56 bytes** |
| Contraseña → clave | Argon2id | Argon2id (**igual**) |
| Formato, codec, ECC, PNG | `quipu-nucleo` | `quipu-nucleo` (**el mismo**) |

Todo lo que no es criptografía vive en
[`quipu-nucleo`](../quipu-nucleo) y se arregla **una vez**. Copiar el
repositorio y dejarlo divergir es como mueren los forks — y en criptografía
muere con una vulnerabilidad corregida en una rama y no en la otra.

## Si puedes elegir, usa `quipu`

Que exista este perfil no significa que sea mejor.

**En hardware sin aceleración AES, AES-GCM es una regresión.** Las
implementaciones en software son más lentas y bastante más difíciles de escribir
en tiempo constante: las tablas de sustitución de AES son un canal lateral
clásico. ChaCha20 no tiene tablas y es constante por construcción.

Este perfil existe para quien tiene un **mandato normativo**, no para quien busca
la mejor criptografía disponible.

## Argon2id no se cambia, y es deliberado

CNSA 2.0 **no se pronuncia** sobre derivación desde contraseña: cubre cifrado,
firma, intercambio de claves y hash, no el paso contraseña → clave.

Sustituir Argon2id por PBKDF2 para «parecer conforme» sería **debilitar el
sistema por estética normativa**. PBKDF2 no tiene coste en memoria y es órdenes
de magnitud más barato de atacar con hardware dedicado. Se mantiene Argon2id y
se declara aquí en vez de esconderlo.

## El nonce de 96 bits no necesita estado global

Es la primera duda de cualquiera que vea AES-GCM con 96 bits, y merece respuesta
explícita. El fallo catastrófico de AES-GCM es reutilizar el par
`(clave, nonce)`.

Aquí **la clave es distinta en cada operación**: se deriva con Argon2id desde una
sal aleatoria de 128 bits generada en el momento de cifrar. Repetir
`(clave, nonce)` exigiría colisionar la sal *y* el nonce; la unicidad la
garantiza la sal, no el nonce.

En términos de SP 800-38D, el modo normal usa la construcción aleatoria
(§8.2.2), cuyo límite son 2³² invocaciones **por clave**, y aquí cada clave se
usa exactamente **una** vez. Un contador persistente no añadiría seguridad y sí
un archivo de estado que corromper y sincronizar entre procesos.

## Lo que todavía NO cubre

**El modo streaming**, sobre el mismo núcleo.

Esta frase decía también «y los enlaces para otros lenguajes», y eso no era una
carencia: era una promesa que contradice una decisión ya tomada. Node, Go y la
C ABI se retiraron en julio de 2026 y Quipu tiene **un solo binding, Python**
(ver `docs/HOJA_DE_RUTA.md`). Prometer los que se quitaron es el defecto exacto
que ya cometió el README de `quipu` — anunciaba Node/Go/C-ABI meses después de
eliminarlos.

La firma (`firma`, ML-DSA-87) y el canal de destinatario (`destinatario`,
ML-KEM-1024) **ya están** desde el 2026-07-31; esta sección los listaba como
pendientes hasta entonces.

### Sobre LMS/XMSS, con el matiz correcto

Se lee a menudo —y nosotros mismos lo escribimos mal en una versión previa de
este archivo— que *CNSA 2.0 exige LMS o XMSS (SP 800-208) para firma de
software*. Es más preciso decirlo así:

- **ML-DSA-87 está aprobado para cualquier uso**, incluida la firma de software
  y firmware. Es el algoritmo de firma de CNSA 2.0.
- **LMS y XMSS están aprobados EXCLUSIVAMENTE para firma de software y
  firmware.** La NSA los priorizó ahí por razones prácticas —había
  implementaciones validadas antes que las de ML-DSA, y una raíz de confianza en
  firmware es dificilísima de actualizar una vez desplegada—, no porque ML-DSA
  no sirva.
- **SLH-DSA no está en CNSA 2.0.** Es FIPS-205 y `quipu` lo ofrece como refuerzo
  propio, no como conformidad.

Consecuencia para este perfil, y ya no es futura: la firma es `firma`
(ML-DSA-87), está construida, y **basta para estar alineados también en este
renglón** — que es el que `docs/CNSA.md` daba por descubierto hasta el
2026-08-02. LMS/XMSS **no es una opción adicional de esta librería**, aunque
aquí se dijo que sí hasta el 2026-08-13. Trae dos costes y el que se suele
contar es el pequeño: son esquemas **con estado** —cada clave produce un número
finito de firmas y reutilizar el índice es catastrófico, así que exige un
contador persistente que sobreviva a caídas y no se duplique en un restore—; el
segundo cierra la puerta del todo.

**CONFIRMADO EN FUENTE PRIMARIA el 2026-08-13, y cambia la conclusión.** Este
párrafo terminaba diciendo que no habíamos podido confirmar si SP 800-208 obliga
a generar las firmas en hardware. **Obliga.** NIST SP 800-208, §8.1
*Conformance*: *«Implementations of the key generation and signature algorithms
in this document shall only be validated for use within hardware cryptographic
modules. The cryptographic modules shall be validated to provide FIPS 140-2 or
FIPS 140-3 Level 3 or higher physical security… The cryptographic module shall
not allow for the export of private keying material.»* Y en la introducción:
*«This recommendation requires that key and signature generation be performed in
hardware cryptographic modules that do not allow secret keying material to be
exported, even in encrypted form.»*

Así que en este renglón la respuesta de `quipu-cnsa` es ML-DSA-87 y **no habrá
otra**: quien necesite LMS/XMSS lo pone en un HSM validado debajo, que es
exactamente la vía que este README ya recomienda para FIPS **y que este crate ya
implementa** (feature `hsm`). Es una carencia menos, no una más — lo que faltaba
no era construible.

## Dónde vive la clave privada

Es la primera pregunta de todo comité de seguridad, y tiene dos respuestas
legítimas:

| | |
|---|---|
| **En memoria** (por defecto) | `firma::SigningKey`. La semilla de 32 bytes se limpia sola al soltarla. Para la mayoría de los despliegues es la respuesta correcta — lo que cambia es que ahora es una **elección**, no la única posible |
| **En un dispositivo PKCS#11** (feature `hsm`) | `firmante::pkcs11::CustodioPkcs11`. La clave vive y se usa DENTRO del HSM, token o tarjeta (la genera quien aprovisiona el dispositivo): por esta librería solo salen firmas y la clave pública, y en claro no sale nunca — si además no debe salir *envuelta*, ver `clave_extraible()` abajo |

**Y esa segunda fila se COMPRUEBA contra el dispositivo, no se supone.** Al
construir el custodio se lee `CKA_SENSITIVE` de la clave privada y **se rechaza
firmar si es falso** —ahí el valor privado se puede leer en claro del token, y
entonces «la clave no sale» sería simplemente mentira—; si el dispositivo no
expone el atributo, también se rechaza, porque suponerlo es justo lo que este
módulo promete no hacer.

Lo que **no** se rechaza es `CKA_EXTRACTABLE`: exportar la clave envuelta bajo
otra clave del propio dispositivo es como se hace la copia de respaldo de un
HSM, y negarse dejaría fuera a un cliente legítimo. Se informa, y quien tenga
una política más dura la afirma él:

```rust,ignore
assert!(!custodio.clave_extraible(), "la política prohíbe claves exportables");
```

Hasta el 2026-08-13 esta tabla decía «**y no sale**» sin que nada lo comprobara
—era una propiedad de los atributos con que alguien creó el objeto, y el custodio
se construía igual sobre una clave legible en claro—. Lo señaló la revisión de
seguridad, no el autor.

Las dos producen firmas que verifica el mismo verificador; el formato en cable
no cambia. La del dispositivo se pide *hedged* y la de memoria es determinista,
así que no son byte a byte idénticas — y eso es deliberado: en cuanto la clave
se muda a un aparato, el adversario con acceso físico entra en el modelo, y es
justo el que ataca a la variante determinista por inyección de fallos.

```toml
quipu-cnsa = { version = "0.1", features = ["hsm"] }
```

```rust,ignore
use quipu_cnsa::firmante::{firmar, pkcs11::CustodioPkcs11};

// La sesión y el PIN son política del integrador; aquí llega ya abierta.
let custodio = CustodioPkcs11::por_etiqueta(sesion, "firma-de-produccion")?;
let firma = firmar(&custodio, mensaje)?;          // se firma dentro del HSM
let vk = custodio.clave_de_verificacion()?;
assert!(vk.verificar(mensaje, &firma));           // verifica el de siempre
```

`cryptoki` carga el módulo del dispositivo por `dlopen` en tiempo de ejecución,
así que compilar con `hsm` no exige tener ningún HSM delante.

## Estado

**Alfa.** Existe, compila y sus pruebas pasan. No ha sido auditada de forma
independiente. No la uses para proteger nada que importe de verdad todavía.

## Licencia

AGPL-3.0-or-later. © 2024-2026 Juan Carlos Isaza.

Como `quipu`, se ofrece también bajo licencia comercial para quien no pueda
cumplir la AGPL: lo que se cobra es la **exención de publicar**, no el uso.
