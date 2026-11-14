# Verificar la autenticidad de una entrega de Quipu

> **⚠ TODO LO QUE DESCRIBÍA ESTE DOCUMENTO ESTÁ RETIRADO, Y EL PROCEDIMIENTO QUE
> VALE ES OTRO.** Corregido el 2026-08-17, cuando una revisión de seguridad
> encontró que seguía publicando instrucciones imposibles de completar.
>
> Lo que decía —attestations PEP 740 en PyPI, y firmas cosign/sigstore adjuntas
> al GitHub Release del tag— dependía de tres cosas que ya no existen:
>
> | pieza | estado |
> |---|---|
> | las ruedas de PyPI | **retiradas** (yanked el 2026-08-10; el binding de Python se eliminó el 14) |
> | el job `sign` de sigstore | **retirado** con la rueda: sin `dist/` no le quedaba nada que firmar |
> | los GitHub Releases | **no hay**: desde el 2026-08-10 el origen es local y Actions está apagado |
>
> Y el modo de fallo era el peor de todos: quien siguiera el `cosign verify-blob`
> de abajo **no podía distinguir «no hay firma» de «la firma no valida»**.

## Lo que sí hay: entrega firmada a pedido

El código se entrega como un **paquete firmado** —fuente completa en un
`.tar.gz`, su firma, la clave pública, y un verificador estático— y la firma es
**híbrida: Ed25519 y ML-DSA-87, válida solo si validan las dos**. Un adversario
que guarde la entrega hoy y tenga un computador cuántico mañana sigue sin poder
falsificar una entrega pasada.

```bash
sha256sum -c SHA256SUMS
./verificar-firma verificar "$(cat CLAVE-PUBLICA.txt)" \
    quipu-<versión>-<commit>.tar.gz quipu-<versión>-<commit>.tar.gz.firma
```

Una entrega buena imprime `FIRMA VALIDA` y sale con 0; una manipulada imprime
`*** FIRMA INVALIDA - NO INSTALES ESTE ARCHIVO ***` y sale con 1, así que la
comprobación se puede automatizar sobre el código de salida.

**La huella de la clave se publica por un canal DISTINTO del paquete** —en el
sitio web, no dentro del `.zip`—, porque una clave que viaje solo dentro del
paquete que autentica no prueba nada.

## Por qué no hay firma «keyless»

La construcción anterior era buena por una razón concreta: sin claves privadas de
larga vida que robar, la identidad del firmante era el propio workflow. Al dejar
de haber workflow, esa identidad desaparece; sustituirla por una clave larga es
un cambio de modelo, no un detalle. **La clave privada vive cifrada con Quipu en
la máquina de casa, bajo una frase que no sale de ella, y nunca se sube al
servidor** — así que comprometer el servidor que sirve la descarga no basta para
falsificar una entrega.

---

<!-- El texto original se conserva abajo como registro de lo que se retiró.
     No lo sigas: describe artefactos que ya no existen. -->

## (RETIRADO) Verificar la autenticidad de un release de Quipu

Cada release publicado desde un tag `v*` produce dos capas de procedencia
verificable, ambas **keyless** (sin claves privadas de larga vida): la identidad
del firmante es el propio workflow de GitHub Actions, atada vía OIDC a sigstore.

## 1. Wheels de PyPI — attestations PEP 740

`pypa/gh-action-pypi-publish` adjunta attestations de procedencia (PEP 740) a cada
rueda y al sdist. `pip`/`uv` las verifican automáticamente cuando están disponibles;
también puedes inspeccionarlas en la página del proyecto en PyPI.

## 2. Artefactos firmados con cosign (sigstore)

El job `sign` firma cada artefacto de `dist/` (keyless, OIDC) y adjunta cada
*bundle* `<archivo>.sigstore` al **GitHub Release** del tag correspondiente,
junto a las ruedas y el sdist. Descarga el artefacto y su `.sigstore` desde
[Releases](https://github.com/isazajuancarlos/quipu/releases) y verifícalo:

```bash
cosign verify-blob \
  --bundle quipu_crypto-<versión>-<plataforma>.whl.sigstore \
  --certificate-identity-regexp 'https://github.com/isazajuancarlos/quipu/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  quipu_crypto-<versión>-<plataforma>.whl
```

Una verificación correcta imprime `Verified OK`. Si el archivo fue alterado o no
proviene del workflow de este repositorio, la verificación falla.

## 3. crates.io

El crate `quipu` se publica manualmente con `cargo publish`. Su integridad la
respalda el checksum del índice de crates.io. La procedencia reproducible del
código es el tag firmado del repositorio y este documento.
