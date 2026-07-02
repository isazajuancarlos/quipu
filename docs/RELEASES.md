# Verificar la autenticidad de un release de Quipu

Cada release publicado desde un tag `v*` produce dos capas de procedencia
verificable, ambas **keyless** (sin claves privadas de larga vida): la identidad
del firmante es el propio workflow de GitHub Actions, atada vía OIDC a sigstore.

## 1. Wheels de PyPI — attestations PEP 740

`pypa/gh-action-pypi-publish` adjunta attestations de procedencia (PEP 740) a cada
rueda y al sdist. `pip`/`uv` las verifican automáticamente cuando están disponibles;
también puedes inspeccionarlas en la página del proyecto en PyPI.

## 2. Artefactos firmados con cosign (sigstore)

El job `sign` firma cada artefacto de `dist/` y sube un *bundle* `<archivo>.sigstore`.
Para verificar un artefacto descargado junto a su bundle:

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
