<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# `.github/` — aquí no queda ninguna automatización, y es a propósito

Este directorio tenía cuatro workflows y una configuración de dependabot. Se
borraron el **2026-08-17**. Lo único que queda es `FUNDING.yml`, que es un dato,
no un programa.

## Por qué

Desde el **2026-08-10** este proyecto no vive en GitHub: el origen es un
repositorio local y Actions está apagado. Ese protocolo es **permanente** — no
hay fecha de vuelta —, así que los workflows llevaban una semana sin poder
ejecutarse y no iban a volver a hacerlo.

Dejarlos tenía tres costes y ninguna ventaja:

1. **Prometían una cobertura que no existía.** `docs/THREAT_MODEL.md` citaba
   controles «enforced in CI». No hay CI. Lo que de verdad se ejecuta hoy es
   `python3 herramientas/verificar.py local`, y una auditoría del 2026-08-17
   midió que cubría **un tercio** de lo que cubrían los jobs. Se le añadieron los
   pasos que faltaban; los workflows ya no aportaban nada que no estuviera ahí.

2. **Viajan dentro de la entrega de código.** Quien reciba el tarball y ponga el
   árbol en una plataforma con Actions encendido despierta dos cosas que no son
   seguras por defecto: `claude.yml` disparaba con `issues: [opened]` y
   `issue_comment: [created]` —o sea, **cualquier desconocido abriendo una
   issue**— y `release.yml` tenía un job con `id-token: write` para publicar por
   OIDC. Entregar eso sin poder vigilarlo es entregar un riesgo.

3. **`dependabot.yml` no puede hacer nada** sin el repositorio en GitHub, y su
   presencia sugiere que las dependencias se actualizan solas. No se actualizan:
   el árbol está vendorizado y congelado a propósito, y lo que vigila los avisos
   es `cargo audit`, que ahora corre dentro del verde local.

## Qué hace su trabajo ahora

    python3 herramientas/verificar.py local

14 comprobaciones, incluidas las que solo vivían en el CI: residuo de memoria en
release con las features **derivadas del propio banco**, `cargo audit`, el
custodio PKCS#11 contra un token de software, y el guardián de coste del códec.

Si algún día vuelve a haber CI, el punto de partida está en el historial:
`git log --diff-filter=D -- .github/workflows/`.
