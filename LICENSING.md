# Licenciamiento de Quipu

Quipu se distribuye bajo un modelo **de licencia dual** (open-core).

> **Titularidad.** Copyright (c) 2024-2026 Juan Carlos Isaza Arenas. Titular
> único de los derechos patrimoniales; ver [`COPYRIGHT`](COPYRIGHT). Es esa
> titularidad indivisa la que hace posible la doble licencia — de ahí el CLA de
> [`CONTRIBUTING.md`](CONTRIBUTING.md). El uso del nombre se rige por
> [`TRADEMARK.md`](TRADEMARK.md).

## 0. Qué licencia cubre qué

No todo el repositorio es AGPL. La regla es sencilla: **lo que un cliente del
servicio OPRF debe enlazar dentro de su propio servidor es permisivo; el resto
es copyleft.**

| Componente | Licencia | Por qué |
|---|---|---|
| `quipu` (núcleo) y sus bindings | `AGPL-3.0-or-later` | El activo: cripto post-cuántica, cifrado en reposo. El copyleft de red no estorba a quien lo usa dentro de su producto. |
| `crates/quipu-voprf` | **`Apache-2.0`** | Lo único que el cliente enlaza en su auth. Con AGPL, el copyleft de red alcanzaría su SaaS y nadie compraría el servicio. |
| `integrations/{django,express,go}` | **`Apache-2.0`** | SDK de cliente. Dependen solo de `quipu-voprf`. |
| `crates/quipu-oprf-server` | `AGPL-3.0-or-later` / comercial | Es SaaS: el cliente nunca recibe el binario. |

Dos precisiones que suelen confundirse:

1. **Poner Apache al SDK no basta por sí solo.** La licencia de un envoltorio no
   relicencia su dependencia: si el SDK importara el núcleo AGPL, la obra
   combinada seguiría disparando el §13 sobre el SaaS del cliente. Por eso las
   primitivas VOPRF viven en un crate **separado**, no solo con otra etiqueta.
2. **La dirección importa.** Apache-2.0 es compatible hacia GPL/AGPL-3.0, no al
   revés. Por eso el núcleo AGPL puede depender de `quipu-voprf` sin fricción,
   y un cliente que solo enlaza `quipu-voprf` no se contagia.

Lo que se cede en `quipu-voprf` son ~270 líneas de matemática de curva estándar.
El foso siguen siendo el servidor, la clave `k` y la biblioteca completa.

## 1. Licencia abierta — AGPL-3.0-or-later

El núcleo de Quipu es software libre bajo la
**GNU Affero General Public License v3.0 o posterior** (SPDX: `AGPL-3.0-or-later`).

Puedes usar, estudiar, modificar y redistribuir Quipu libremente. La condición
clave de la AGPL es el **copyleft de red**: si ofreces a terceros un servicio
(por red) construido con Quipu o con obras derivadas, debes poner el **código
fuente completo** de tu versión a disposición de esos usuarios, bajo la misma
licencia.

El texto legal completo debe acompañar al proyecto en el archivo `LICENSE`
(texto oficial: https://www.gnu.org/licenses/agpl-3.0.txt).

## 2. Licencia comercial

La obligación de abrir el código de la AGPL **no encaja** con muchos productos
propietarios o SaaS cerrados. Para esos casos ofrecemos una **licencia comercial
separada** que exime del copyleft de red, a cambio de una cuota.

Si tu organización quiere:

- integrar Quipu en un producto **cerrado / propietario**, o
- ofrecer un **servicio** basado en Quipu **sin publicar** tu código fuente,

entonces necesitas una licencia comercial. Contacto: **isazajuancarlos@gmail.com**.

Los términos están en [`LICENSE-COMMERCIAL`](LICENSE-COMMERCIAL). En resumen: la
licencia es anual y exime del copyleft de red; al vencer sin renovar, **conservas
de forma perpetua el derecho a seguir distribuyendo las versiones recibidas**
durante la vigencia, pero no las posteriores. La concesión AGPL es permanente y
no se ve afectada por nada de esto.

## 3. El servicio gestionado (capa de pago)

Independiente de la licencia del código: el **servidor OPRF de endurecimiento
online** se ofrece también como **servicio gestionado** (disponibilidad,
rate-limit, custodia y rotación de la clave). Ejecutarlo tú mismo con el código
libre es legítimo bajo AGPL; el servicio gestionado es una comodidad de pago.

## Resumen

| Uso | Qué necesitas |
|-----|---------------|
| Proyecto abierto (compatible con AGPL) | Nada, úsalo bajo AGPL. |
| Uso interno sin distribuir ni ofrecer por red | AGPL basta. |
| Producto propietario cerrado | Licencia comercial. |
| SaaS sin abrir tu código | Licencia comercial. |
| No quieres operar el servidor OPRF | Servicio gestionado (de pago). |

> Nota: esto es un resumen práctico, no asesoría legal. El texto vinculante es el
> de `LICENSE` (AGPL-3.0) y el del contrato de licencia comercial.
