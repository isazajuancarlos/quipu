#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
"""Verificador de Quipu: lo que hay que comprobar, encerrado en una herramienta.

# Por qué existe

El 2026-07-21, en una sola jornada, SEIS mecanismos de verificación distintos
resultaron no estar verificando nada. Ninguno falló ruidosamente: los seis
produjeron exactamente la señal que yo esperaba ver.

  1. `cargo test | tail -30` — en bash el `$?` de una tubería es el del ÚLTIMO
     comando. Salía 0 aunque las pruebas fallaran, y el log solo guardaba 30
     líneas, así que leerlo tampoco lo desmentía.
  2. Un monitor construido sobre `jq` — que no estaba instalado. Veinte minutos
     de silencio que parecían «sin novedad».
  3. `gh pr checks --json` — bandera inexistente en gh 2.46. El vigilante
     nacía mudo.
  4. `cargo test --all-targets` SIN `--workspace` — 137 pruebas de 235. Los
     vectores RFC 9497 de `quipu-voprf` no se habían ejecutado en CI jamás.
  5. `--all-targets` EXCLUYE los doctests, pese al nombre.
  6. `gh pr view --json statusCheckRollup` devuelve `conclusion: ""` —cadena
     vacía, no `null`— mientras el check corre, y el operador `//` de jq solo
     cae al alternativo con `null`. Un check en marcha parecía terminado.

Y el que los precedió, el 2026-07-20: la rueda de PyPI 0.9.0 salió sin la
feature `hsm` porque `release.yml` repetía la lista de features en vez de
leerla, y yo verifiqué la rueda LOCAL en vez de la construida por el CI.

La lección no es «acuérdate de estas siete cosas». Es que acordarse no escala:
yo me equivoco de nuevo, una herramienta no. Cada vez que se descubra una forma
nueva de verificar en falso, se corrige AQUÍ y deja de ser posible.

# Qué NO hace

No sustituye al CI. La matriz de features y `--workspace` viven en `ci.yml`
porque un job que revienta el PR no depende de que nadie ejecute nada. Esto
cubre lo que el CI no puede: el ARTEFACTO ya publicado, que se construye en el
flujo de release y vive en índices de terceros.

Uso:
    python3 herramientas/verificar.py local
    python3 herramientas/verificar.py publicado --version 0.9.1
    python3 herramientas/verificar.py pr 84
    python3 herramientas/verificar.py todo --version 0.9.1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
AGENTE = "quipu-verificar/1.0 (+https://github.com/isazajuancarlos/quipu)"

VERDE, ROJO, AMARILLO, GRIS, FIN = "\033[32m", "\033[31m", "\033[33m", "\033[90m", "\033[0m"
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    VERDE = ROJO = AMARILLO = GRIS = FIN = ""


@dataclass
class Informe:
    """Acumula resultados. Un comprobante ausente NO cuenta como aprobado."""

    lineas: list[tuple[str, str, str]] = field(default_factory=list)

    def ok(self, que: str, detalle: str = "") -> None:
        self.lineas.append(("ok", que, detalle))

    def fallo(self, que: str, detalle: str = "") -> None:
        self.lineas.append(("fallo", que, detalle))

    def omitido(self, que: str, porque: str) -> None:
        """Ni aprobado ni suspenso: NO SE PUDO MIRAR.

        Existe esta tercera categoría a propósito. Meter lo no comprobado en el
        montón de lo aprobado es precisamente el error que esta herramienta
        combate: el silencio de un vigilante solo informa si se comprobó que
        podía hablar.
        """
        self.lineas.append(("omitido", que, porque))

    def imprimir(self) -> int:
        print()
        for estado, que, detalle in self.lineas:
            if estado == "ok":
                marca, color = "✓", VERDE
            elif estado == "fallo":
                marca, color = "✗", ROJO
            else:
                marca, color = "?", AMARILLO
            cola = f"  {GRIS}{detalle}{FIN}" if detalle else ""
            print(f"  {color}{marca}{FIN} {que}{cola}")

        fallos = sum(1 for e, _, _ in self.lineas if e == "fallo")
        omitidos = sum(1 for e, _, _ in self.lineas if e == "omitido")
        aprobados = sum(1 for e, _, _ in self.lineas if e == "ok")
        print(f"\n  {aprobados} comprobados · {fallos} fallidos · {omitidos} SIN COMPROBAR")

        if fallos:
            print(f"\n{ROJO}VERIFICACIÓN FALLIDA{FIN}")
            return 1
        if omitidos:
            # Salir 0 aquí sería exactamente el fallo que esta herramienta
            # persigue: convertir «no lo miré» en «está bien».
            print(f"\n{AMARILLO}INCOMPLETA: hay comprobaciones que no se pudieron hacer.{FIN}")
            print(f"{AMARILLO}NO es un aprobado. Resuelve lo que falta y repite.{FIN}")
            return 2
        print(f"\n{VERDE}TODO VERIFICADO{FIN}")
        return 0


def correr(orden: list[str], cwd: Path | None = None, timeout: int = 3600):
    """Ejecuta SIN shell y devuelve (codigo, salida).

    Sin `shell=True` y con la orden como lista: no hay tuberías que puedan
    tragarse el código de salida (lección 1). Si alguna vez hiciera falta una
    tubería aquí, tendría que ser con `set -o pipefail` explícito.
    """
    try:
        p = subprocess.run(
            orden, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, (p.stdout + p.stderr)
    except FileNotFoundError:
        return 127, f"no se encontró el ejecutable: {orden[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"tiempo agotado ({timeout}s)"


def hay(programa: str) -> bool:
    """¿Existe el ejecutable? Comprobar ANTES de fiarse de su silencio."""
    return shutil.which(programa) is not None


def bajar(url: str, destino: Path) -> bool:
    pet = urllib.request.Request(url, headers={"User-Agent": AGENTE})
    try:
        with urllib.request.urlopen(pet, timeout=120) as r, destino.open("wb") as f:
            shutil.copyfileobj(r, f)
        return True
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return False


def leer_json_estado(url: str) -> tuple[str, object]:
    """("ok", datos) · ("ausente", None) si el índice responde 404 ·
    ("sin-respuesta", None) para todo lo demás.

    Los índices exigen User-Agent; sin él, crates.io responde 403 y un 403 NO
    significa «no publicado» (nos costó una conclusión equivocada).

    Los tres estados existen porque colapsarlos a dos vuelve a producir esa
    misma conclusión con otro disfraz: «no pude mirar» y «miré y no está» se
    parecen en el código —los dos son un `None`— y son opuestos en lo que
    autorizan. Un 404 del índice es un dato: el crate no está publicado. Un
    timeout no es ningún dato.
    """
    pet = urllib.request.Request(url, headers={"User-Agent": AGENTE})
    try:
        with urllib.request.urlopen(pet, timeout=60) as r:
            return "ok", json.load(r)
    except urllib.error.HTTPError as e:
        return ("ausente", None) if e.code == 404 else ("sin-respuesta", None)
    except (urllib.error.URLError, TimeoutError, ValueError):
        return "sin-respuesta", None


def leer_json(url: str):
    """Los datos, o `None` si no se pudieron leer POR EL MOTIVO QUE SEA.

    Quien necesite distinguir «no está» de «no pude mirar» tiene que usar
    [`leer_json_estado`]: aquí los dos casos son el mismo `None`.
    """
    return leer_json_estado(url)[1]


# --------------------------------------------------------------------------
# Features declaradas: se LEEN, no se repiten.
# --------------------------------------------------------------------------

def _leer_toml(ruta: Path) -> dict:
    """Lee un TOML, o REVIENTA.

    La primera versión devolvía `[]` si faltaba `tomllib` (Python < 3.11). Eso
    convertía «no pude leer las features» en «no hay features», y la
    comprobación pasaba sin comprobar nada — un aprobado por ausencia de datos,
    que es el defecto que esta herramienta entera existe para impedir
    (directiva 20: ante un dato ausente, fallar ruidosamente).
    """
    try:
        import tomllib
    except ModuleNotFoundError as e:  # Python < 3.11
        raise SystemExit(
            "verificar.py necesita Python 3.11+ (tomllib) para leer los "
            "manifiestos. Sin eso no puede comprobar las features, y prefiere "
            "no arrancar antes que aprobar sin mirar."
        ) from e
    return tomllib.loads(ruta.read_text(encoding="utf-8"))


def features_del_manifiesto() -> list[str]:
    """Todas las features declaradas en Cargo.toml, leídas del propio archivo.

    Repetir esta lista a mano es lo que dejó la rueda 0.9.0 sin `hsm`.
    """
    return sorted(_leer_toml(RAIZ / "Cargo.toml").get("features", {}).keys())


def features_de_la_rueda() -> list[str]:
    """Las features con las que se construye la rueda de PyPI."""
    datos = _leer_toml(RAIZ / "pyproject.toml")
    return datos.get("tool", {}).get("maturin", {}).get("features", [])


# --------------------------------------------------------------------------
# local
# --------------------------------------------------------------------------

def verificar_local(inf: Informe) -> None:
    if not hay("cargo"):
        inf.omitido("pruebas locales", "cargo no está instalado")
        return

    # `--workspace` NO es decorativo: sin él cargo prueba solo el paquete raíz.
    # `--all-targets` EXCLUYE los doctests, así que hacen falta las dos pasadas.
    pasos = [
        ("pruebas del workspace", ["cargo", "test", "--workspace", "--all-targets"]),
        ("doctests", ["cargo", "test", "--workspace", "--doc"]),
        ("clippy sin avisos", ["cargo", "clippy", "--workspace", "--all-targets",
                               "--", "-D", "warnings"]),
    ]
    for nombre, orden in pasos:
        codigo, salida = correr(orden, cwd=RAIZ)
        if codigo == 0:
            inf.ok(nombre, resumen_de_pruebas(salida))
        else:
            inf.fallo(nombre, primera_linea_de_error(salida))

    if hay("cargo-vet"):
        codigo, salida = correr(["cargo", "vet", "--locked"], cwd=RAIZ)
        (inf.ok if codigo == 0 else inf.fallo)(
            "cadena de suministro (cargo-vet)", primera_linea_de_error(salida)
        )
    else:
        inf.omitido("cadena de suministro (cargo-vet)", "cargo-vet no instalado")


def resumen_de_pruebas(salida: str) -> str:
    pasadas = fallidas = 0
    for linea in salida.splitlines():
        if linea.startswith("test result:"):
            trozos = linea.split()
            try:
                pasadas += int(trozos[3])
                fallidas += int(trozos[5])
            except (IndexError, ValueError):
                pass
    return f"{pasadas} pasadas, {fallidas} fallidas" if pasadas or fallidas else ""


def primera_linea_de_error(salida: str) -> str:
    for linea in salida.splitlines():
        if linea.startswith("error") or "Vetting" in linea or "FAILED" in linea:
            return linea.strip()[:120]
    return ""


# --------------------------------------------------------------------------
# publicado
# --------------------------------------------------------------------------

def verificar_crate_publicado(inf: Informe, version: str, tmp: Path) -> None:
    """Baja el .crate de crates.io y lo compila FEATURE POR FEATURE.

    Contra el artefacto, no contra el árbol de trabajo. Así se descubrió que
    quipu 0.9.1 no compila con `--features lab-offline`.
    """
    meta = leer_json("https://crates.io/api/v1/crates/quipu")
    if meta is None:
        inf.omitido("crates.io alcanzable", "no se pudo consultar el índice")
    else:
        publicadas = {v["num"]: v for v in meta.get("versions", [])}
        if version in publicadas:
            estado = "retirada (yanked)" if publicadas[version].get("yanked") else "activa"
            inf.ok(f"crates.io tiene quipu {version}", estado)
        else:
            inf.fallo(f"crates.io tiene quipu {version}", "no aparece en el índice")
            return

    if not hay("cargo"):
        inf.omitido("compilar el crate publicado", "cargo no está instalado")
        return

    archivo = tmp / f"quipu-{version}.crate"
    url = f"https://static.crates.io/crates/quipu/quipu-{version}.crate"
    if not bajar(url, archivo):
        inf.omitido("compilar el crate publicado", f"no se pudo descargar {url}")
        return

    with tarfile.open(archivo) as t:
        t.extractall(tmp, filter="data")
    fuente = tmp / f"quipu-{version}"

    for feature in [""] + features_del_manifiesto():
        # `lab-offline` implica `lab`; se prueban igual porque el usuario puede
        # pedir cualquiera de las dos.
        orden = ["cargo", "build", "--quiet"]
        etiqueta = "por defecto (sin features)" if not feature else f"--features {feature}"
        if feature:
            orden += ["--features", feature]
        codigo, salida = correr(orden, cwd=fuente, timeout=1800)
        if codigo == 0:
            inf.ok(f"quipu {version} compila: {etiqueta}")
        else:
            inf.fallo(f"quipu {version} compila: {etiqueta}", primera_linea_de_error(salida))


# Símbolos que cada feature de la rueda debe hacer visibles en `import quipu`.
# Los nombres están VERIFICADOS contra `src/python.rs`, no supuestos — y
# `testigo_existe_en_el_codigo` lo vuelve a comprobar en cada ejecución, para
# que renombrar una función en Rust no convierta esta lista en una acusación
# falsa contra el artefacto.
#
# Si se añade una feature a `[tool.maturin] features`, hay que añadir aquí su
# testigo. Sin testigo, esa feature puede desaparecer de la rueda sin que nadie
# se entere — que es exactamente lo que pasó con `hsm` en la 0.9.0.
TESTIGOS = {
    "python": ["encode", "decode"],
    "escrow": ["split_secret", "combine_secret"],
    "hsm": ["CustodioHsm"],
    # `honey` NO aparece: el binding de Python de Honey Encryption todavía no
    # está mergeado (vive en `feat/python-honey`). Poner aquí un testigo de algo
    # que no existe sería aspiración disfrazada de comprobación. Se añade el día
    # que la función exista, no antes.
}


def testigo_existe_en_el_codigo(nombre: str) -> bool:
    """¿El símbolo testigo existe de verdad en el binding de Python?

    Contempla los genéricos: `fn decode<'py>(...)` es una declaración tan válida
    como `fn encode(...)`, y buscar solo `fn nombre(` la daba por ausente.
    """
    fuente = RAIZ / "src" / "python.rs"
    if not fuente.exists():
        return True  # sin fuente que consultar, no se puede desmentir
    texto = fuente.read_text(encoding="utf-8")
    return any(
        marca in texto
        for marca in (f"fn {nombre}(", f"fn {nombre}<", f"struct {nombre}")
    )


def verificar_rueda_publicada(inf: Informe, version: str, tmp: Path) -> None:
    """Instala la rueda de PyPI en un venv LIMPIO y comprueba los símbolos.

    Lo que atrapó que la 0.9.0 salió sin `hsm`: los símbolos que promete el
    `pyproject.toml` tienen que existir en el paquete INSTALADO desde PyPI, no
    en la rueda que uno construye en su portátil.
    """
    meta = leer_json("https://pypi.org/pypi/quipu-crypto/json")
    if meta is None:
        inf.omitido("PyPI alcanzable", "no se pudo consultar el índice")
        return
    if version not in meta.get("releases", {}):
        inf.fallo(f"PyPI tiene quipu-crypto {version}", "no aparece en el índice")
        return
    archivos = meta["releases"][version]
    retirada = all(a.get("yanked") for a in archivos) if archivos else False
    inf.ok(f"PyPI tiene quipu-crypto {version}", "retirada (yanked)" if retirada else "activa")

    venv = tmp / "venv"
    codigo, salida = correr([sys.executable, "-m", "venv", str(venv)])
    if codigo != 0:
        inf.omitido("símbolos de la rueda de PyPI", "no se pudo crear el venv")
        return
    pip = venv / "bin" / "pip"
    python = venv / "bin" / "python"
    codigo, salida = correr(
        [str(pip), "install", "--quiet", f"quipu-crypto=={version}"], timeout=900
    )
    if codigo != 0:
        inf.fallo("instalar quipu-crypto desde PyPI", primera_linea_de_error(salida))
        return
    inf.ok(f"quipu-crypto {version} instala en venv limpio")

    declaradas = features_de_la_rueda()
    for feature in declaradas:
        testigos = TESTIGOS.get(feature)
        if testigos is None:
            inf.omitido(f"símbolos de la feature «{feature}»", "no hay testigo definido")
            continue

        # Un testigo que no existe en `src/python.rs` acusaría al artefacto de
        # un error MÍO. La primera versión de esta herramienta inventó
        # `combine_shares` —se llama `combine_secret`— y reportó un fallo de la
        # rueda 0.9.1 que no existía. Un testigo inválido tiene que fallar
        # DISTINTO de un símbolo ausente (directiva 20: fallar ruidosamente en
        # vez de sustituir por una suposición).
        invalidos = [t for t in testigos if not testigo_existe_en_el_codigo(t)]
        if invalidos:
            inf.omitido(
                f"símbolos de la feature «{feature}»",
                f"testigo inválido, no está en src/python.rs: {', '.join(invalidos)}",
            )
            continue

        guion = (
            "import quipu, sys;"
            f"faltan=[s for s in {testigos!r} if not hasattr(quipu, s)];"
            "sys.exit(1) if faltan else None;"
        )
        codigo, salida = correr([str(python), "-c", guion])
        if codigo == 0:
            inf.ok(f"la rueda trae «{feature}»", ", ".join(testigos))
        else:
            inf.fallo(f"la rueda trae «{feature}»", f"faltan símbolos: {testigos}")


# =========================== coherencia de versiones ===========================
#
# El error que más veces se ha repetido en este proyecto es publicar con la
# versión puesta en unos archivos y no en otros. La defensa era una LISTA en el
# CLAUDE.md («son DOCE archivos») y un `grep` para comprobarla. Auditada el
# 2026-07-27, esa defensa tenía tres agujeros, y los tres del mismo tipo — la
# lista y el comando decían cosas que no eran:
#
#   1. El `grep` filtra por `--include="*.toml"` y **`Cargo.lock` no es un
#      `.toml`**, así que no veía las dos entradas que sí tiene — siendo el
#      punto 2 de su propia lista.
#   2. `pyproject.toml` figuraba en la lista y usa `dynamic = ["version"]`: no
#      contiene ninguna versión. Sobraba.
#   3. `integrations/express/package.json` figuraba como si llevara la versión
#      de Quipu, y lo que lleva es un RANGO DE DEPENDENCIA (`^0.9.1`); su propia
#      versión es otra (0.1.0). Son dos cosas distintas que la lista mezclaba.
#
# Así que aquí no hay lista en prosa: hay un registro con un extractor por
# sitio, que dice DÓNDE vive la versión en cada archivo. Y dos categorías, que
# no se comprueban igual:
#
#   - PROPIA: es la versión de Quipu. Debe ser idéntica a la de `Cargo.toml`.
#   - REFERENCIA: la nombra en documentación o en un rango de dependencia.
#     Debe mencionarla; si nombra otra, es documentación caducada.
#
# Los manifiestos se leen con `tomllib` y `json`, ESTRUCTURALMENTE. Un `grep` no
# vale: `Cargo.lock` contiene `version = "0.9.1"` para `aes` y para `poly1305`,
# que no tienen nada que ver con Quipu. Buscar la cadena encuentra vecinos.
#
# Y al final hay un BARRIDO: cualquier archivo versionado en git que contenga la
# versión y no esté en el registro se reporta. Sin eso, el registro envejecería
# igual que la lista a la que sustituye — un archivo nuevo entraría sin que
# nadie lo vigilara, que es exactamente cómo se llegó hasta aquí.

# Archivos que legítimamente nombran muchas versiones y no deben vigilarse.
_BARRIDO_EXENTO = {
    "CHANGELOG.md",           # documenta todas las versiones, esa es su función
    "Cargo.lock",             # ya cubierto, entrada por entrada, más arriba
    "supply-chain/config.toml",  # ídem: la autoexención está en el registro
    "supply-chain/imports.lock",
}


def _toml_relativo(rel: str) -> dict:
    """Igual que `_leer_toml`, pero tomando una ruta RELATIVA a la raíz.

    Existe aparte y con otro nombre a propósito: la primera versión de esto se
    llamaba también `_leer_toml` y, por definirse más abajo en el archivo,
    SUSTITUÍA a la otra en silencio. Python no avisa de eso. Dos funciones con
    el mismo nombre y distinta firma en el mismo módulo es un fallo esperando
    a que alguien cambie una de las dos.
    """
    return _leer_toml(RAIZ / rel)


def _version_de_referencia() -> str:
    """La versión de Quipu, tal como la declara su `Cargo.toml`. La fuente."""
    return _toml_relativo("Cargo.toml")["package"]["version"]


def _sitios_de_version(v: str) -> list[tuple[str, str, str, object]]:
    """(archivo, qué sitio, categoría, valor-encontrado-o-None).

    Cada extractor sabe dónde mirar. `None` significa «el sitio ya no existe»,
    que es distinto de «tiene otra versión» y se reporta distinto: un archivo
    que dejó de llevar la versión puede ser un cambio legítimo o un despiste, y
    en ambos casos hay que enterarse.
    """
    import tomllib

    sitios: list[tuple[str, str, str, object]] = []

    def toml_pkg(rel: str) -> object:
        try:
            return _toml_relativo(rel)["package"]["version"]
        except Exception:
            return None

    def json_clave(rel: str, *claves: str) -> object:
        try:
            d = json.loads((RAIZ / rel).read_text(encoding="utf-8"))
            for c in claves:
                d = d[c]
            return d
        except Exception:
            return None

    def texto_contiene(rel: str, aguja: str) -> object:
        try:
            return aguja if aguja in (RAIZ / rel).read_text(encoding="utf-8") else "(no aparece)"
        except Exception:
            return None

    # --- la versión propia de Quipu -----------------------------------------
    sitios.append(("Cargo.toml", "[package] version", "propia", toml_pkg("Cargo.toml")))

    # Cargo.lock: por BLOQUE, nunca por búsqueda de la cadena.
    try:
        with open(RAIZ / "Cargo.lock", "rb") as f:
            lock = tomllib.load(f)
        por_nombre = {p["name"]: p.get("version") for p in lock.get("package", [])}
        for crate in ("quipu",):
            sitios.append(("Cargo.lock", f'[[package]] {crate}', "propia", por_nombre.get(crate)))
    except Exception:
        sitios.append(("Cargo.lock", "ilegible", "propia", None))


    # La autoexención de cargo-vet: si no se sube, el check del CI falla.
    try:
        cfg = _toml_relativo("supply-chain/config.toml")
        ex = cfg.get("exemptions", {}).get("quipu", [])
        sitios.append(
            ("supply-chain/config.toml", "[[exemptions.quipu]]", "propia",
             ex[0].get("version") if ex else None)
        )
    except Exception:
        sitios.append(("supply-chain/config.toml", "[[exemptions.quipu]]", "propia", None))

    # --- documentación y rangos que la NOMBRAN -------------------------------
    sitios.append(("SECURITY.md", f"`v{v}`", "referencia", texto_contiene("SECURITY.md", f"v{v}")))
    # La cabecera de la especificación. Entra en el registro el 2026-08-05, el
    # mismo día en que se corrigió: decía «through v0.6.0» con el crate en
    # 0.11.0, y el cuerpo llevaba cinco secciones de formatos posteriores. Lo
    # caducado era el banner, que es lo primero que lee quien llega de docs.rs.
    #
    # Se REGISTRA en vez de quitarle la versión, y esa es la decisión: un
    # documento que dice hasta dónde cubre vale más que uno que no lo dice, pero
    # solo si algo lo obliga a envejecer con el resto. Sin esta línea vuelve a
    # quedarse atrás al primer salto, y en silencio — que es como llegó a v0.6.0.
    sitios.append(("docs/SPEC.md", f"`v{v}` (cabecera)", "referencia", texto_contiene("docs/SPEC.md", f"v{v}")))
    return sitios


def _nombres_de_dependencias() -> set[str]:
    """Nombres de crates del `Cargo.lock` que NO son de Quipu.

    Son la referencia DURA para saber si un «0.9.1» suelto en un texto es la
    versión de una dependencia (aes, poly1305, ml-kem…) o la de Quipu. Se leen
    del grafo real, no se adivina por la forma: así «release 0.10.0» —que no es
    un crate— sigue contando como versión de Quipu, y «aes 0.9.1» no.
    """
    try:
        import tomllib
        with open(RAIZ / "Cargo.lock", "rb") as f:
            lock = tomllib.load(f)
    except (OSError, ValueError, ModuleNotFoundError):
        return set()
    return {
        p["name"].lower()
        for p in lock.get("package", [])
        if isinstance(p.get("name"), str) and not p["name"].startswith("quipu")
    }


_SEP_VERSION = re.compile(r'[\s="@:^~<>\-]+$')
_TOKEN_FINAL = re.compile(r'([A-Za-z][A-Za-z0-9_-]*)$')

# Marcas que convierten la versión en una REFERENCIA HISTÓRICA, no en una
# declaración: «público desde la 0.10.0» dice cuándo pasó algo, no qué versión
# es esta. Un archivo así NO hay que actualizarlo al subir de versión — hacerlo
# falsearía la historia.
#
# Es el tercer punto ciego del barrido, y el mismo error que los dos anteriores
# con otro disfraz: marcaba `docs/SPEC.md` por la frase «has been public and
# settable through `Options` since 0.10.0». La salvaguarda tenía razón en que
# ahí había un «0.10.0» y se equivocaba en lo que significaba.
#
# LA LISTA ES CORTA A PROPÓSITO. Solo entran marcas INEQUÍVOCAS. Se dejaron
# fuera «in» y «en» —«el fallo en 0.10.0» es histórico, pero «la versión en
# 0.10.0» no— porque para una salvaguarda la duda se resuelve señalando
# (directiva 21): un falso positivo cuesta una mirada, un falso negativo deja la
# versión atrás en silencio.
_MARCA_HISTORICA = re.compile(
    r"(?:since|desde(?:\s+la)?|a\s+partir\s+de(?:\s+la)?|hasta(?:\s+la)?|until|"
    r"introducid[oa]\s+en(?:\s+la)?|añadid[oa]\s+en(?:\s+la)?|added\s+in|"
    r"removed\s+in|retirad[oa]\s+en(?:\s+la)?|deprecated\s+in)\s+v?$",
    re.IGNORECASE,
)


def _version_a_espaldas(texto: str, v: str, deps: set[str]) -> bool:
    """¿`texto` nombra `v` COMO VERSIÓN DE QUIPU (no de una dependencia)?

    Devuelve True si hay al menos una aparición de `v` que NO está pegada al
    nombre de una dependencia conocida (`aes 0.9.1`, `aes = "0.9.1"`, `aes-0.9.1`,
    `aes@0.9.1`…). Una aparición sin ese contexto cuenta como versión de Quipu:
    para una salvaguarda, la duda se resuelve señalando, no callando
    (directiva 21).

    Es el punto ciego 2 de la tarea #138: el barrido marcaba
    `docs/ATAQUES_TAXONOMIA.md` por contener «aes 0.9.1» como si 0.9.1 fuera la
    versión de Quipu — la MISMA trampa que el grep original ya documentaba
    («Cargo.lock tiene 0.9.1 para aes y poly1305, que no son de Quipu»),
    reaparecida dentro de la herramienta que vino a sustituirlo. Se arregla en la
    REGLA, no exentando el archivo (directiva 23): el falso positivo volvería con
    la próxima dependencia que se documente.

    El límite `(?<![\\d.]) … (?![\\d.])` evita que «0.9.1» case dentro de
    «0.9.10» o «10.9.1».
    """
    patron = re.compile(r"(?<![\d.])" + re.escape(v) + r"(?![\d.])")
    for m in patron.finditer(texto):
        izquierda = texto[max(0, m.start() - 40):m.start()]
        if _MARCA_HISTORICA.search(izquierda):
            continue  # «desde la 0.10.0»: dice cuándo, no cuál. No se actualiza.
        cola = _SEP_VERSION.sub("", izquierda)
        mtok = _TOKEN_FINAL.search(cola)
        nombre = mtok.group(1).lower() if mtok else ""
        if nombre in deps:
            continue  # esta aparición es la versión de esa dependencia
        return True   # aparición sin coartada: cuenta como versión de Quipu
    return False      # o no aparece, o todas son de dependencias


def verificar_versiones(inf: Informe) -> None:
    """Todos los sitios que llevan la versión llevan LA MISMA."""
    try:
        v = _version_de_referencia()
    except Exception as e:
        inf.omitido("coherencia de versiones", f"no se pudo leer Cargo.toml: {e}")
        return

    descuadres, ausentes = [], []
    for archivo, sitio, categoria, valor in _sitios_de_version(v):
        if valor is None:
            ausentes.append(f"{archivo} ({sitio})")
        elif categoria == "propia":
            if valor != v:
                descuadres.append(f"{archivo} ({sitio}) = {valor}, se esperaba {v}")
        else:  # referencia: basta con que la nombre
            if v not in str(valor):
                descuadres.append(f"{archivo} ({sitio}) = {valor!r}, no menciona {v}")

    n = len(_sitios_de_version(v))
    if descuadres:
        inf.fallo(
            f"coherencia de versiones ({v})",
            "; ".join(descuadres) + " — etiquetar así publica artefactos que no concuerdan",
        )
    else:
        inf.ok(f"los {n} sitios de versión concuerdan en {v}")

    if ausentes:
        inf.omitido(
            "sitios de versión que ya no existen",
            "; ".join(ausentes) + " — o el archivo cambió de forma, o se perdió la versión",
        )

    # --- barrido: ¿hay algún archivo con la versión que nadie vigila? --------
    #
    # LOS DOS PUNTOS CIEGOS QUE TUVO ESTE BARRIDO Y CÓMO SE CIERRAN (tarea #138):
    #
    # 1. SOLO VE LO RASTREADO POR GIT. Un archivo ignorado —CLAUDE.md, las
    #    skills— puede llevar la versión y quedarse atrás en un salto sin que
    #    esto lo vea. NO se escanean a ciegas: llevan versiones AJENAS en prosa
    #    (dependencias, Python, plugins) que dispararían falsos positivos, y un
    #    escaneo que se equivoca es una salvaguarda que hay que desactivar
    #    —justo lo que la directiva 23 prohíbe—. Se DECLARA el alcance para que
    #    el silencio no se lea como «comprobado»: lo ignorado se revisa a mano al
    #    subir de versión. El registro cubre lo VERSIONADO, y ahora lo dice.
    #
    # 2. NO DISTINGUÍA DE QUIÉN ES LA VERSIÓN: «aes 0.9.1» marcaba el archivo
    #    aunque 0.9.1 fuera de una dependencia. Ahora `_version_a_espaldas`
    #    contrasta el contexto contra Cargo.lock y solo cuenta lo que es de Quipu.
    cod, salida = correr(["git", "ls-files"], cwd=RAIZ, timeout=60)
    if cod != 0:
        inf.omitido("barrido de archivos no vigilados", "git ls-files no respondió")
        return
    deps = _nombres_de_dependencias()
    if not deps:
        inf.omitido(
            "barrido de archivos no vigilados",
            "no se pudo leer Cargo.lock: sin el grafo de dependencias el barrido no "
            "puede distinguir la versión de Quipu de la de un paquete ajeno",
        )
        return
    vigilados = {a for a, _, _, _ in _sitios_de_version(v)} | _BARRIDO_EXENTO
    sueltos, rastreados = [], 0
    for rel in salida.splitlines():
        rel = rel.strip()
        if not rel or rel in vigilados:
            continue
        if not rel.endswith((".toml", ".json", ".md", ".yml", ".yaml", ".cfg", ".txt")):
            continue
        rastreados += 1
        try:
            texto = (RAIZ / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _version_a_espaldas(texto, v, deps):
            sueltos.append(rel)
    alcance = (
        f"{rastreados} archivos rastreados revisados — los IGNORADOS por git "
        "(CLAUDE.md, .claude/skills) quedan fuera: revísalos a mano al subir de versión"
    )
    if sueltos:
        inf.fallo(
            "archivos con la versión de Quipu que NADIE vigila",
            ", ".join(sueltos) + " — añádelos al registro de `_sitios_de_version` o el "
            "próximo salto de versión los dejará atrás en silencio",
        )
    else:
        inf.ok("ningún archivo rastreado lleva la versión de Quipu a espaldas del registro",
               alcance)


# =========================== la portada no promete de más ======================
#
# El campo `description` de un manifiesto es lo que se publica en crates.io y en
# PyPI: es la PORTADA, lo primero que lee quien evalúa la librería. Y es lo que
# más veces se ha quedado atrás:
#
#   - `quipu-cnsa` anunciaba ML-KEM-1024 sin implementarlo (corregido en b767341,
#     con una prueba propia dentro del crate).
#   - `quipu`, `quipu-nucleo` y `pyproject.toml` seguían anunciando «canal visual
#     de glifos» DESPUÉS de que los PR #93 y #99 lo eliminaran entero. Tres
#     manifiestos, uno de ellos el de PyPI, prometiendo un subsistema borrado.
#
# La forma de comprobarlo no puede ser una lista de palabras prohibidas: esa
# lista habría que acordarse de ampliarla cada vez que se quite algo, y
# acordarse es justo lo que falla. Se comprueba al revés y se DERIVA: si una
# descripción nombra un subsistema, ese subsistema tiene que existir en el
# código. Cuando se borra el código, la comprobación se pone roja sola.
_SUBSISTEMAS = {
    # término en la portada -> señales de que existe de verdad en el árbol
    "glifo": ["glyphfont", "glyphopt", "glyphscan", "encode_to_glyph_image"],
    "canal visual": ["fn bytes_to_png", "encode_to_image", "glyphfont"],
    "PNG": ["fn bytes_to_png", "encode_to_image"],
    "honey": ["fn encrypt_pin", "mod honey"],
    "VOPRF": ["fn blind_evaluate", "mod voprf", "pub use quipu_voprf"],
    "ML-KEM": ["ml_kem", "ml-kem", "MlKem1024"],
    "ML-DSA": ["ml_dsa", "ml-dsa", "MlDsa87"],
    "Reed-Solomon": ["reed_solomon", "mod ecc"],
    "Shamir": ["mod shamir", "fn split_secret"],
}

_MANIFIESTOS = [
    "Cargo.toml",
    "pyproject.toml",
    "crates/quipu-nucleo/Cargo.toml",
    "crates/quipu-cnsa/Cargo.toml",
    "crates/quipu-voprf/Cargo.toml",
]


def _fuente_del_arbol() -> str:
    """Todo el Rust del árbol, para preguntarle si algo existe."""
    trozos = []
    for base in ("src", "crates"):
        raiz = RAIZ / base
        if not raiz.is_dir():
            continue
        for ruta in raiz.rglob("*.rs"):
            if "target" in ruta.parts:
                continue
            try:
                trozos.append(ruta.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                pass
    return "\n".join(trozos)


def verificar_promesas_de_la_portada(inf: Informe) -> None:
    """Lo que la `description` publicada nombra, tiene que estar en el código."""
    fuente = _fuente_del_arbol()
    if len(fuente) < 10_000:
        inf.omitido("promesas de la portada", "no se pudo leer el árbol de fuentes")
        return

    mentiras = []
    revisados = 0
    for rel in _MANIFIESTOS:
        ruta = RAIZ / rel
        if not ruta.exists():
            continue
        descripcion = ""
        for linea in ruta.read_text(encoding="utf-8").splitlines():
            if linea.lstrip().startswith("description"):
                descripcion = linea
                break
        if not descripcion:
            continue
        revisados += 1
        bajo = descripcion.lower()
        for termino, señales in _SUBSISTEMAS.items():
            if termino.lower() not in bajo:
                continue
            if not any(s in fuente for s in señales):
                mentiras.append(f"{rel} anuncia «{termino}» y no está en el código")

    if mentiras:
        inf.fallo(
            "la portada promete lo que el código no tiene",
            "; ".join(mentiras) + " — es el texto que se publica en crates.io y PyPI",
        )
    else:
        inf.ok(f"las descripciones de {revisados} manifiestos solo prometen lo que existe")


def verificar_coherencia_de_features(inf: Informe) -> None:
    """`release.yml` no debe REPETIR la lista de features de `pyproject.toml`.

    Mientras exista en dos sitios pueden divergir, y divergieron: la 0.9.0 salió
    a PyPI sin `hsm`. Lo correcto es que `release.yml` la lea. Hasta que eso
    esté hecho, al menos que la divergencia se detecte.
    """
    release = RAIZ / ".github" / "workflows" / "release.yml"
    if not release.exists():
        inf.omitido("features de la rueda en un solo sitio", "no existe release.yml")
        return
    declaradas = features_de_la_rueda()

    # Solo cuentan las banderas ACTIVAS: las que están dentro de un `args:`.
    # Buscar `--features` en el texto crudo daba un falso positivo en cuanto un
    # comentario explicaba por qué la bandera ya NO está — el mismo error que
    # cometió el exportador de PENDIENTES.md al tragarse su propia cabecera.
    # Cuando un archivo se documenta a sí mismo, hay que distinguir la
    # descripción del dato.
    activas = [
        linea.strip()
        for linea in release.read_text(encoding="utf-8").splitlines()
        if linea.lstrip().startswith("args:") and "--features" in linea
    ]
    if not activas:
        inf.ok(
            "features de la rueda en un solo sitio",
            "release.yml no las repite: maturin las lee de pyproject.toml",
        )
        return

    repetidas = [f for f in declaradas if any(f in a for a in activas)]
    inf.fallo(
        "features de la rueda en un solo sitio",
        f"release.yml todavía las repite ({', '.join(repetidas) or 'con --features'}): "
        "quita la bandera y deja que maturin lea pyproject.toml",
    )


# --------------------------------------------------------------------------
# pr
# --------------------------------------------------------------------------

def verificar_pr(inf: Informe, numero: int) -> None:
    """Estado de los checks de un PR.

    OJO con dos trampas comprobadas en gh 2.46:
      - `gh pr checks --json` NO EXISTE. La consulta buena es
        `gh pr view --json statusCheckRollup`.
      - mientras el check corre, `conclusion` es la CADENA VACÍA, no `null`.
        El operador `//` de jq no cae al alternativo con cadena vacía, así que
        un check en marcha parecía terminado. Hay que mirar `status`.
    """
    if not hay("gh"):
        inf.omitido(f"checks del PR #{numero}", "gh no está instalado")
        return
    codigo, salida = correr(
        ["gh", "pr", "view", str(numero), "--json", "statusCheckRollup,headRefOid"]
    )
    if codigo != 0:
        inf.omitido(f"checks del PR #{numero}", salida.strip()[:120])
        return
    datos = json.loads(salida)
    checks = datos.get("statusCheckRollup") or []
    if not checks:
        inf.omitido(f"checks del PR #{numero}", "todavía no hay checks registrados")
        return

    corriendo = [c for c in checks if c.get("status") != "COMPLETED"]
    fallidos = [c for c in checks if c.get("conclusion") not in ("SUCCESS", "NEUTRAL", "SKIPPED", "")]
    fallidos = [c for c in fallidos if c.get("status") == "COMPLETED"]

    if corriendo:
        inf.omitido(
            f"checks del PR #{numero}",
            f"{len(corriendo)} sin terminar: " + ", ".join(c["name"] for c in corriendo[:3]),
        )
    for c in fallidos:
        inf.fallo(f"check «{c['name']}»", c.get("conclusion") or "sin conclusión")
    if not corriendo and not fallidos:
        inf.ok(
            f"checks del PR #{numero}",
            f"{len(checks)}/{len(checks)} en verde · {datos.get('headRefOid','')[:8]}",
        )


# ===========================================================================
# PROMOCIÓN ENTRE RAMAS — el robot que Debian sí tiene
# ===========================================================================
#
# El modelo de tres ramas (`docs/RAMAS.md`) vale lo que valga su promoción. En
# Debian, quien migra paquetes de `unstable` a `testing` es un ROBOT con reglas:
# diez días sin fallos críticos, dependencias satisfacibles. Sin ese robot,
# `testing` es solo una rama que alguien tiene que acordarse de fusionar — y
# acordarse no escala, que es la lección que este archivo entero documenta.
#
# Esto es ese robot. No fusiona: las ramas están protegidas y saltárselo siendo
# administrador es justo lo que rompe el CI. Lo que hace es NEGARSE, y solo
# cuando no tiene motivo para negarse, abrir el PR.
#
# Se niega también si algo quedó SIN COMPROBAR. Meter lo no verificado en el
# montón de lo aprobado es el defecto que esta herramienta existe para impedir.

_DESTINOS = {
    "testing": {
        "desde": None,  # cualquier rama de trabajo
        "porque": "candidata a la próxima versión: integrada y verde",
    },
    "estable": {
        "desde": "testing",  # a estable solo se llega por testing
        "porque": "lo publicado: de aquí salen los tags, y poner un tag ES publicar",
    },
}


def _rama_actual() -> str | None:
    cod, salida = correr(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=RAIZ, timeout=30)
    return salida.strip() if cod == 0 else None


# --------------------------------------------------------------------------
# Los crates HERMANOS: su versión NO puede ir por detrás de crates.io.
# --------------------------------------------------------------------------
#
# El fallo que esto caza vive ENTRE dos árboles, y por eso ningún check de rama
# lo veía. Medido el 2026-08-02: `estable` llevaba `quipu-nucleo` 0.1.1 —y
# crates.io también— mientras `testing` seguía en 0.1.0. Dentro de `testing` ese
# 0.1.0 es perfectamente coherente consigo mismo, así que «coherencia de
# versiones» lo aprobaba; y esta misma función solo contrastaba contra PyPI la
# versión del paquete RAÍZ, así que la promoción también lo aprobaba. Dos
# guardianes en verde y una promoción que no se puede publicar.
#
# LA REGLA, escrita en una frase para poder auditarla: se rechaza que la versión
# del árbol sea MENOR que la mayor publicada. Nada más.
#
# Lo que NO se rechaza, y es deliberado (directiva 21: se rechaza lo imposible,
# nunca lo inusual): que sean IGUALES. Un release que toca `quipu` y no toca
# `quipu-nucleo` deja el hermano en su número publicado y no lo republica —es la
# operación normal, no un error—. Exigir «estrictamente mayor» convertiría cada
# release en un bump obligatorio de los cinco crates, que es justo el cliente
# legítimo contra el que hay que probar toda regla antes de escribirla.

def verificar_exenciones_de_vet(inf: Informe) -> None:
    """La exención de `cargo-vet` de cada miembro tiene que nombrar SU versión.

    POR QUÉ EXISTE: `cargo vet` exime crates POR VERSIÓN exacta. Al subir un
    miembro —`quipu-nucleo` a 0.1.2, `quipu-voprf` a 0.2.3— la exención se queda
    apuntando a la anterior y el check `cargo-vet (supply chain)` se pone ROJO
    con «missing safe-to-deploy». Pasó el 2026-08-03 y lo cazó el CI, o sea
    tarde: la coherencia de versiones ya miraba los cuatro sitios de `quipu`,
    pero ninguno era este ni cubría a los hermanos.

    LA REGLA, en una frase: si un miembro del workspace TIENE exención, su
    versión tiene que ser la del miembro. No exige que la tenga —un crate
    auditado de verdad no necesita exención, y obligar a ponerla sería premiar lo
    peor—; solo que si está, no mienta.
    """
    ruta = RAIZ / "supply-chain" / "config.toml"
    if not ruta.exists():
        inf.omitido("exenciones de cargo-vet", "no hay supply-chain/config.toml")
        return
    try:
        exenciones = _leer_toml(ruta).get("exemptions", {})
        miembros = _miembros_publicables()
        raiz = _leer_toml(RAIZ / "Cargo.toml")["package"]
        miembros.append((raiz["name"], raiz["version"], "."))
    except Exception as e:
        inf.omitido("exenciones de cargo-vet", f"no se pudo leer: {e}")
        return

    desfasadas = []
    revisadas = 0
    for nombre, version, _ in miembros:
        entradas = exenciones.get(nombre)
        if not entradas:
            continue  # sin exención: no hay nada que pueda mentir
        revisadas += 1
        versiones = [e.get("version") for e in entradas if isinstance(e, dict)]
        if version not in versiones:
            desfasadas.append(f"{nombre}: el árbol va por {version} y la exención dice {versiones}")

    if desfasadas:
        inf.fallo(
            "exenciones de cargo-vet al día",
            "; ".join(desfasadas)
            + " — `cargo vet` exime por versión EXACTA, así que el check se pondrá "
            "rojo: actualiza supply-chain/config.toml",
        )
    elif revisadas:
        inf.ok("exenciones de cargo-vet al día", f"{revisadas} miembro(s) con exención, y concuerdan")
    else:
        inf.omitido(
            "exenciones de cargo-vet",
            "ningún miembro del workspace tiene exención: no hay nada que contrastar",
        )


def _miembros_publicables() -> list[tuple[str, str, str]]:
    """(nombre, versión, ruta) de cada miembro del workspace que SÍ se publica.

    Se LEEN de `[workspace] members`, no se enumeran aquí: una lista escrita a
    mano es una lista que diverge el día que nazca el sexto crate — y este
    archivo ya documenta esa lección tres veces.
    """
    raiz = _leer_toml(RAIZ / "Cargo.toml")
    salida: list[tuple[str, str, str]] = []
    for rel in raiz.get("workspace", {}).get("members", []):
        if rel == ".":
            continue  # el paquete raíz lo cubre `_version_de_referencia`
        pkg = _leer_toml(RAIZ / rel / "Cargo.toml").get("package", {})
        if pkg.get("publish") is False:
            continue
        salida.append((pkg["name"], pkg["version"], rel))
    return salida


def _semver(v: str) -> tuple[int, int, int, int] | None:
    """(mayor, menor, parche, 1 si es final / 0 si es prelanzamiento). `None` si
    no se puede ordenar con certeza.

    ESTA FUNCIÓN ESTUVO ESCRITA DOS VECES, y por eso está así de comentada.
    Dos guardianes nacidos con un día de diferencia —`verificar_versiones_no_
    retroceden` (1 ago) y `verificar_versiones_de_miembros` (2 ago)— trajeron
    cada uno su `_semver` al mismo archivo, con contratos INCOMPATIBLES: una
    devolvía una tupla de longitud variable o `None`, la otra una de cuatro
    elementos que reventaba con `ValueError`. En Python la segunda definición
    tapa a la primera SIN UN AVISO, así que al fusionar las dos ramas uno de los
    dos guardianes habría pasado a llamar a una función que no era la suya:
    `(0,1,1) < (0,1,1,1)` es `True`, o sea que la MISMA versión se habría leído
    como «va por detrás» y habría suspendido una promoción legítima.

    Unificadas el 2026-08-03 quedándose con lo mejor de cada una: el cuarto
    elemento de la de 4 (ordena el prelanzamiento) y el `None` de la de 3 (no
    inventar orden). Ese `None` es lo importante — **comparar mal es peor que no
    comparar**, y el llamante lo convierte en SIN COMPROBAR, nunca en aprobado
    (directiva 20).

    Lo que SÍ ordena:
      `0.1` → (0,1,0,1)          se rellena: cargo trata «0.1» como 0.1.0
      `0.2.0` → (0,2,0,1)
      `0.2.0-rc.1` → (0,2,0,0)   antes que `0.2.0`, que es lo que dice semver
      `1.0.0+deadbeef` → (1,0,0,1)  el metadato de construcción NO cuenta para
                                    la precedencia; lo dice la propia norma
    Lo que devuelve `None` en vez de adivinar:
      `0.1.x`, `dev`, ``          no es numérica
      `1.2.3.4`                   cuatro componentes no son semver

    LÍMITE DECLARADO: dos prelanzamientos del mismo núcleo salen IGUALES
    —`0.2.0-rc.1` y `0.2.0-rc.2` son ambos (0,2,0,0)—. No hace falta resolverlo
    en ninguno de los dos usos, y ordenar identificadores de prelanzamiento bien
    (numéricos antes que alfanuméricos, campo a campo) es más norma de la que
    aquí se necesita. Se dice en vez de fingir que se ordenan.
    """
    sin_build, _, _ = v.strip().partition("+")
    nucleo, _, pre = sin_build.partition("-")
    partes = nucleo.split(".")
    if not (1 <= len(partes) <= 3) or not all(p.isdigit() for p in partes):
        return None
    partes = (partes + ["0", "0"])[:3]
    return (*(int(p) for p in partes), 0 if pre else 1)  # type: ignore[return-value]


def verificar_versiones_de_miembros(inf: Informe) -> None:
    """Ningún crate hermano puede llevar una versión ya superada en crates.io."""
    try:
        miembros = _miembros_publicables()
    except Exception as e:
        inf.omitido("versiones de los crates hermanos", f"no se pudo leer el workspace: {e}")
        return
    if not miembros:
        inf.omitido(
            "versiones de los crates hermanos",
            "el workspace no declaró ninguno: eso NO es un aprobado",
        )
        return

    for nombre, version, rel in miembros:
        estado, datos = leer_json_estado(
            f"https://crates.io/api/v1/crates/{nombre}/versions"
        )
        if estado == "ausente":
            inf.ok(f"{nombre} {version}", "todavía no está en crates.io: nada que superar")
            continue
        if estado != "ok":
            inf.omitido(
                f"versión de {nombre}",
                "crates.io no respondió: sin ese dato no se puede promover",
            )
            continue
        nums = [
            v["num"] for v in (datos or {}).get("versions", []) if not v.get("yanked")
        ]
        if not nums:
            inf.ok(f"{nombre} {version}", "sin versiones vivas en crates.io")
            continue
        propia = _semver(version)
        if propia is None:
            inf.omitido(
                f"versión de {nombre}",
                f"«{version}» no se puede ordenar, y no se inventa un orden para "
                "ella: mírala a mano antes de promover",
            )
            continue

        # Las del índice que no se puedan ordenar se APARTAN y se DICEN. Dejarlas
        # caer en silencio convertiría «no pude leer una» en «no había ninguna
        # mayor», que es un aprobado por ausencia de datos.
        ordenables = [(n, _semver(n)) for n in nums]
        ilegibles = [n for n, s in ordenables if s is None]
        comparables = [(n, s) for n, s in ordenables if s is not None]
        if ilegibles:
            inf.omitido(
                f"versiones de {nombre} que no se pudieron ordenar",
                ", ".join(sorted(ilegibles)) + " — quedan fuera de la comparación",
            )
        if not comparables:
            inf.omitido(
                f"versión de {nombre}",
                "ninguna versión del índice se pudo ordenar: eso NO es un aprobado",
            )
            continue

        mayor, s_mayor = max(comparables, key=lambda par: par[1])
        atrasada = propia < s_mayor
        if atrasada:
            inf.fallo(
                f"{nombre} {version} va POR DETRÁS de crates.io ({mayor})",
                f"{rel}/Cargo.toml quedó en un número ya publicado — súbelo por "
                f"encima de {mayor} o esta promoción no se puede publicar",
            )
        else:
            inf.ok(
                f"{nombre} {version}",
                "no va por detrás de crates.io"
                + ("" if version != mayor else f" (igual a la publicada {mayor}: no se republica)"),
            )


# --------------------------------------------------------------------------
# Retroceso ENTRE RAMAS: el mismo fallo, medido sin salir a la red.
# --------------------------------------------------------------------------
#
# `verificar_versiones_de_miembros` compara el ÁRBOL contra CRATES.IO.
# Esto compara el ÁRBOL contra LA RAMA DESTINO. Parecen lo mismo y no lo son, y
# por eso conviven en vez de que uno sustituya al otro:
#
#   · el de crates.io ve lo que de verdad está publicado —incluido lo que
#     alguien subió a mano sin que ninguna rama lo refleje—, pero necesita red y
#     se calla si el índice no responde;
#   · este ve la relación entre las dos ramas sin preguntarle a nadie, así que
#     no se pone rojo porque un índice esté caído, y caza el caso que al otro se
#     le escapa: `estable` puede llevar una versión que todavía no llegó al
#     índice (release en vuelo) y promover por encima la despublicaría igual.
#
# Cubren fallos distintos con la misma forma. Lo que NO puede haber es dos
# maneras de ordenar versiones: eso era el choque, y se resolvió en `_semver`.
#
# EL CASO REAL: el 2026-08-01 `testing` llevaba cuatro días con
# `quipu-nucleo 0.1.0` mientras `estable` ya publicaba la 0.1.1. Promover así
# habría devuelto el crate a la versión anterior en silencio, y ningún check lo
# veía — `verificar_versiones` mira los cuatro sitios de la versión de `quipu`,
# que estaban perfectamente coherentes consigo mismos EN LAS DOS RAMAS. El fallo
# no vive en un árbol: vive ENTRE DOS, y ningún examen de uno solo puede verlo
# por minucioso que sea.


def _toml_de_texto(texto: str) -> dict:
    """El mismo TOML que `_leer_toml`, pero desde una cadena (viene de `git show`)."""
    try:
        import tomllib
    except ModuleNotFoundError as e:  # Python < 3.11
        raise SystemExit(
            "verificar.py necesita Python 3.11+ (tomllib) para leer los "
            "manifiestos."
        ) from e
    return tomllib.loads(texto)


def _versiones_de_los_crates(ref: str) -> dict[str, str] | None:
    """`{nombre: versión}` de los miembros del workspace TAL COMO ESTÁN en `ref`.

    Lee del árbol de git, no del disco: la pregunta es qué versiones lleva esa
    rama, y el disco solo sabe de la actual. La lista de miembros se toma también
    del ref, porque un crate puede haber nacido o desaparecido entre las dos
    ramas — `padme-frame` nació el 2026-08-01 y no existe en `estable`.

    `None` cuando no se pudo leer el ref: es «no pude mirar», que el llamante
    convierte en SIN COMPROBAR y jamás en aprobado.
    """
    cod, raiz = correr(["git", "show", f"{ref}:Cargo.toml"], cwd=RAIZ, timeout=60)
    if cod != 0:
        return None
    try:
        miembros = _toml_de_texto(raiz)["workspace"]["members"]
    except Exception:
        return None

    versiones: dict[str, str] = {}
    for m in miembros:
        rel = "Cargo.toml" if m == "." else f"{m}/Cargo.toml"
        cod, texto = correr(["git", "show", f"{ref}:{rel}"], cwd=RAIZ, timeout=60)
        if cod != 0:
            continue
        try:
            pkg = _toml_de_texto(texto)["package"]
        except Exception:
            continue
        if "name" in pkg and "version" in pkg:
            versiones[pkg["name"]] = pkg["version"]
    return versiones


def _copia_de_origin_al_dia(ref: str) -> tuple[bool | None, str]:
    """¿`origin/<rama>` en el disco coincide con lo que el remoto tiene AHORA?

    Existe porque este archivo no hace `fetch` en ningún momento, y comparar
    contra una copia vieja de `origin/estable` daría un APROBADO EN SILENCIO —
    justo la forma de fallo que el guardián viene a impedir. Una consulta barata
    (`git ls-remote`, sin descargar objetos) convierte «mi copia está vieja» en
    algo que se dice, en vez de en un verde inmerecido.

    Devuelve `(None, motivo)` cuando no se pudo preguntar: no saber no es estar
    al día.
    """
    if not ref.startswith("origin/"):
        return True, "ref local: no hay copia remota que contrastar"
    rama = ref[len("origin/"):]
    cod, local = correr(["git", "rev-parse", ref], cwd=RAIZ, timeout=60)
    if cod != 0:
        return None, f"no existe {ref} en el disco: haz `git fetch origin {rama}`"
    cod, remoto = correr(["git", "ls-remote", "--heads", "origin", rama], cwd=RAIZ, timeout=120)
    if cod != 0 or not remoto.strip():
        return None, f"el remoto no respondió por «{rama}»"
    if remoto.split()[0].strip() != local.strip():
        return False, (
            f"tu {ref} está desactualizada respecto del remoto — "
            f"`git fetch origin {rama}` antes de fiarte de esta comparación"
        )
    return True, f"{ref} coincide con el remoto"


def verificar_versiones_no_retroceden(inf: Informe, origen: str, destino: str) -> None:
    """Ningún crate del workspace puede llevar en `origen` una versión INFERIOR a
    la que ya lleva `destino`.

    Que sean IGUALES no suspende, y es deliberado (directiva 21): un release que
    toca `quipu` y no toca `quipu-nucleo` deja al hermano en su número y no lo
    republica. Es la operación normal contra la que hay que probar toda regla
    antes de escribirla; exigir «estrictamente mayor» obligaría a bumpear los
    cinco crates en cada release.
    """
    al_dia, motivo = _copia_de_origin_al_dia(destino)
    if al_dia is not True:
        inf.omitido(
            f"ninguna versión retrocede de {origen} a {destino}",
            motivo + " — comparar contra una copia vieja aprobaría sin mirar",
        )
        return

    de_origen = _versiones_de_los_crates(origen)
    de_destino = _versiones_de_los_crates(destino)
    if de_origen is None or de_destino is None:
        cual = origen if de_origen is None else destino
        inf.omitido(
            "ninguna versión retrocede",
            f"no se pudo leer el workspace de «{cual}» — sin las dos ramas la "
            "comparación no se puede hacer",
        )
        return

    retrocesos, sin_comparar = [], []
    for crate, vd in sorted(de_destino.items()):
        vo = de_origen.get(crate)
        if vo is None:
            # Un crate que el origen ya no tiene es un borrado deliberado, no un
            # retroceso de versión. Lo mira quien revise el PR.
            continue
        a, b = _semver(vo), _semver(vd)
        if a is None or b is None:
            sin_comparar.append(f"{crate} ({vo} vs {vd})")
        elif a < b:
            retrocesos.append(f"{crate}: {origen} lleva {vo} y {destino} ya tiene {vd}")

    if retrocesos:
        inf.fallo(
            f"ninguna versión retrocede de {origen} a {destino}",
            "; ".join(retrocesos) + " — promover así DESPUBLICA ese release: "
            f"fusiona {destino} en {origen} antes de promover",
        )
    else:
        inf.ok(
            f"ninguna versión retrocede de {origen} a {destino}",
            f"{len(de_destino)} crates comparados",
        )

    if sin_comparar:
        inf.omitido(
            "versiones que no se pudieron ordenar",
            "; ".join(sin_comparar) + " — no se inventa un orden para ellas",
        )


# --------------------------------------------------------------------------
# Deriva desde el tag: cambios que NO llegarán al índice.
# --------------------------------------------------------------------------
#
# `verificar_versiones_de_miembros` caza que el árbol vaya por DEBAJO de
# crates.io. No caza el caso simétrico y más silencioso: que vaya IGUAL y el
# CONTENIDO haya cambiado.
#
# Pasó con `quipu-voprf` el 2026-08-02. El árbol y la 0.2.2 publicada diferían
# en exactamente una línea —el `#![forbid(unsafe_code)]`—, y como crates.io no
# deja re-subir una versión, ese endurecimiento no habría llegado JAMÁS a quien
# hace `cargo add`. Nada estaba roto: el número coincidía, las pruebas pasaban y
# el guardián nuevo lo aprobaba con razón. Simplemente el trabajo se quedaba en
# el disco.
#
# LA REGLA: si existe el tag de la versión que declara el árbol y hay cambios
# entre ese tag y HEAD dentro del crate, el número tiene que subir.
#
# POR QUÉ SOLO AL PROMOVER, y no en cada verificación: durante el desarrollo esa
# diferencia es el estado NORMAL —se trabaja sobre la versión publicada hasta
# que toca subirla—, así que una alarma continua sería falsa todos los días y a
# la tercera nadie la miraría (directiva 23). En la promoción a `estable`, en
# cambio, es exactamente la pregunta que hay que contestar.

# Prefijo de tag por crate. TIENE QUE CONCORDAR con `on.push.tags` de
# `.github/workflows/release.yml`; si no, esto mira un tag que nadie empuja.
_PREFIJO_DE_TAG = {
    "quipu": "v",
    "quipu-voprf": "voprf-v",
    "quipu-nucleo": "nucleo-v",
    "padme-frame": "padme-v",
    "quipu-cnsa": "cnsa-v",
}


def verificar_deriva_desde_el_tag(inf: Informe) -> None:
    """Ningún crate puede llevar cambios sin publicar bajo un número ya usado."""
    if not hay("git"):
        inf.omitido("deriva desde el tag", "git no está instalado")
        return
    try:
        miembros = _miembros_publicables()
    except Exception as e:
        inf.omitido("deriva desde el tag", f"no se pudo leer el workspace: {e}")
        return

    # El paquete raíz no sale de `members`, y es el que más importa.
    #
    # Sus rutas van ACOTADAS a lo que `cargo publish -p quipu` empaqueta. Con un
    # `.` el diff cazaría cualquier cambio del repositorio —un README de otro
    # crate, un workflow— y diría que `quipu` tiene trabajo sin publicar cuando
    # no lo tiene. Una alarma así es peor que ninguna.
    try:
        miembros = [("quipu", _version_de_referencia(), None)] + miembros
    except Exception as e:
        inf.omitido("deriva desde el tag", f"no se pudo leer la versión raíz: {e}")
        return

    for nombre, version, rel in miembros:
        prefijo = _PREFIJO_DE_TAG.get(nombre)
        if prefijo is None:
            # Un crate publicable sin prefijo declarado NO se aprueba en
            # silencio: o se le da tag, o se dice que no se puede mirar.
            inf.omitido(
                f"deriva de {nombre}",
                "no tiene prefijo de tag en `_PREFIJO_DE_TAG` — si es publicable, "
                "necesita uno en release.yml y aquí",
            )
            continue

        tag = f"{prefijo}{version}"
        cod, _ = correr(["git", "rev-parse", "-q", "--verify", f"{tag}^{{}}"], cwd=RAIZ, timeout=30)
        if cod != 0:
            inf.ok(
                f"{nombre} {version}",
                f"el tag {tag} no existe aún: es una versión sin cortar, nada que comparar",
            )
            continue

        rutas = ["src", "Cargo.toml"] if rel is None else [rel]
        cod, salida = correr(
            ["git", "diff", "--name-only", tag, "HEAD", "--", *rutas], cwd=RAIZ, timeout=60
        )
        if cod != 0:
            inf.omitido(f"deriva de {nombre}", f"git diff contra {tag} no respondió")
            continue
        cambios = [l for l in salida.strip().splitlines() if l.strip()]
        if cambios:
            muestra = ", ".join(cambios[:3]) + (" …" if len(cambios) > 3 else "")
            inf.fallo(
                f"{nombre} {version} cambió desde el tag {tag}",
                f"{len(cambios)} archivo(s) distintos ({muestra}) bajo un número YA "
                f"publicado: sube la versión o esos cambios no llegarán al índice",
            )
        else:
            inf.ok(f"{nombre} {version}", f"idéntico al tag {tag}: nada sin publicar")


def verificar_promocion(inf: Informe, destino: str) -> None:
    """Comprueba que esta rama puede promoverse a `destino`. No fusiona."""
    if destino not in _DESTINOS:
        inf.fallo("destino de promoción", f"«{destino}» no es una rama del modelo")
        return
    regla = _DESTINOS[destino]

    if not hay("git"):
        inf.omitido("promoción", "git no está instalado")
        return

    rama = _rama_actual()
    if rama is None:
        inf.omitido("rama actual", "git no supo decir en qué rama estamos")
        return

    # --- ¿desde dónde se promueve? ------------------------------------------
    if rama == destino:
        inf.fallo(
            f"promover a {destino}",
            f"ya estás EN {destino}: una rama no se promueve a sí misma",
        )
        return
    exigida = regla["desde"]
    if exigida and rama != exigida:
        inf.fallo(
            f"promover a {destino}",
            f"se promueve desde «{exigida}», no desde «{rama}» — nada baja a "
            f"{destino} sin pasar por ahí",
        )
        return
    inf.ok(f"origen de la promoción: {rama} → {destino}", regla["porque"])

    # --- el árbol tiene que estar limpio ------------------------------------
    #
    # Un cambio sin commitear NO viaja en la promoción, así que lo que se
    # verifica aquí no sería lo que llega al destino. Verde sobre algo distinto
    # de lo que se promueve es el peor de los verdes.
    cod, salida = correr(["git", "status", "--porcelain"], cwd=RAIZ, timeout=60)
    if cod != 0:
        inf.omitido("árbol limpio", "git status no respondió")
    elif salida.strip():
        n = len(salida.strip().splitlines())
        inf.fallo(
            "árbol limpio",
            f"{n} cambio(s) sin commitear: lo verificado NO sería lo que se promueve",
        )
    else:
        inf.ok("árbol limpio", "lo que se verifica es lo que viaja")

    # --- y estar empujada, o el PR no vería estos commits -------------------
    cod, salida = correr(
        ["git", "rev-list", "--count", f"origin/{rama}..{rama}"], cwd=RAIZ, timeout=60
    )
    if cod != 0:
        inf.omitido("rama empujada", f"no hay origin/{rama}: empújala primero")
    elif salida.strip() not in ("", "0"):
        inf.fallo("rama empujada", f"{salida.strip()} commit(s) sin empujar")
    else:
        inf.ok("rama empujada", f"origin/{rama} está al día")

    # --- ningún hermano puede ir por detrás, ni del índice ni del destino ---
    #
    # En las DOS promociones, no solo al ir a `estable`: la regresión se
    # introduce al entrar en `testing` y cuanto antes se vea, más barata sale.
    #
    # Son DOS comprobaciones porque son dos preguntas: contra lo publicado (red,
    # ve lo subido a mano) y contra la rama destino (sin red, ve el release en
    # vuelo que aún no llegó al índice). Comparten `_semver` y nada más.
    verificar_versiones_de_miembros(inf)
    verificar_versiones_no_retroceden(inf, rama, f"origin/{destino}")

    # --- ni llevar cambios sin publicar bajo un número ya usado -------------
    #
    # Solo al ir a `estable`, y el porqué está en el encabezado de la función:
    # durante el desarrollo esa deriva es el estado normal.
    if destino == "estable":
        verificar_deriva_desde_el_tag(inf)

    # --- la versión no puede estar ya publicada -----------------------------
    #
    # Solo al ir a `estable`, porque es de donde sale el tag. Publicar una
    # versión que ya existe no falla ruidosamente en todas partes: PyPI la
    # rechaza, pero el resto del flujo ya arrancó. Y PyPI NO deja re-subir, así
    # que equivocarse cuesta un yank — pasó con la 0.9.0.
    if destino == "estable":
        verificar_version_no_publicada(inf)


def verificar_version_no_publicada(inf: Informe) -> None:
    """La versión del árbol no puede existir ya en PyPI.

    Va en función propia y no dentro de `verificar_promocion` PARA PODER
    PROBARLA: mientras estuvo embebida, su rama verde nunca se ejecutó y nadie
    lo notó.
    """
    try:
        v = _version_de_referencia()
    except Exception as e:
        inf.omitido("versión no publicada aún", f"no se pudo leer Cargo.toml: {e}")
        return
    # EL ENDPOINT ES POR VERSIÓN, así que una versión que no existe devuelve
    # **404** — y ese 404 es la respuesta BUENA, la que dice «adelante».
    #
    # Aquí se usaba `leer_json`, que devuelve `None` tanto para el 404 como
    # para un fallo de red, y el 404 caía en la rama de «PyPI no respondió».
    # Consecuencia: la comprobación NUNCA podía aprobar. Con la 0.11.0 sin
    # publicar salía «? SIN COMPROBAR» y la puerta entera acababa en
    # INCOMPLETA, o sea que bloqueaba toda promoción de una versión nueva —
    # justo la única clase de promoción que existe. La rama `ok` era código
    # muerto y nadie lo había ejecutado jamás.
    #
    # Es el error que este archivo ya tiene documentado dos veces: colapsar
    # «no pude mirar» con un veredicto. `leer_json_estado` existe para
    # separar los tres estados y este sitio se había quedado sin migrar.
    # Comprobado a mano el 2026-08-03: `curl` a ese endpoint da 200 para
    # 0.10.0 y 404 para 0.11.0.
    estado, meta = leer_json_estado(f"https://pypi.org/pypi/quipu-crypto/{v}/json")
    if estado == "ausente":
        inf.ok(f"la versión {v} no está publicada", "el tag será nuevo")
    elif estado == "ok" and isinstance(meta, dict) and meta.get("info"):
        inf.fallo(
            f"la versión {v} YA está en PyPI",
            "sube la versión antes de promover, o el release publicará algo "
            "distinto con el mismo número (PyPI no deja re-subir)",
        )
    else:
        # Un fallo de red NO es un aprobado. Que se note.
        inf.omitido(
            f"la versión {v} no está publicada aún",
            "PyPI no respondió: sin ese dato no se puede promover con seguridad",
        )


def abrir_pr_de_promocion(destino: str) -> int:
    """Abre el PR de la promoción. Se llama SOLO si la verificación salió limpia."""
    rama = _rama_actual()
    if not hay("gh"):
        print(f"\n{AMARILLO}gh no está instalado. Abre el PR a mano:{FIN}")
        print(f"  https://github.com/isazajuancarlos/quipu/compare/{destino}...{rama}")
        return 0

    # ¿Ya hay uno? Abrir un duplicado sería ruido, y cerrarlo, trabajo.
    cod, salida = correr(
        ["gh", "pr", "list", "--head", rama, "--base", destino, "--json", "number,url"]
    )
    if cod == 0:
        try:
            existentes = json.loads(salida)
        except ValueError:
            existentes = []
        if existentes:
            print(f"\n{VERDE}Ya hay un PR abierto para esta promoción:{FIN}")
            print(f"  {existentes[0]['url']}")
            return 0

    titulo = f"promoción: {rama} → {destino}"
    cuerpo = (
        f"Promoción verificada con `verificar.py promover --a {destino}`.\n\n"
        "Se abrió porque la verificación salió sin fallos **y sin nada pendiente de "
        "comprobar**. Los checks del PR siguen siendo la última palabra: esta "
        "herramienta no fusiona ni se salta la protección de la rama.\n"
    )
    cod, salida = correr(
        ["gh", "pr", "create", "--base", destino, "--head", rama,
         "--title", titulo, "--body", cuerpo]
    )
    if cod == 0:
        print(f"\n{VERDE}PR de promoción abierto:{FIN}\n  {salida.strip().splitlines()[-1]}")
        return 0
    print(f"\n{ROJO}No se pudo abrir el PR:{FIN} {salida.strip()[:200]}")
    return 1


# ===========================================================================
# I7 — LA SUPERFICIE DESPLEGADA RESPONDE POR SÍ MISMA
# ===========================================================================

OPRF_POR_DEFECTO = "https://oprf.xiliux.com"


def _curl(args: list[str], timeout: int = 15) -> tuple[int, str]:
    """Devuelve (código de salida, salida). `curl` y nada más: cero dependencias."""
    cod, salida = correr(["curl", "-sS", "--max-time", str(timeout), *args], timeout=timeout + 5)
    return cod, salida


def verificar_desplegado(inf: Informe, base: str) -> None:
    """Audita el servicio EN PRODUCCIÓN, no el archivo de configuración.

    Existe porque el invariante I7 —«la superficie desplegada responde por sí
    misma»— era el único de los siete sin ninguna herramienta, y es el que cubre
    lo que está expuesto a internet cobrando suscripciones. La taxonomía lo
    añadió el 2026-07-26 tras contrastarla con casos reales: de los nueve
    capítulos de *Hacking Ético*, cuatro tratan de aplicación web y hardening y
    ninguno cruzaba con las cinco familias que teníamos.

    NO ES INTRUSIVO a propósito. Comprueba postura, no explota: nada de fuerza
    bruta, ni fuzzing, ni agotar el límite de peticiones de un servicio que está
    cobrando. Lo que no se puede mirar sin dañar, se declara SIN COMPROBAR.

    Lo que NO se exige, y es deliberado: CSP, X-Frame-Options, Permissions-Policy
    y Referrer-Policy protegen a un NAVEGADOR. Esto es una API JSON que consumen
    SDK, así que pedirlas sería inflar la lista con hallazgos que ningún cliente
    legítimo necesita — la regla se prueba antes de escribirla contra «¿a quién
    de verdad protege?».
    """
    if not hay("curl"):
        inf.omitido("superficie desplegada", "no hay curl: el vigilante nacería mudo")
        return

    # --- ¿está vivo? ------------------------------------------------------
    cod, salida = _curl(["-o", "/dev/null", "-w", "%{http_code}", f"{base}/healthz"])
    if cod != 0:
        inf.omitido("servicio alcanzable", f"curl no pudo conectar con {base}")
        return
    # UN NOMBRE QUE REDIRIGE A OTRO NO ES UN SERVICIO: ES UN REDIRECTOR, Y
    # AUDITARLO COMO SI ALOJARA ALGO MIDE LA CAPA EQUIVOCADA.
    #
    # `www.xiliux.com` manda todo al canónico con un 301. Contra él, cada
    # comprobación de contenido veía la redirección en vez de una respuesta:
    # `GET /healthz` se declaraba FALLO por «devolvió 301» —o sea, denunciaba el
    # canónico que se acababa de montar bien— y ninguna ruta daba 200, así que
    # cinco comprobaciones más morían en SIN COMPROBAR. Ruido, no hallazgos.
    #
    # Seguir la redirección en silencio sería peor: informaría «9 comprobados»
    # sobre `www` habiendo medido en realidad el canónico. Se dice lo que hay y
    # se manda a auditar el nombre que sí sirve el contenido.
    codigo = salida.strip()[-3:]
    if codigo.startswith("3"):
        _, destino = _curl(
            ["-L", "--max-redirs", "5", "-o", "/dev/null",
             "-w", "%{url_effective}", f"{base}/healthz"]
        )
        origen = urllib.parse.urlsplit(base).netloc
        llegada = urllib.parse.urlsplit(destino.strip()).netloc

        # NO BASTA CON QUE REDIRIJA `/healthz`. Saltarse el resto de la auditoría
        # porque UNA ruta se va a otro sitio es dar por supuesto que se van
        # TODAS, y un servidor puede redirigir casi todo y servir el panel. El
        # atajo se ganó así un agujero en el minuto siguiente a escribirlo, en la
        # comprobación que más importa: se apagaba sola sin haber mirado.
        # Se exige que la ruta que nunca debe estar abierta también salga fuera.
        _, destino_admin = _curl(
            ["-L", "--max-redirs", "5", "-o", "/dev/null",
             "-w", "%{url_effective}", f"{base}/admin/keys"]
        )
        admin_fuera = urllib.parse.urlsplit(destino_admin.strip()).netloc == llegada

        if llegada and llegada != origen and admin_fuera:
            inf.ok(
                f"{origen} es un redirector hacia {llegada}",
                "no aloja contenido propio; la postura se audita en el destino",
            )
            inf.omitido(
                f"superficie de {origen}",
                f"todo redirige a {llegada}: repetir con --base https://{llegada}",
            )
            return

    vivo = codigo == "200"
    if vivo:
        inf.ok("GET /healthz responde 200")
    else:
        inf.fallo("GET /healthz", f"devolvió {salida.strip()}")

    # LA RUTA VIVA, una sola vez: la usan la sonda y las cabeceras.
    #
    # Antes cada bloque elegía la suya y el de HEAD estaba clavado a `/healthz`.
    # Contra un servicio SIN esa ruta —el portafolio, por ejemplo— HEAD y GET
    # daban 404 los dos, «coincidían», y la sonda se declaraba sana mientras
    # `GET /` respondía 200 y `HEAD /` respondía 405. O sea: el falso verde
    # exacto que esta función existe para impedir, en la misma herramienta que
    # lo denuncia. Medido contra https://xiliux.com el 2026-07-27.
    #
    # La lección no es «arreglar el HEAD»: es que comparar dos respuestas de
    # ERROR no compara nada. Dos 404 coinciden siempre y no dicen si la sonda
    # miente. Hay que preguntar donde la aplicación de verdad contesta.
    ruta_viva = None
    for candidata in ("/healthz", "/"):
        _, cab = _curl(["-D", "-", "-o", "/dev/null", f"{base}{candidata}"])
        primera = cab.splitlines()[0] if cab.splitlines() else ""
        if " 200" in primera:
            ruta_viva = candidata
            break

    # --- la sonda no puede mentir -----------------------------------------
    # HEAD es lo que usan los monitores de disponibilidad. Si difiere de GET, el
    # monitor da el servicio por caído aunque esté sano — o al revés, y entonces
    # no avisa cuando se cae. Detectado el 2026-07-27: HEAD devolvía 404 donde
    # GET devolvía 200, así que la sonda estándar habría mentido siempre.
    if ruta_viva is None:
        inf.omitido(
            "HEAD coincide con GET",
            "ninguna ruta responde 200: comparar dos errores no dice si la sonda miente",
        )
    else:
        _, cabeza = _curl(
            ["-o", "/dev/null", "-w", "%{http_code}", "-I", f"{base}{ruta_viva}"]
        )
        if cabeza.strip().endswith("200"):
            inf.ok(
                f"HEAD {ruta_viva} coincide con GET",
                "los monitores de disponibilidad no mienten",
            )
        else:
            inf.fallo(
                f"HEAD {ruta_viva} NO coincide con GET",
                f"HEAD={cabeza.strip()} vs GET=200: un monitor estándar reportaría mal",
            )

    # --- transporte -------------------------------------------------------
    # LAS CABECERAS SE MIRAN SOBRE UNA RESPUESTA 200, NO SOBRE UN 404.
    #
    # Una ruta inexistente la contesta a menudo el servidor de delante y no la
    # aplicación, con otro juego de cabeceras: auditar ahí mide la postura de la
    # capa equivocada. Si ninguna ruta responde 200 no se emite veredicto, porque
    # entonces «falta la cabecera» y «esto lo contestó otra capa» son
    # indistinguibles.
    cabeceras, ruta = "", ruta_viva
    if ruta is not None:
        _, cabeceras = _curl(["-D", "-", "-o", "/dev/null", f"{base}{ruta}"])
    bajas = cabeceras.lower()

    if ruta is None:
        # Ni aprobado ni suspenso: sin una respuesta de la APLICACIÓN no se puede
        # distinguir «falta la cabecera» de «esto lo contestó otra capa».
        inf.omitido(
            "cabeceras de seguridad",
            "ninguna ruta devolvió 200; un 404 lo sirve el servidor de delante y miente",
        )
    else:
        if "strict-transport-security:" in bajas:
            inf.ok("HSTS presente", f"visto en {ruta}")
        else:
            # El 301 de HTTP a HTTPS no basta: la PRIMERA petición de un cliente
            # nuevo viaja en claro y ahí se intercepta. Es la única cabecera que
            # de verdad importa en una API sin navegador.
            inf.fallo("falta HSTS", "el 301 no protege la primera petición de un cliente nuevo")

        if "x-content-type-options:" in bajas:
            inf.ok("X-Content-Type-Options presente")
        else:
            inf.fallo("falta X-Content-Type-Options: nosniff", "barato y aplica también a una API")

    sin_tls = base.replace("https://", "http://")
    _, red = _curl(["-o", "/dev/null", "-w", "%{http_code}", f"{sin_tls}/healthz"])
    if red.strip().startswith("3"):
        inf.ok("HTTP redirige a HTTPS", f"código {red.strip()}")
    else:
        inf.fallo("HTTP no redirige", f"devolvió {red.strip()}")

    cod_viejo, _ = _curl(["-o", "/dev/null", "--tls-max", "1.1", f"{base}/healthz"])
    if cod_viejo != 0:
        inf.ok("TLS 1.0/1.1 rechazado")
    else:
        inf.fallo("TLS 1.0/1.1 ACEPTADO", "protocolos obsoletos siguen negociando")

    # --- lo que nunca debe estar abierto ----------------------------------
    #
    # SOLO UN 2xx ES «ABIERTO». Todo lo demás, o es un cierre explícito, o es
    # una respuesta que NO DICE NADA sobre si /admin está protegido.
    #
    # La regla anterior era la contraria —«cerrado si 401/403/404, ABIERTO en
    # cualquier otro caso»— y eso convierte en denuncia de brecha cualquier
    # código que no se hubiera previsto. Cazado dos veces el mismo día, en el
    # chequeo más serio que tiene esta herramienta:
    #
    #   · un 502 en `proyecto.xiliux.com`, cuyo backend estaba muerto: la
    #     petición no llegó a ninguna aplicación, así que no hay nada que
    #     concluir sobre sus permisos;
    #   · un 301 en `www.xiliux.com`, que redirige al canónico: la redirección
    #     lleva a un 404: cerrado. Denunciarla como brecha señalaba justo el
    #     mecanismo que se acababa de montar bien.
    #
    # La primera vez parcheé el 5xx y dejé la regla intacta. Corregir el CASO en
    # vez de la REGLA es lo que permitió la segunda: un 405, un 429 o un 400
    # habrían gritado igual. Una alarma que resulta falsa dos veces es una
    # alarma que a la tercera nadie mira, y esta protege el panel de admin.
    for metodo, extra in (("GET", []), ("POST", ["-X", "POST", "-d", "{}"])):
        _, cod_admin = _curl(
            ["-o", "/dev/null", "-w", "%{http_code}", *extra, f"{base}/admin/keys"]
        )
        c = cod_admin.strip()[-3:]
        detalle = f"código {c}"

        # Una redirección no se juzga: se SIGUE. Es lo que hace un navegador y
        # lo que haría quien busca el panel, así que el veredicto tiene que
        # salir del destino real, no del salto.
        if c.startswith("3"):
            _, cod_final = _curl(
                ["-L", "--max-redirs", "5", "-o", "/dev/null", "-w", "%{http_code}",
                 *extra, f"{base}/admin/keys"]
            )
            final = cod_final.strip()[-3:]
            detalle = f"{c} y, siguiendo la redirección, {final}"
            c = final

        if c in ("401", "403", "404"):
            inf.ok(f"{metodo} /admin/keys cerrado sin credenciales", detalle)
        elif c.startswith("2"):
            inf.fallo(f"{metodo} /admin/keys ABIERTO", detalle)
        else:
            inf.omitido(
                f"{metodo} /admin/keys",
                f"devolvió {detalle}: no es ni un cierre explícito (401/403/404) "
                f"ni un acceso concedido (2xx), así que no dice si el panel está "
                f"protegido. Averiguar por qué responde eso y repetir",
            )

    # --- higiene ----------------------------------------------------------
    servidor = ""
    for linea in cabeceras.splitlines():
        if linea.lower().startswith("server:"):
            servidor = linea.split(":", 1)[1].strip()
    if servidor and any(ch.isdigit() for ch in servidor):
        inf.fallo("la cabecera Server filtra la versión", servidor)
    elif servidor:
        inf.ok("la cabecera Server no filtra versión", servidor)
    else:
        inf.omitido("cabecera Server", "no vino en la respuesta")

    # --- lo que esta herramienta NO puede comprobar ------------------------
    # Se declara en vez de callarse: un hueco silencioso se lee como aprobado.
    inf.omitido(
        "límite de peticiones",
        "agotarlo en producción es un ataque de denegación contra un servicio que cobra",
    )
    inf.omitido(
        "continuidad ante caída del proveedor",
        "riesgo R7: Supersalud y MIPRES cayeron porque cayó IFX, su proveedor. No se prueba desde fuera",
    )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Verificador de Quipu: comprueba lo local y lo PUBLICADO.",
        epilog="Salidas: 0 todo verificado · 1 hay fallos · 2 hay cosas SIN COMPROBAR.",
    )
    sub = p.add_subparsers(dest="orden", required=True)
    sub.add_parser("local", help="pruebas, doctests, clippy y cargo-vet del árbol")
    sub.add_parser("version", help="todos los sitios que llevan la versión llevan la misma")
    sub.add_parser("portada", help="la description publicada no promete lo que no existe")
    prom = sub.add_parser(
        "promover",
        help="¿puede esta rama promoverse? (modelo de tres ramas, ver docs/RAMAS.md)",
    )
    prom.add_argument("--a", required=True, choices=["testing", "estable"],
                      dest="destino", help="rama destino")
    pub = sub.add_parser("publicado", help="artefactos en crates.io y PyPI")
    pub.add_argument("--version", required=True)
    desp = sub.add_parser("desplegado", help="postura del servicio EN PRODUCCIÓN (I7)")
    desp.add_argument("--base", default=OPRF_POR_DEFECTO)
    pr = sub.add_parser("pr", help="estado de los checks de un PR")
    pr.add_argument("numero", type=int)
    todo = sub.add_parser("todo", help="local + publicado")
    todo.add_argument("--version", required=True)
    args = p.parse_args()

    inf = Informe()
    if args.orden == "version":
        print(f"{GRIS}Comprobando que la versión concuerde en todos sus sitios…{FIN}")
        verificar_versiones(inf)
        # `supply-chain/config.toml` es un sitio más de la versión, y de los que
        # no se miran: no rompe la compilación, rompe un check del CI.
        verificar_exenciones_de_vet(inf)
    if args.orden == "portada":
        print(f"{GRIS}Comprobando que las descripciones publicadas no mientan…{FIN}")
        verificar_promesas_de_la_portada(inf)
    if args.orden == "promover":
        print(f"{GRIS}¿Puede promoverse a {args.destino}?{FIN}")
        # El orden importa: primero las condiciones baratas de la promoción. Si
        # estás en la rama equivocada no tiene sentido gastar cuatro minutos de
        # suite para decírtelo.
        verificar_promocion(inf, args.destino)
        if not any(e == "fallo" for e, _, _ in inf.lineas):
            verificar_local(inf)
            verificar_versiones(inf)
            verificar_promesas_de_la_portada(inf)
            verificar_coherencia_de_features(inf)
    if args.orden in ("local", "todo"):
        print(f"{GRIS}Verificando el árbol de trabajo…{FIN}")
        verificar_local(inf)
        verificar_coherencia_de_features(inf)
        verificar_promesas_de_la_portada(inf)
        # Barato y va aquí a propósito: es lo que hay que mirar ANTES de
        # etiquetar, y etiquetar es publicar.
        verificar_versiones(inf)
    if args.orden in ("publicado", "todo"):
        print(f"{GRIS}Verificando los artefactos publicados de la {args.version}…{FIN}")
        with tempfile.TemporaryDirectory(prefix="quipu-verificar-") as d:
            tmp = Path(d)
            verificar_crate_publicado(inf, args.version, tmp)
            verificar_rueda_publicada(inf, args.version, tmp)
            # npm YA NO se comprueba: desde 0.10 no se publica ahí. El paquete
            # `quipu-crypto` sigue en el registro con sus versiones antiguas y
            # deprecado, así que esta comprobación pasaría en verde para 0.9.1 y
            # fallaría para todo lo que venga — un vigilante que empieza a
            # mentir en el próximo release. Ver el CHANGELOG de 0.10.
    if args.orden == "desplegado":
        print(f"{GRIS}Auditando la superficie desplegada en {args.base}…{FIN}")
        verificar_desplegado(inf, args.base.rstrip("/"))
    if args.orden == "pr":
        verificar_pr(inf, args.numero)

    codigo = inf.imprimir()

    # El PR se abre SOLO si no hubo fallos NI cosas sin comprobar. `imprimir`
    # devuelve 2 para lo segundo, y 2 no es un aprobado: es «no lo miré».
    if args.orden == "promover" and codigo == 0:
        return abrir_pr_de_promocion(args.destino)
    return codigo


if __name__ == "__main__":
    sys.exit(main())
