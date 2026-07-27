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
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
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


def leer_json(url: str):
    """Los índices exigen User-Agent; sin él, crates.io responde 403 y un 403
    NO significa «no publicado» (nos costó una conclusión equivocada)."""
    pet = urllib.request.Request(url, headers={"User-Agent": AGENTE})
    try:
        with urllib.request.urlopen(pet, timeout=60) as r:
            return json.load(r)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        return None


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


def verificar_npm_publicado(inf: Informe, version: str) -> None:
    meta = leer_json("https://registry.npmjs.org/quipu-crypto")
    if meta is None:
        inf.omitido("npm alcanzable", "no se pudo consultar el registro")
        return
    if version in meta.get("versions", {}):
        inf.ok(f"npm tiene quipu-crypto {version}")
    else:
        inf.fallo(f"npm tiene quipu-crypto {version}", "no aparece en el registro")


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
    return sitios


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
    cod, salida = correr(["git", "ls-files"], cwd=RAIZ, timeout=60)
    if cod != 0:
        inf.omitido("barrido de archivos no vigilados", "git ls-files no respondió")
        return
    vigilados = {a for a, _, _, _ in _sitios_de_version(v)} | _BARRIDO_EXENTO
    sueltos = []
    for rel in salida.splitlines():
        rel = rel.strip()
        if not rel or rel in vigilados:
            continue
        if not rel.endswith((".toml", ".json", ".md", ".yml", ".yaml", ".cfg", ".txt")):
            continue
        try:
            if v in (RAIZ / rel).read_text(encoding="utf-8", errors="ignore"):
                sueltos.append(rel)
        except OSError:
            continue
    if sueltos:
        inf.fallo(
            "archivos con la versión que NADIE vigila",
            ", ".join(sueltos) + " — añádelos al registro de `_sitios_de_version` o el "
            "próximo salto de versión los dejará atrás en silencio",
        )
    else:
        inf.ok("ningún archivo lleva la versión a espaldas del registro")


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


# --------------------------------------------------------------------------

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
    vivo = salida.strip().endswith("200")
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
    for metodo, extra in (("GET", []), ("POST", ["-X", "POST", "-d", "{}"])):
        _, cod_admin = _curl(
            ["-o", "/dev/null", "-w", "%{http_code}", *extra, f"{base}/admin/keys"]
        )
        c = cod_admin.strip()[-3:]
        if c in ("401", "403", "404"):
            inf.ok(f"{metodo} /admin/keys cerrado sin credenciales", f"código {c}")
        else:
            inf.fallo(f"{metodo} /admin/keys ABIERTO", f"devolvió {c}")

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
    pub = sub.add_parser("publicado", help="artefactos en crates.io, PyPI y npm")
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
    if args.orden == "portada":
        print(f"{GRIS}Comprobando que las descripciones publicadas no mientan…{FIN}")
        verificar_promesas_de_la_portada(inf)
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
            verificar_npm_publicado(inf, args.version)
    if args.orden == "desplegado":
        print(f"{GRIS}Auditando la superficie desplegada en {args.base}…{FIN}")
        verificar_desplegado(inf, args.base.rstrip("/"))
    if args.orden == "pr":
        verificar_pr(inf, args.numero)
    return inf.imprimir()


if __name__ == "__main__":
    sys.exit(main())
