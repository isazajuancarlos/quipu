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

def main() -> int:
    p = argparse.ArgumentParser(
        description="Verificador de Quipu: comprueba lo local y lo PUBLICADO.",
        epilog="Salidas: 0 todo verificado · 1 hay fallos · 2 hay cosas SIN COMPROBAR.",
    )
    sub = p.add_subparsers(dest="orden", required=True)
    sub.add_parser("local", help="pruebas, doctests, clippy y cargo-vet del árbol")
    pub = sub.add_parser("publicado", help="artefactos en crates.io, PyPI y npm")
    pub.add_argument("--version", required=True)
    pr = sub.add_parser("pr", help="estado de los checks de un PR")
    pr.add_argument("numero", type=int)
    todo = sub.add_parser("todo", help="local + publicado")
    todo.add_argument("--version", required=True)
    args = p.parse_args()

    inf = Informe()
    if args.orden in ("local", "todo"):
        print(f"{GRIS}Verificando el árbol de trabajo…{FIN}")
        verificar_local(inf)
        verificar_coherencia_de_features(inf)
    if args.orden in ("publicado", "todo"):
        print(f"{GRIS}Verificando los artefactos publicados de la {args.version}…{FIN}")
        with tempfile.TemporaryDirectory(prefix="quipu-verificar-") as d:
            tmp = Path(d)
            verificar_crate_publicado(inf, args.version, tmp)
            verificar_rueda_publicada(inf, args.version, tmp)
            verificar_npm_publicado(inf, args.version)
    if args.orden == "pr":
        verificar_pr(inf, args.numero)
    return inf.imprimir()


if __name__ == "__main__":
    sys.exit(main())
