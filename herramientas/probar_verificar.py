#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas
"""Banco de pruebas de `verificar.py`.

Un verificador sin pruebas propias es la ironía completa: la herramienta que
existe para que nada pase sin comprobar, sin comprobar.

Lo que se prueba NO es que la herramienta apruebe cuando todo está bien. Eso es
lo fácil y lo que menos importa: una función que devuelve «ok» siempre también
lo cumple. Se prueba que **DISCRIMINA** —que suspende cuando debe— y que
distingue sus tres estados, porque el fallo que arruina un verificador no es no
detectar: es **decir que sí sin haber mirado**.

Uso:  python3 herramientas/probar_verificar.py
"""

from __future__ import annotations

import io
import shutil
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verificar  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
fallos: list[str] = []
hechas = 0


def comprobar(condicion: bool, descripcion: str) -> None:
    global hechas
    hechas += 1
    if not condicion:
        fallos.append(descripcion)


def salida_de(inf: verificar.Informe) -> int:
    """Código de salida del informe, sin ensuciar la consola."""
    with redirect_stdout(io.StringIO()):
        return inf.imprimir()


# ---------------------------------------------------------------------------
# El informe y sus TRES estados
# ---------------------------------------------------------------------------

def probar_los_tres_estados() -> None:
    inf = verificar.Informe()
    inf.ok("algo")
    comprobar(salida_de(inf) == 0, "todo aprobado debe salir 0")

    inf = verificar.Informe()
    inf.ok("algo")
    inf.fallo("otra cosa")
    comprobar(salida_de(inf) == 1, "un fallo debe salir 1")

    # LA PRUEBA QUE MÁS IMPORTA. Si «no lo pude mirar» saliera 0, la
    # herramienta convertiría la ignorancia en aprobado — exactamente el
    # defecto que existe para combatir.
    inf = verificar.Informe()
    inf.ok("algo")
    inf.omitido("otra cosa", "no se pudo mirar")
    comprobar(salida_de(inf) == 2, "un omitido NO puede salir 0: debe salir 2")

    # Un fallo pesa más que un omitido: si hay ambos, gana el 1.
    inf = verificar.Informe()
    inf.fallo("rota")
    inf.omitido("sin mirar", "razón")
    comprobar(salida_de(inf) == 1, "fallo + omitido debe salir 1, no 2")

    # Un informe vacío no es un aprobado por defecto... pero tampoco miente:
    # sale 0 porque no afirma nada. Se deja documentado para que quien añada un
    # subcomando sepa que DEBE registrar algo.
    inf = verificar.Informe()
    comprobar(salida_de(inf) == 0, "informe vacío sale 0 (no afirma nada)")


# ---------------------------------------------------------------------------
# `correr`: el código de salida no se puede perder
# ---------------------------------------------------------------------------

def probar_correr() -> None:
    codigo, _ = verificar.correr(["true"])
    comprobar(codigo == 0, "`true` debe dar 0")

    codigo, _ = verificar.correr(["false"])
    comprobar(codigo != 0, "`false` NO puede dar 0: sería un verde falso")

    # Sin `shell=True` no hay tubería que pueda tragarse el código de salida.
    # Esta es la lección 1 del 2026-07-21 hecha prueba.
    codigo, salida = verificar.correr(["sh", "-c", "exit 3"])
    comprobar(codigo == 3, "el código de salida real debe llegar intacto")

    codigo, salida = verificar.correr(["ejecutable-que-no-existe-jamas"])
    comprobar(codigo == 127, "un ejecutable ausente debe dar 127, no 0")
    comprobar("no se encontró" in salida, "y debe decir que no lo encontró")

    codigo, _ = verificar.correr(["sleep", "5"], timeout=1)
    comprobar(codigo == 124, "un tiempo agotado debe dar 124, no 0")


def probar_hay() -> None:
    comprobar(verificar.hay("sh"), "`sh` existe")
    comprobar(not verificar.hay("programa-inexistente-xyz"), "lo inexistente no existe")


# ---------------------------------------------------------------------------
# Testigos: un testigo inventado NO es un defecto del artefacto
# ---------------------------------------------------------------------------

def probar_testigos() -> None:
    for feature, testigos in verificar.TESTIGOS.items():
        for t in testigos:
            comprobar(
                verificar.testigo_existe_en_el_codigo(t),
                f"el testigo «{t}» de «{feature}» debe existir en src/python.rs",
            )

    # `combine_shares` es el nombre que la primera versión INVENTÓ, y que hizo
    # que acusara a la rueda 0.9.1 de un fallo inexistente. Es la prueba de
    # regresión de ese error.
    comprobar(
        not verificar.testigo_existe_en_el_codigo("combine_shares"),
        "«combine_shares» no existe: se llama combine_secret",
    )
    comprobar(
        not verificar.testigo_existe_en_el_codigo("funcion_inventada_xyz"),
        "un símbolo inventado debe dar False",
    )
    # `fn decode<'py>(...)`: los genéricos no pueden esconder una declaración.
    comprobar(
        verificar.testigo_existe_en_el_codigo("decode"),
        "debe encontrar `fn decode<'py>(` pese al parámetro de tiempo de vida",
    )
    # `honey` no debe tener testigo mientras su binding no exista.
    comprobar(
        "honey" not in verificar.TESTIGOS,
        "«honey» no lleva testigo: su binding de Python no está mergeado",
    )


# ---------------------------------------------------------------------------
# Features leídas, no repetidas
# ---------------------------------------------------------------------------

def probar_lectura_de_features() -> None:
    declaradas = verificar.features_del_manifiesto()
    comprobar(len(declaradas) >= 8, "Cargo.toml declara al menos 8 features")
    for esperada in ("hsm", "escrow", "honey", "lab", "lab-offline"):
        comprobar(esperada in declaradas, f"«{esperada}» debe salir de Cargo.toml")

    rueda = verificar.features_de_la_rueda()
    comprobar("hsm" in rueda, "la rueda debe declarar «hsm» (la que faltó en 0.9.0)")
    comprobar(
        set(rueda) <= set(declaradas),
        "la rueda no puede pedir features que Cargo.toml no declara",
    )


# ---------------------------------------------------------------------------
# La comprobación que ya se equivocó: descripción contra dato
# ---------------------------------------------------------------------------

def probar_coherencia_de_features() -> None:
    release = RAIZ / ".github" / "workflows" / "release.yml"
    respaldo = release.read_text(encoding="utf-8")

    inf = verificar.Informe()
    verificar.verificar_coherencia_de_features(inf)
    estado, _, _ = inf.lineas[0]
    comprobar(
        estado == "ok",
        "release.yml actual NO repite las features: debe aprobar. "
        "Menciona `--features` en un COMENTARIO, y confundir la descripción "
        "con el dato ya rompió esta comprobación una vez.",
    )

    # Reponer el defecto de la 0.9.0 y exigir que se detecte.
    try:
        roto = respaldo.replace(
            "args: --release --out dist\n",
            "args: --release --features python,escrow --out dist\n",
            1,
        )
        comprobar(roto != respaldo, "se pudo simular el defecto de la 0.9.0")
        release.write_text(roto, encoding="utf-8")
        inf = verificar.Informe()
        verificar.verificar_coherencia_de_features(inf)
        estado, _, detalle = inf.lineas[0]
        comprobar(
            estado == "fallo",
            "con la bandera repuesta DEBE fallar: es el defecto que dejó la "
            "rueda 0.9.0 sin `hsm`",
        )
        comprobar(
            "python" in detalle and "escrow" in detalle,
            "y debe nombrar las features repetidas",
        )
    finally:
        release.write_text(respaldo, encoding="utf-8")

    comprobar(
        release.read_text(encoding="utf-8") == respaldo,
        "release.yml debe quedar EXACTAMENTE como estaba",
    )


# ---------------------------------------------------------------------------
# Que un índice inalcanzable no se convierta en aprobado
# ---------------------------------------------------------------------------

def probar_red_caida() -> None:
    original = verificar.leer_json
    try:
        verificar.leer_json = lambda url: None  # simula el índice caído
        inf = verificar.Informe()
        with tempfile.TemporaryDirectory() as d:
            verificar.verificar_npm_publicado(inf, "0.9.1")
            verificar.verificar_rueda_publicada(inf, "0.9.1", Path(d))
        estados = [e for e, _, _ in inf.lineas]
        comprobar(
            estados and all(e == "omitido" for e in estados),
            "con el índice caído todo debe ser OMITIDO, nunca aprobado",
        )
        comprobar(salida_de(inf) == 2, "y el informe debe salir 2, no 0")
    finally:
        verificar.leer_json = original


def main() -> int:
    for prueba in (
        probar_los_tres_estados,
        probar_correr,
        probar_hay,
        probar_testigos,
        probar_lectura_de_features,
        probar_coherencia_de_features,
        probar_red_caida,
    ):
        prueba()

    if fallos:
        print(f"{len(fallos)} de {hechas} comprobaciones FALLARON:")
        for f in fallos:
            print(f"  ✗ {f}")
        return 1
    print(f"banco del verificador: {hechas} comprobaciones, todas correctas")
    return 0


if __name__ == "__main__":
    sys.exit(main())
