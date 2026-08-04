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
            # Antes esto cubría también npm. Se quitó con la comprobación, que
            # se retiró en 0.10 porque npm dejó de ser destino de publicación:
            # un vigilante que empieza a mentir en el próximo release.
            verificar.verificar_rueda_publicada(inf, "0.9.1", Path(d))
        estados = [e for e, _, _ in inf.lineas]
        comprobar(
            estados and all(e == "omitido" for e in estados),
            "con el índice caído todo debe ser OMITIDO, nunca aprobado",
        )
        comprobar(salida_de(inf) == 2, "y el informe debe salir 2, no 0")
    finally:
        verificar.leer_json = original


def probar_barrido_distingue_version_de_dependencia() -> None:
    """El barrido no puede marcar «0.9.1» cuando es de una DEPENDENCIA.

    Punto ciego 2 de la tarea #138: `docs/ATAQUES_TAXONOMIA.md` decía que
    `quipu-cnsa` depende de `aes 0.9.1` y el barrido lo marcó como si 0.9.1 fuera
    la versión de Quipu — la misma trampa que el grep original ya documentaba.
    Es LA prueba que importa: que la regla DISCRIMINE de quién es la versión.
    """
    deps = verificar._nombres_de_dependencias()
    comprobar("aes" in deps, "aes debe estar en el grafo de dependencias (Cargo.lock)")
    comprobar("poly1305" in deps, "poly1305 también: es la otra que tiene 0.9.x")
    comprobar("quipu" not in deps, "quipu NO es dependencia ajena: se excluye del grafo")

    # La versión de una dependencia, en todas sus formas, NO cuenta como Quipu.
    for texto in (
        "quipu-cnsa depende de aes 0.9.1 para el modo simétrico",
        'aes = "0.9.1"',
        "aes-0.9.1",
        "aes@0.9.1",
        "poly1305 0.9.1 y aes 0.9.1",
    ):
        comprobar(
            not verificar._version_a_espaldas(texto, "0.9.1", deps),
            f"«{texto}» es versión de dependencia: marcarlo sería el falso positivo de #138",
        )

    # La versión de Quipu, sin nombre de dependencia pegado, SÍ cuenta: quitar el
    # falso positivo no puede cegar el barrido a lo que existe para vigilar.
    for texto in (
        "Versión 0.9.1 de Quipu",
        "quipu 0.9.1",
        "0.9.1",
        "release 0.9.1",  # «release» no es un crate: sigue contando como Quipu
    ):
        comprobar(
            verificar._version_a_espaldas(texto, "0.9.1", deps),
            f"«{texto}» es la versión de Quipu: el barrido DEBE poder verla",
        )

    # Un archivo con AMBAS —la de Quipu y la de una dependencia— se marca: basta
    # una aparición sin coartada. Para una salvaguarda, la duda cierra.
    comprobar(
        verificar._version_a_espaldas("Quipu 0.9.1, que usa aes 0.9.1", "0.9.1", deps),
        "si hay una aparición de Quipu, da igual que también cite una dependencia",
    )


def probar_barrido_respeta_fronteras_numericas() -> None:
    """«0.9.1» no puede casar dentro de «0.9.10» ni de «10.9.1».

    El barrido viejo usaba `v in texto` (subcadena), que sí casaba dentro de un
    número mayor. Un falso positivo tan tonto como real.
    """
    deps = verificar._nombres_de_dependencias()
    comprobar(
        not verificar._version_a_espaldas("subimos a 0.9.10 la semana pasada", "0.9.1", deps),
        "0.9.1 no debe casar dentro de 0.9.10",
    )
    comprobar(
        not verificar._version_a_espaldas("el build 10.9.1 del kernel", "0.9.1", deps),
        "0.9.1 no debe casar dentro de 10.9.1",
    )
    comprobar(
        not verificar._version_a_espaldas("un texto sin ninguna versión", "0.9.1", deps),
        "un texto sin la versión no la contiene",
    )


def main() -> int:
    # LAS PRUEBAS SE DESCUBREN, NO SE ENUMERAN.
    #
    # Aquí había una lista escrita a mano, y falló exactamente como fallan las
    # listas escritas a mano: se añadieron tres pruebas del promotor y NO se
    # ejecutaron. El banco siguió diciendo «41 comprobaciones, todas correctas»
    # —cierto, y a la vez inútil— porque las nuevas ni siquiera se llamaron.
    #
    # Es el mismo defecto que este repositorio lleva un mes corrigiendo en otros
    # sitios: la lista de doce archivos de versión, la matriz de paridad entre
    # bindings. Un registro que hay que acordarse de ampliar es un registro que
    # diverge. Y que le pasara al BANCO DE PRUEBAS del verificador, que existe
    # para que nada pase sin comprobar sin comprobar, es lo bastante irónico
    # como para dejarlo escrito.
    pruebas = sorted(
        (nombre, f)
        for nombre, f in globals().items()
        if nombre.startswith("probar_") and callable(f)
    )
    if not pruebas:
        print("el banco no encontró ninguna prueba: eso NO es un aprobado")
        return 1
    for _nombre, prueba in pruebas:
        prueba()

    if fallos:
        print(f"{len(fallos)} de {hechas} comprobaciones FALLARON:")
        for f in fallos:
            print(f"  ✗ {f}")
        return 1
    print(f"banco del verificador: {len(pruebas)} pruebas, "
          f"{hechas} comprobaciones, todas correctas")
    return 0


# ---------------------------------------------------------------------------
# I7 — la auditoría de la superficie desplegada
# ---------------------------------------------------------------------------

def probar_desplegado_sin_curl_no_aprueba() -> None:
    """Sin la herramienta con la que mira, NO puede decir que todo está bien.

    Es el defecto que este banco existe para cazar, aplicado al modo nuevo: un
    vigilante que nace mudo produce silencio, y el silencio se lee como «sin
    novedad». Ya pasó con un monitor construido sobre `jq` cuando `jq` no estaba.
    """
    original = verificar.hay
    verificar.hay = lambda _programa: False
    try:
        inf = verificar.Informe()
        verificar.verificar_desplegado(inf, "https://ejemplo.invalido")
        comprobar(salida_de(inf) == 2, "sin curl debe salir 2 (SIN COMPROBAR), nunca 0")
        comprobar(
            all(e == "omitido" for e, _, _ in inf.lineas),
            "sin curl no puede haber ni aprobados ni fallos: no se miró nada",
        )
    finally:
        verificar.hay = original


def probar_desplegado_con_host_inalcanzable_no_aprueba() -> None:
    """Un dominio que no existe no es un servicio sano: es uno que no se miró."""
    if not verificar.hay("curl"):
        return
    inf = verificar.Informe()
    verificar.verificar_desplegado(inf, "https://no-existe.invalido")
    comprobar(salida_de(inf) != 0, "un host inalcanzable NO puede salir 0")


def probar_desplegado_declara_lo_que_no_puede_mirar() -> None:
    """El límite de peticiones y la continuidad NO se prueban desde fuera.

    Agotar el límite de un servicio que cobra es una denegación de servicio
    contra el propio negocio, y la caída de un proveedor no se simula con curl.
    Las dos tienen que aparecer como SIN COMPROBAR y no desaparecer: un hueco
    silencioso se lee como aprobado.
    """
    original = verificar.hay
    verificar.hay = lambda _programa: False
    try:
        inf = verificar.Informe()
        verificar.verificar_desplegado(inf, "https://ejemplo.invalido")
    finally:
        verificar.hay = original
    # Con curl ausente sale pronto; lo que se fija aquí es que el modo NUNCA
    # devuelve un informe vacío, porque un informe vacío también sale 0.
    comprobar(len(inf.lineas) > 0, "el modo desplegado nunca puede devolver un informe vacío")


def probar_promocion_rechaza_la_rama_equivocada() -> None:
    """A `estable` solo se llega desde `testing`, y nunca desde sí misma.

    Es la regla que sostiene el modelo: si se puede promover desde cualquier
    sitio, `testing` no filtra nada y las tres ramas son decoración.
    """
    original = verificar._rama_actual
    try:
        # Promoverse a uno mismo.
        verificar._rama_actual = lambda: "estable"
        inf = verificar.Informe()
        verificar.verificar_promocion(inf, "estable")
        comprobar(salida_de(inf) == 1, "una rama no puede promoverse a sí misma")

        # Saltarse `testing`.
        verificar._rama_actual = lambda: "feat/lo-que-sea"
        inf = verificar.Informe()
        verificar.verificar_promocion(inf, "estable")
        comprobar(salida_de(inf) == 1, "a estable NO se llega saltándose testing")

        # Una rama de trabajo SÍ puede ir a testing: si esto fallara, el modelo
        # sería inusable y nadie lo usaría, que es la otra forma de que se pudra.
        verificar._rama_actual = lambda: "feat/lo-que-sea"
        inf = verificar.Informe()
        verificar.verificar_promocion(inf, "testing")
        primera = inf.lineas[0]
        comprobar(primera[0] == "ok", "una rama de trabajo SÍ puede ir a testing")
    finally:
        verificar._rama_actual = original


def probar_promocion_a_destino_inventado() -> None:
    """Un destino que no es del modelo se rechaza, no se acepta por descuido."""
    inf = verificar.Informe()
    verificar.verificar_promocion(inf, "produccion")
    comprobar(salida_de(inf) == 1, "un destino fuera del modelo debe fallar")


def probar_promocion_sin_red_no_aprueba() -> None:
    """Si PyPI no contesta, NO se puede promover a estable.

    Es el caso que más fácil se cuela: sin respuesta, la tentación es asumir
    que la versión no está publicada y seguir. Eso convierte «no lo sé» en
    «adelante», y publicar sobre una versión existente cuesta un yank — PyPI no
    deja re-subir. Tiene que salir SIN COMPROBAR, que no es un aprobado.
    """
    orig_rama, orig_json = verificar._rama_actual, verificar.leer_json
    orig_estado = verificar.leer_json_estado
    verificar._rama_actual = lambda: "testing"
    verificar.leer_json = lambda _url: None          # la red no contesta
    # También el índice de crates.io: si no se apaga, la comprobación de los
    # hermanos saldría a la red DE VERDAD desde el banco.
    verificar.leer_json_estado = lambda _url: ("sin-respuesta", None)
    try:
        inf = verificar.Informe()
        verificar.verificar_promocion(inf, "estable")
        comprobar(
            any(e == "omitido" for e, _, _ in inf.lineas),
            "sin respuesta de PyPI, la versión queda SIN COMPROBAR",
        )
        comprobar(salida_de(inf) != 0, "y un SIN COMPROBAR nunca sale 0")
    finally:
        verificar._rama_actual, verificar.leer_json = orig_rama, orig_json
        verificar.leer_json_estado = orig_estado


# ---------------------------------------------------------------------------
# La versión de un crate HERMANO no puede ir por detrás de crates.io
# ---------------------------------------------------------------------------
#
# El caso real que lo motivó: `estable` y crates.io en `quipu-nucleo` 0.1.1,
# `testing` en 0.1.0. Las cuatro pruebas de abajo son las cuatro respuestas
# posibles, y la que de verdad importa es la SEGUNDA: si «igual a la publicada»
# saliera roja, la regla estaría mal y obligaría a subir los cinco crates en
# cada release.

def _indice_con(*versiones: str):
    """Un crates.io de mentira que sirve estas versiones para cualquier crate."""
    return lambda _url: (
        "ok",
        {"versions": [{"num": v, "yanked": False} for v in versiones]},
    )


def _informe_de_miembros(indice, miembros=(("quipu-nucleo", "0.1.0", "crates/quipu-nucleo"),)):
    orig_estado = verificar.leer_json_estado
    orig_miembros = verificar._miembros_publicables
    verificar.leer_json_estado = indice
    verificar._miembros_publicables = lambda: list(miembros)
    try:
        inf = verificar.Informe()
        verificar.verificar_versiones_de_miembros(inf)
        return inf
    finally:
        verificar.leer_json_estado = orig_estado
        verificar._miembros_publicables = orig_miembros


def probar_hermano_atrasado_suspende() -> None:
    """0.1.0 en el árbol contra 0.1.1 publicada: eso no se puede promover."""
    inf = _informe_de_miembros(_indice_con("0.1.1", "0.1.0"))
    comprobar(
        any(e == "fallo" for e, _, _ in inf.lineas),
        "un hermano por detrás del índice tiene que SUSPENDER",
    )
    comprobar(salida_de(inf) == 1, "y el informe sale 1")


def probar_hermano_igual_a_la_publicada_aprueba() -> None:
    """La operación NORMAL: un release que no toca este crate.

    Si esto saliera rojo, la regla estaría mal por bien argumentada que
    estuviera: obligaría a bumpear los cinco crates en cada release aunque
    ninguno haya cambiado (directiva 21).
    """
    inf = _informe_de_miembros(
        _indice_con("0.1.1"), miembros=(("quipu-nucleo", "0.1.1", "crates/quipu-nucleo"),)
    )
    comprobar(
        all(e == "ok" for e, _, _ in inf.lineas),
        "un hermano IGUAL a la versión publicada es normal, no un fallo",
    )
    comprobar(salida_de(inf) == 0, "y el informe sale 0")


def probar_hermano_sin_publicar_no_es_un_fallo() -> None:
    """Un 404 del índice SÍ es un dato: el crate aún no existe ahí."""
    inf = _informe_de_miembros(
        lambda _url: ("ausente", None),
        miembros=(("padme-frame", "0.1.0", "crates/padme-frame"),),
    )
    comprobar(
        all(e == "ok" for e, _, _ in inf.lineas),
        "un crate que todavía no está publicado no tiene nada que superar",
    )


def probar_indice_caido_no_aprueba_a_los_hermanos() -> None:
    """«No pude mirar» nunca es «lo miré y está bien»."""
    inf = _informe_de_miembros(lambda _url: ("sin-respuesta", None))
    comprobar(
        all(e == "omitido" for e, _, _ in inf.lineas),
        "sin respuesta del índice, la versión del hermano queda SIN COMPROBAR",
    )
    comprobar(salida_de(inf) == 2, "y un SIN COMPROBAR sale 2, no 0")


def probar_workspace_vacio_no_aprueba() -> None:
    """Cero miembros no es «todos correctos»: es que no se leyó nada."""
    inf = _informe_de_miembros(_indice_con("0.1.1"), miembros=())
    comprobar(salida_de(inf) != 0, "un workspace sin miembros NO puede salir 0")


def probar_la_referencia_historica_no_es_una_sede_de_version() -> None:
    """«desde la 0.10.0» dice CUÁNDO pasó algo, no qué versión es esta.

    El caso real: `docs/SPEC.md` decía «has been public and settable through
    `Options` since 0.10.0» y el barrido lo marcaba como archivo con la versión
    sin vigilar. Actualizar esa frase al subir de versión sería FALSEAR la
    historia — el campo no se volvió público en la 0.11.0.

    Lo que de verdad se prueba aquí no es que deje de marcarlo: es que **siga
    marcando todo lo demás**. Una exención que se pasa de ancha convierte la
    salvaguarda en un aprobado.
    """
    deps = {"aes", "poly1305"}
    v = "0.10.0"
    historicas = [
        "It has been public and settable through `Options` since 0.10.0, so",
        "público y ajustable desde la 0.10.0",
        "el campo existe a partir de la 0.10.0",
        "added in 0.10.0",
        "deprecated in 0.10.0",
        "se retiró hasta la 0.10.0",
    ]
    for t in historicas:
        comprobar(
            not verificar._version_a_espaldas(t, v, deps),
            f"referencia histórica marcada como sede de versión: {t!r}",
        )

    declaraciones = [
        "Quipu is `v0.10.0`. It composes only vetted primitives",
        'version = "0.10.0"',
        "La versión actual es 0.10.0 y sale de Cargo.toml",
        "quipu 0.10.0",
        # Sin ninguna marca alrededor: la duda se resuelve SEÑALANDO.
        "0.10.0",
    ]
    for t in declaraciones:
        comprobar(
            verificar._version_a_espaldas(t, v, deps),
            f"declaración de versión que el barrido DEJÓ pasar: {t!r}",
        )

    # Y la discriminación que ya existía no puede haberse roto por el camino.
    comprobar(
        not verificar._version_a_espaldas("aes 0.10.0", v, deps),
        "la versión de una dependencia volvió a contarse como de Quipu",
    )
    comprobar(
        verificar._version_a_espaldas("since 0.10.0 y además quipu 0.10.0", v, deps),
        "un archivo con una histórica Y una declaración tiene que marcarse igual",
    )


def probar_semver_ordena_el_prelanzamiento_antes() -> None:
    comprobar(
        verificar._semver("0.2.0-rc.1") < verificar._semver("0.2.0"),
        "un prelanzamiento ordena ANTES que su versión final",
    )
    comprobar(
        verificar._semver("0.10.0") > verificar._semver("0.9.1"),
        "0.10.0 es mayor que 0.9.1 (comparación numérica, no de texto)",
    )


def probar_semver_es_uno_solo_y_no_se_inventa_un_orden() -> None:
    """El contrato ÚNICO de `_semver`, que antes estaba escrito dos veces.

    Esta prueba existe por un choque concreto: `verificar_versiones_no_retroceden`
    y `verificar_versiones_de_miembros` nacieron en ramas distintas con un
    `_semver` cada una —una devolvía tuplas de longitud variable o `None`, la
    otra tuplas de cuatro que reventaban—. Al fusionar, la segunda definición
    habría tapado a la primera EN SILENCIO, y `(0,1,1) < (0,1,1,1)` es `True`:
    la misma versión leída como «va por detrás». Fija el contrato para que un
    tercer guardián no vuelva a traer el suyo.
    """
    # ORDENA lo que se puede ordenar.
    comprobar(verificar._semver("0.1.1") > verificar._semver("0.1.0"), "0.1.1 > 0.1.0")
    comprobar(verificar._semver("0.10.0") > verificar._semver("0.9.9"), "0.10.0 > 0.9.9")
    comprobar(
        verificar._semver("0.1") == verificar._semver("0.1.0"),
        "«0.1» se rellena a 0.1.0, que es como lo trata cargo",
    )
    comprobar(
        verificar._semver("1.0.0+deadbeef") == verificar._semver("1.0.0"),
        "el metadato de construcción NO cuenta para la precedencia (lo dice semver)",
    )
    # La longitud es SIEMPRE 4: es justo lo que el choque rompía.
    for v in ("0.1", "0.1.0", "0.2.0-rc.1", "1.0.0+x"):
        comprobar(len(verificar._semver(v)) == 4, f"«{v}» produce una tupla de 4")

    # SE NIEGA en vez de adivinar, y `None` no es un aprobado.
    for v in ("", "dev", "0.1.x", "1.2.3.4", "0.1.-1"):
        comprobar(verificar._semver(v) is None, f"«{v}» no se ordena, devuelve None")


def probar_ninguna_version_retrocede() -> None:
    """Promover una rama con un crate MÁS VIEJO que el destino despublica un release.

    El caso real: el 2026-08-01 `testing` llevaba `quipu-nucleo 0.1.0` y `estable`
    ya publicaba la 0.1.1. Las dos ramas eran internamente coherentes —los cuatro
    sitios de la versión de `quipu` concordaban en las dos—, así que el check de
    coherencia salía VERDE en ambas. El fallo solo existe al compararlas.

    EL LECTOR VA SUSTITUIDO A PROPÓSITO. Atar la prueba a las ramas de verdad la
    dejaría sin caso rojo en cuanto la fusión aterrice: seguiría en verde y ya no
    comprobaría nada, que es la forma exacta en que muere una salvaguarda.
    """
    original = verificar._versiones_de_los_crates
    original_al_dia = verificar._copia_de_origin_al_dia
    arboles: dict[str, dict[str, str] | None] = {}
    verificar._versiones_de_los_crates = lambda ref: arboles.get(ref)
    # La frescura de origin/ se prueba aparte; aquí estorbaría pidiendo red.
    verificar._copia_de_origin_al_dia = lambda ref: (True, "sustituido en la prueba")
    try:
        # ROJO: el origen lleva un crate más viejo que el destino.
        arboles.clear()
        arboles["origen"] = {"quipu": "0.10.0", "quipu-nucleo": "0.1.0"}
        arboles["destino"] = {"quipu": "0.10.0", "quipu-nucleo": "0.1.1"}
        inf = verificar.Informe()
        verificar.verificar_versiones_no_retroceden(inf, "origen", "destino")
        comprobar(salida_de(inf) == 1, "una versión que retrocede DEBE suspender")

        # VERDE: iguales. Es lo normal entre release y release; si esto fallara,
        # el guardián bloquearía toda promoción y habría que desactivarlo.
        arboles["origen"] = {"quipu": "0.10.0", "quipu-nucleo": "0.1.1"}
        inf = verificar.Informe()
        verificar.verificar_versiones_no_retroceden(inf, "origen", "destino")
        comprobar(salida_de(inf) == 0, "versiones iguales SÍ se pueden promover")

        # VERDE: el origen va por delante. Es el caso de un release preparado.
        arboles["origen"] = {"quipu": "0.11.0", "quipu-nucleo": "0.2.0"}
        inf = verificar.Informe()
        verificar.verificar_versiones_no_retroceden(inf, "origen", "destino")
        comprobar(salida_de(inf) == 0, "subir de versión SÍ se puede promover")

        # VERDE: un crate NUEVO en el origen no es un retroceso de nada. Es el
        # caso de `padme-frame`, que nació después de `estable`.
        arboles["origen"] = {"quipu": "0.10.0", "quipu-nucleo": "0.1.1", "padme-frame": "0.1.0"}
        inf = verificar.Informe()
        verificar.verificar_versiones_no_retroceden(inf, "origen", "destino")
        comprobar(salida_de(inf) == 0, "un crate nuevo no cuenta como retroceso")

        # ROJO: un prelanzamiento por debajo del final ya publicado.
        #
        # ESTE CASO CAMBIÓ AL UNIFICAR, y a mejor: con el `_semver` que devolvía
        # `None` ante cualquier `-rc`, esto quedaba SIN COMPROBAR. El unificado
        # SÍ lo ordena —`0.1.1-rc1` va antes que `0.1.1`—, así que lo que era una
        # abstención pasa a ser el fallo que de verdad es: promover eso devolvería
        # un release publicado a un candidato.
        arboles["origen"] = {"quipu": "0.10.0", "quipu-nucleo": "0.1.1-rc1"}
        inf = verificar.Informe()
        verificar.verificar_versiones_no_retroceden(inf, "origen", "destino")
        comprobar(salida_de(inf) == 1, "un prelanzamiento por debajo del final SUSPENDE")

        # SIN COMPROBAR: lo que de verdad no se puede ordenar sigue sin ordenarse.
        arboles["origen"] = {"quipu": "0.10.0", "quipu-nucleo": "no-es-una-version"}
        inf = verificar.Informe()
        verificar.verificar_versiones_no_retroceden(inf, "origen", "destino")
        comprobar(salida_de(inf) == 2, "una versión no ordenable queda SIN COMPROBAR")

        # SIN COMPROBAR: si una de las dos ramas no se puede leer, no hay
        # comparación posible — y eso no es un aprobado.
        arboles["origen"] = None
        inf = verificar.Informe()
        verificar.verificar_versiones_no_retroceden(inf, "origen", "destino")
        comprobar(salida_de(inf) == 2, "sin una de las ramas, SIN COMPROBAR y no 0")
    finally:
        verificar._versiones_de_los_crates = original
        verificar._copia_de_origin_al_dia = original_al_dia


def probar_un_404_de_pypi_es_via_libre_y_no_una_abstencion() -> None:
    """El endpoint por versión de PyPI da 404 cuando la versión NO existe, y ese
    404 es la respuesta BUENA.

    Aquí se usaba `leer_json`, que devuelve `None` para el 404 y para un fallo de
    red por igual, así que el caso bueno caía en «PyPI no respondió». La
    comprobación no podía aprobar NUNCA: la rama verde era código muerto, y la
    puerta de `estable` terminaba en INCOMPLETA para cualquier versión sin
    publicar — que es la única clase de versión que se promueve. Medido el
    2026-08-03 con la 0.11.0.

    Los tres estados, cada uno con su veredicto distinto.
    """
    original = verificar.leer_json_estado
    original_ver = verificar._version_de_referencia
    verificar._version_de_referencia = lambda: "0.11.0"
    try:
        casos = [
            (("ausente", None), 0, "un 404 significa «no publicada»: VÍA LIBRE"),
            (("ok", {"info": {"version": "0.11.0"}}), 1, "un 200 significa YA publicada: suspende"),
            (("error", None), 2, "un fallo de red NO es un aprobado: SIN COMPROBAR"),
        ]
        for respuesta, esperado, glosa in casos:
            verificar.leer_json_estado = lambda url, r=respuesta: r
            inf = verificar.Informe()
            verificar.verificar_version_no_publicada(inf)
            comprobar(salida_de(inf) == esperado, glosa)
    finally:
        verificar.leer_json_estado = original
        verificar._version_de_referencia = original_ver


def probar_una_exencion_de_vet_desfasada_suspende() -> None:
    """Subir un miembro y no mover su exención de `cargo-vet` tiene que suspender.

    Es lo que pasó el 2026-08-03: `quipu-nucleo` fue a 0.1.2 y `quipu-voprf` a
    0.2.3, `supply-chain/config.toml` se quedó en 0.1.0 y 0.2.2, y el check
    `cargo-vet (supply chain)` salió rojo en el PR. Lo cazó el CI, o sea tarde y
    con minutos gastados.

    El lector va SUSTITUIDO para que el caso rojo no dependa del árbol de verdad:
    atarlo al repositorio real lo dejaría sin rojo en cuanto se arregle.
    """
    original = verificar._miembros_publicables
    original_toml = verificar._leer_toml
    try:
        verificar._miembros_publicables = lambda: [("quipu-nucleo", "0.1.2", "crates/quipu-nucleo")]

        def toml_falso(ruta):
            if ruta.name == "config.toml":
                return {"exemptions": {"quipu-nucleo": [{"version": VERSION_EXENTA}]}}
            return {"package": {"name": "quipu", "version": "9.9.9"}}

        verificar._leer_toml = toml_falso

        # ROJO: la exención apunta a una versión que ya no es la del árbol.
        VERSION_EXENTA = "0.1.0"
        inf = verificar.Informe()
        verificar.verificar_exenciones_de_vet(inf)
        comprobar(salida_de(inf) == 1, "una exención desfasada DEBE suspender")

        # VERDE: concuerdan. Es la operación normal y no puede bloquear nada.
        VERSION_EXENTA = "0.1.2"
        inf = verificar.Informe()
        verificar.verificar_exenciones_de_vet(inf)
        comprobar(salida_de(inf) == 0, "una exención al día NO suspende")

        # SIN COMPROBAR: un miembro sin exención no es un fallo — un crate
        # auditado de verdad no la necesita, y exigirla premiaría lo peor.
        verificar._leer_toml = lambda ruta: (
            {"exemptions": {}} if ruta.name == "config.toml"
            else {"package": {"name": "quipu", "version": "9.9.9"}}
        )
        inf = verificar.Informe()
        verificar.verificar_exenciones_de_vet(inf)
        comprobar(salida_de(inf) == 2, "sin exenciones queda SIN COMPROBAR, no en verde ni rojo")
    finally:
        verificar._miembros_publicables = original
        verificar._leer_toml = original_toml


def probar_la_frescura_de_origin_se_mide_de_verdad() -> None:
    """`_copia_de_origin_al_dia` DA el veredicto correcto en los cuatro casos.

    ESTA PRUEBA NACIÓ DE UN BANCO DE MUTACIÓN, y de que el banco me pillara:
    `probar_una_copia_vieja_de_origin_no_aprueba` comprueba que el LLAMANTE
    reacciona a un veredicto negativo, pero lo consigue sustituyendo la función
    — así que desactivar la función de verdad no ponía roja ni esa prueba ni
    ninguna otra (0 de 5 la cazaban). Comprobar la reacción al veredicto no es
    comprobar que el veredicto se produzca.

    Aquí se sustituye `correr`, no la función bajo prueba: se mide la lógica
    real sin salir a la red.
    """
    original = verificar.correr
    respuestas: dict[tuple, tuple[int, str]] = {}
    verificar.correr = lambda orden, cwd=None, timeout=0: respuestas.get(
        tuple(orden), (1, "")
    )
    try:
        SHA = "a" * 40
        rev = ("git", "rev-parse", "origin/estable")
        ls = ("git", "ls-remote", "--heads", "origin", "estable")

        # AL DÍA: el sha local y el remoto coinciden.
        respuestas.clear()
        respuestas[rev] = (0, SHA + "\n")
        respuestas[ls] = (0, f"{SHA}\trefs/heads/estable\n")
        veredicto, _ = verificar._copia_de_origin_al_dia("origin/estable")
        comprobar(veredicto is True, "shas iguales → la copia está al día")

        # VIEJA: el remoto avanzó. Es el caso que da el verde inmerecido.
        respuestas[ls] = (0, "b" * 40 + "\trefs/heads/estable\n")
        veredicto, motivo = verificar._copia_de_origin_al_dia("origin/estable")
        comprobar(veredicto is False, "shas distintos → la copia está VIEJA")
        comprobar("fetch" in motivo, "y el motivo dice cómo arreglarlo")

        # NO SE PUDO PREGUNTAR: ni True ni False, que son las dos afirmaciones.
        respuestas[ls] = (1, "")
        veredicto, _ = verificar._copia_de_origin_al_dia("origin/estable")
        comprobar(veredicto is None, "el remoto mudo NO es «está al día»")

        respuestas.clear()
        respuestas[ls] = (0, f"{SHA}\trefs/heads/estable\n")  # falta el rev-parse
        veredicto, _ = verificar._copia_de_origin_al_dia("origin/estable")
        comprobar(veredicto is None, "sin la ref en el disco tampoco se afirma nada")

        # Una ref LOCAL no tiene copia remota que contrastar: no hay nada que
        # exigirle, y tratarla como «vieja» bloquearía las pruebas del banco.
        veredicto, _ = verificar._copia_de_origin_al_dia("testing")
        comprobar(veredicto is True, "una ref local no se compara con ningún remoto")
    finally:
        verificar.correr = original


def probar_una_copia_vieja_de_origin_no_aprueba() -> None:
    """Comparar contra un `origin/X` desactualizado sería un verde inmerecido.

    `verificar.py` no hace `fetch` en ningún momento, así que la copia local de
    `origin/estable` puede ser de hace días. Sin esta comprobación el guardián
    diría «ninguna versión retrocede» tras mirar un árbol que ya no existe.

    Comprueba la REACCIÓN del llamante; que el veredicto se produzca bien lo
    comprueba `probar_la_frescura_de_origin_se_mide_de_verdad`. Hacen falta las
    dos: esta sola dejaba la función de verdad sin una sola prueba encima.
    """
    original = verificar._copia_de_origin_al_dia
    original_crates = verificar._versiones_de_los_crates
    verificar._versiones_de_los_crates = lambda ref: {"quipu": "0.10.0"}
    try:
        for veredicto, motivo, etiqueta in (
            (False, "tu copia está vieja", "una copia DESACTUALIZADA"),
            (None, "el remoto no respondió", "no haber podido preguntar"),
        ):
            verificar._copia_de_origin_al_dia = lambda ref, v=veredicto, m=motivo: (v, m)
            inf = verificar.Informe()
            verificar.verificar_versiones_no_retroceden(inf, "rama", "origin/estable")
            comprobar(
                salida_de(inf) == 2,
                f"{etiqueta} deja la comparación SIN COMPROBAR, no en verde",
            )
    finally:
        verificar._copia_de_origin_al_dia = original
        verificar._versiones_de_los_crates = original_crates


if __name__ == "__main__":
    sys.exit(main())
