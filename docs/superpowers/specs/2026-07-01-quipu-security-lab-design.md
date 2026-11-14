# Quipu Security Lab — diseño

**Fecha:** 2026-07-01
**Estado:** aprobado (brainstorm) · pendiente de plan de implementación
**Alcance de esta versión:** Etapa A (núcleo CI). Etapa B especificada, no implementada.

## 1. Motivación

Con cada avance tecnológico los atacantes aprenden, se adaptan y entrenan sus
propios modelos locales de IA para ciberataque. Una batería fija de tests
envejece; la mejor defensa es un sistema que **se ataca a sí mismo y se corrige**
—modelo "antivirus con laboratorio incluido": muestra → análisis → firma de
defensa → protección permanente.

Quipu ya tiene un red-team interno (`hackerbot`) con ataques deterministas
(`tamper`, `truncation`, `uniqueness`, `forgery`). El Security Lab lo eleva a un
**adversario adaptativo auto-hospedado** que evoluciona sus ataques, recuerda lo
aprendido y convierte cada brecha en un test de regresión permanente.

## 2. Principios rectores

1. **Adversario que evoluciona, no batería fija:** guarda lo aprendido y sube el
   listón en cada corrida.
2. **El arma no viaja con el producto:** las herramientas ofensivas nunca se
   compilan en el artefacto publicado (crate ni rueda de PyPI).
3. **Las defensas no se apagan en silencio:** si alguien debilita la capa
   antihacker, el CI falla en rojo.
4. **El veredicto no se puede falsear:** el corpus de hallazgos va sellado.
5. **Dos velocidades, dos jaulas:** guardia rápido determinista (CI) + banco
   pesado físicamente aislado (contenedor sin red).
6. **Nunca inventar primitivas:** el laboratorio compone y ataca; jamás sustituye
   una primitiva verificada por uno propio. Solo ataca a Quipu, nunca a terceros.

## 3. Arquitectura

Dos velocidades, dos jaulas, por etapas.

```
   ETAPA A (ahora)      NÚCLEO CI  (Rust puro, feature-gated `lab`)
                        ─ superficie 1: fuga en ciphertext/formato
                        ─ superficie 4: falsificación adaptativa
                        ─ 3 candados de blindaje
                        aislamiento = NO se compila en release

   ETAPA B (spec)       BANCO OFFLINE  (contenedor quipu-lab, --network none)
                        ─ superficie 2: timing / canales laterales
                        ─ superficie 3: guessing acelerado por IA
                        aislamiento = jaula física (sin red, sin claves reales)
```

- **Núcleo CI:** Rust determinista con semilla fija (reproducible). Su aislamiento
  es que *no se compila* en release.
- **Banco offline:** donde vive el ML pesado; su aislamiento es físico
  (contenedor sin red).

## 4. Etapa A — Núcleo CI (implementación de esta versión)

Nuevo módulo `src/lab/` bajo `#[cfg(feature = "lab")]`.

### 4.a Motor adaptativo (`src/lab/engine.rs`)

- Fuzzer *breach-guided*: mantiene una población de entradas/mutaciones, puntúa
  cuáles se "acercan" a una brecha y prioriza esas líneas (recocido / genético
  simple). PRNG con **semilla fija** → reproducible en CI.
- Trait común `Attack` para que cada superficie sea una unidad aislada y
  testeable:
  - `fn name(&self) -> &'static str`
  - `fn step(&mut self, rng, corpus) -> AttackOutcome` (Advanced / Breach / NoProgress)
- `AttackReport` reutiliza/extiende el existente en `hackerbot` (name, attempts,
  breaches) más un contador de "acercamientos" para guiar la búsqueda.

### 4.b Superficie 1 — fuga en ciphertext/formato (`src/lab/leak.rs`)

- Distinguidor estadístico: ¿el contenedor, el padding Padmé o el codec base-N
  correlacionan con longitud o estructura del plaintext?
- Genera pares (plaintext estructurado vs aleatorio de igual tamaño), codifica y
  mide sesgo (p. ej. longitud de salida, distribución de símbolos) con un test
  estadístico simple. **Brecha = sesgo detectable** que permita distinguir.

### 4.c Superficie 4 — falsificación adaptativa (`src/lab/forge.rs`)

Evoluciona el `forgery_attack` actual (stride fijo) hacia ataques dirigidos:

- **Frankensignatures:** mezcla componentes Ed25519 / ML-DSA de dos firmas
  válidas distintas; el combinador AND debe rechazar.
- **Key-substitution:** intenta que una firma verifique bajo otra clave (el
  preimagen liga la verifying key completa + label `quipu/v3/sign`).
- **Recorte/relleno de regiones del contenedor QSG1** (magic/version/flags/len).
- **Brecha = `decode_verified` acepta algo forjado.**

### 4.d Los tres candados de blindaje

- **Aislamiento de compilación:** todo `src/lab/` bajo `#[cfg(feature = "lab")]`;
  la feature **no** se activa en release ni en la rueda de PyPI (maturin usa
  `features = ["python"]`, sin `lab`). Test que confirma que el núcleo publicado
  no expone el laboratorio.
- **Tamper-evidence (`src/lab/guard.rs`):** meta-tests que afirman que las
  defensas antihacker siguen presentes y efectivas:
  - `ct_eq` sigue comparando en tiempo constante y rechaza diferencias.
  - la validación de parámetros KDF sigue bloqueando parámetros maliciosos
    (regresión del DoS Argon2 ya corregido).
  - `zeroize` sigue aplicándose al material de clave en drop.
  Borrar o debilitar cualquiera → CI rojo.
- **Integridad del corpus (`src/lab/corpus.rs`):** corpus append-only encadenado
  por hash (cada entrada incluye el hash de la anterior; hash raíz fijo).
  Envenenar el historial (inyectar "todo verde") rompe la cadena y se detecta.

### 4.e Corpus (`lab/corpus/`)

- Versionado en el repo: semillas + hallazgos + cadena de hash.
- Cada brecha nueva se congela como **test de regresión permanente** (bucle
  atacar → corregir → firmar defensa).

### 4.f Integración

- Ejecutable de desarrollo: `cargo run --example securitylab --features lab`.
- CI: job que corre `cargo test --features lab` (semilla fija) y los meta-tests
  de blindaje. Se mantiene el build de release **sin** `lab`.

## 5. Etapa B — Banco offline (especificada, no implementada)

- **Contenedor `quipu-lab`** (`lab/Dockerfile`): imagen aparte, `--network none`,
  usuario no-root, FS de solo lectura, montaje efímero del código, **cero** acceso
  a claves reales / `oprf_seed.bin`. Toda la maquinaria ML vive solo aquí. Imagen
  reproducible con hash fijado (enlaza con integridad del corpus).
- **Superficie 2 — timing:** harness que mide `decode` / `decode_verified` / KDF
  con muchas repeticiones y busca variación dependiente del secreto (análisis
  estadístico; opción de amplificar con ML). Complementa lo heredado de los crates
  constant-time.
- **Superficie 3 — guessing IA:** modela un atacante que prioriza contraseñas con
  un modelo local y verifica que el costo Argon2id + pepper por intento no
  colapsa con parámetros límite.

## 6. Pruebas y definición de éxito

- Cada superficie es una unidad con sus tests; el motor tiene tests con semilla
  fija (reproducible).
- Meta-tests de blindaje (los tres candados).
- **Éxito:** toda brecha encontrada se convierte en test de regresión permanente
  y `breaches == 0` en CI. El laboratorio "gana" cuando un ataque nuevo no
  encuentra nada que los anteriores no cubrieran.

## 7. Alcance / YAGNI

- **Dentro (Etapa A):** motor adaptativo, superficies 1 y 4, tres candados,
  corpus encadenado, ejemplo + job de CI.
- **Fuera por ahora (Etapa B, especificada):** contenedor, timing, ML real.
- **Explícitamente fuera:** capacidad ofensiva contra terceros; romper o sustituir
  primitivas. El laboratorio solo ataca a Quipu y solo compone primitivas
  verificadas.
