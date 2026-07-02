# Quipu Security Lab — banco offline (Etapa B)

Mesa de laboratorio PESADA y AISLADA. No corre en CI ni viaja en el producto.

## Qué contiene
- **Superficie 2 — timing** (`src/lab/timing.rs`): busca variación de tiempo
  dependiente del secreto en `ct_eq` y en `decode`.
- **Superficie 3 — guessing** (`src/lab/guessing.rs`): modela un atacante que
  prioriza contraseñas con IA y verifica que el coste Argon2id por intento
  arruina el guessing masivo.

## Cómo correrlo

Local (rápido, para desarrollo):

```
cargo run --release --example securitylab_offline --features lab-offline
```

Aislado en contenedor (recomendado; sin red, sin claves, solo lectura):

```
bash lab/run.sh
```

## ML-ready
El banco es Rust determinista (reproducible, apto para auditoría). El contenedor
queda PREPARADO para enchufar modelos ML pesados (distinguidores de timing,
ranking de contraseñas) si algún día se quiere; no se empaqueta ninguno hoy para
no añadir dependencias pesadas ni no-determinismo.
