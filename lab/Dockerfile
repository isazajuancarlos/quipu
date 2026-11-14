# Contenedor del banco offline del Quipu Security Lab.
# Aislamiento: se EJECUTA con `--network none`, usuario no-root y FS de solo
# lectura (ver lab/run.sh). El arma no viaja con el producto: esta imagen es
# solo para investigación local, nunca se publica ni entra en el crate/rueda.
# Base fijada por versión (para reproducibilidad, se puede fijar por @sha256).
FROM rust:1.90-slim-bookworm

# Usuario no-root.
RUN useradd --create-home --uid 1000 labrunner
WORKDIR /work

# Copia el código (solo lo necesario para compilar el banco).
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples

# Compila el banco offline en release.
RUN cargo build --release --example securitylab_offline --features lab-offline

USER labrunner
# Corre el banco. Sin red, sin claves reales (montadas fuera).
ENTRYPOINT ["/work/target/release/examples/securitylab_offline"]
