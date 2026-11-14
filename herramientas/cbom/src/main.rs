//! Genera el CBOM (CycloneDX 1.6) de un perfil de Quipu desde su descriptor.
//!
//! Ángulo A del plan CBOM: quipu se saca su propia "radiografía criptográfica".
//! El descriptor (`descriptor.json`) es el dato curado —lo que quipu declara de
//! sí mismo—; este binario solo lo envuelve en CycloneDX 1.6 válido. No detecta
//! nada por su cuenta (eso sería el generador para terceros, que vive en nexus).

use serde::{Deserialize, Serialize};
use std::io::Write;

mod html;

const USO: &str = "\
quipu-cbom — CBOM (CycloneDX 1.6) de un perfil de Quipu

USO:
  quipu-cbom [<descriptor.json>]            genera el CBOM del descriptor (por defecto: descriptor.json)
  quipu-cbom html <cbom.json>...            vista HTML de portafolio de uno o varios CBOM firmados
  quipu-cbom --help                         esta ayuda

La fecha se fija con SOURCE_DATE_EPOCH para obtener artefactos reproducibles.";

// ---------- Descriptor de entrada (curado a mano) ----------

#[derive(Deserialize)]
struct Descriptor {
    perfil: Perfil,
    activos: Vec<Activo>,
}

#[derive(Deserialize)]
struct Perfil {
    nombre: String,
    version: String,
    descripcion: String,
    licencia: String,
    repositorio: String,
    validado_fips_140_3: bool,
    nota_conformidad: String,
}

#[derive(Deserialize)]
struct Activo {
    nombre: String,
    modulo: String,
    primitive: String,
    oid: Option<String>,
    #[serde(rename = "parameterSetIdentifier")]
    parameter_set: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(rename = "cryptoFunctions")]
    crypto_functions: Vec<String>,
    #[serde(rename = "classicalSecurityLevel")]
    classical_level: Option<u32>,
    #[serde(rename = "nistQuantumSecurityLevel")]
    nist_pq_level: u32,
    cnsa: String,
    rationale: String,
    // Opcionales: perfil híbrido (clasico|pq|simetrico) y canal (cifrado|kem|firma|kdf|hash|drbg)
    #[serde(default)]
    rol: Option<String>,
    #[serde(default)]
    canal: Option<String>,
}

// ---------- CycloneDX 1.6 de salida ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Cbom {
    bom_format: &'static str,
    spec_version: &'static str,
    serial_number: String,
    version: u32,
    metadata: Metadata,
    components: Vec<Component>,
}

#[derive(Serialize)]
struct Metadata {
    timestamp: String,
    tools: Tools,
    component: AppComponent,
}

#[derive(Serialize)]
struct Tools {
    components: Vec<ToolComponent>,
}

#[derive(Serialize)]
struct ToolComponent {
    #[serde(rename = "type")]
    kind: &'static str,
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppComponent {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    version: String,
    description: String,
    licenses: Vec<LicenseWrap>,
    external_references: Vec<ExtRef>,
    properties: Vec<Prop>,
}

#[derive(Serialize)]
struct LicenseWrap {
    license: LicenseId,
}
#[derive(Serialize)]
struct LicenseId {
    id: String,
}

#[derive(Serialize)]
struct ExtRef {
    #[serde(rename = "type")]
    kind: &'static str,
    url: String,
}

#[derive(Serialize)]
struct Prop {
    name: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Component {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    description: String,
    crypto_properties: CryptoProperties,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Prop>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CryptoProperties {
    asset_type: &'static str,
    algorithm_properties: AlgorithmProperties,
    #[serde(skip_serializing_if = "Option::is_none")]
    oid: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AlgorithmProperties {
    primitive: String,
    parameter_set_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    execution_environment: &'static str,
    implementation_platform: &'static str,
    certification_level: Vec<&'static str>,
    crypto_functions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classical_security_level: Option<u32>,
    nist_quantum_security_level: u32,
}

// ---------- Utilidades deterministas (sin deps externas) ----------

/// FNV-1a 64-bit → serialNumber estable y sintácticamente UUID. No pretende ser
/// un UUID v5 real; solo un identificador reproducible para el mismo perfil.
fn serial_determinista(semilla: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in semilla.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let a = h;
    // segundo bloque para llenar 128 bits
    let mut h2 = h;
    for b in semilla.bytes().rev() {
        h2 ^= b as u64;
        h2 = h2.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!(
        "urn:uuid:{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16,
        a as u16,
        (h2 >> 48) as u16,
        h2 & 0xffff_ffff_ffff
    )
}

/// epoch (segundos UTC) → "YYYY-MM-DDTHH:MM:SSZ" (algoritmo civil de Hinnant).
fn rfc3339_utc(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let (h, mi, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn ahora() -> String {
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        });
    rfc3339_utc(epoch)
}

/// `html <cbom.json>...`: lee cada CBOM + su `.sig.json` hermano y emite la vista.
fn subcomando_html(rutas: &[String]) {
    if rutas.is_empty() {
        eprintln!("uso: quipu-cbom html <cbom.json> [<cbom2.json> ...]");
        std::process::exit(2);
    }
    let entradas: Vec<(String, Option<String>)> = rutas
        .iter()
        .map(|r| {
            let cbom = std::fs::read_to_string(r)
                .unwrap_or_else(|e| panic!("no pude leer {r}: {e}"));
            let sig = std::fs::read_to_string(format!("{r}.sig.json")).ok();
            (cbom, sig)
        })
        .collect();
    let pagina = html::render(&entradas, &ahora()).unwrap_or_else(|e| panic!("render HTML: {e}"));
    std::io::stdout().write_all(pagina.as_bytes()).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--help" | "-h") => {
            println!("{USO}");
            return;
        }
        Some("html") => {
            subcomando_html(&args[1..]);
            return;
        }
        _ => {}
    }

    let ruta = args.into_iter().next().unwrap_or_else(|| "descriptor.json".into());
    let crudo = std::fs::read_to_string(&ruta)
        .unwrap_or_else(|e| panic!("no pude leer {ruta}: {e}"));
    let d: Descriptor = serde_json::from_str(&crudo)
        .unwrap_or_else(|e| panic!("descriptor mal formado: {e}"));

    let ref_perfil = format!("{}@{}", d.perfil.nombre, d.perfil.version);

    let components: Vec<Component> = d
        .activos
        .iter()
        .map(|a| {
            let mut props = vec![
                Prop { name: "quipu:modulo".into(), value: a.modulo.clone() },
                Prop { name: "quipu:cnsa".into(), value: a.cnsa.clone() },
            ];
            props.push(Prop {
                name: "quipu:rationale".into(),
                value: a.rationale.clone(),
            });
            if let Some(r) = &a.rol {
                props.push(Prop { name: "quipu:rol".into(), value: r.clone() });
            }
            if let Some(c) = &a.canal {
                props.push(Prop { name: "quipu:canal".into(), value: c.clone() });
            }
            Component {
                kind: "cryptographic-asset",
                bom_ref: format!("crypto/{}", a.nombre),
                name: a.nombre.clone(),
                description: a.rationale.clone(),
                crypto_properties: CryptoProperties {
                    asset_type: "algorithm",
                    algorithm_properties: AlgorithmProperties {
                        primitive: a.primitive.clone(),
                        parameter_set_identifier: a.parameter_set.clone(),
                        mode: a.mode.clone(),
                        execution_environment: "software-plain-ram",
                        implementation_platform: "generic",
                        certification_level: vec!["none"],
                        crypto_functions: a.crypto_functions.clone(),
                        classical_security_level: a.classical_level,
                        nist_quantum_security_level: a.nist_pq_level,
                    },
                    oid: a.oid.clone(),
                },
                properties: props,
            }
        })
        .collect();

    let fips = if d.perfil.validado_fips_140_3 { "sí" } else { "no" };

    let cbom = Cbom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        serial_number: serial_determinista(&ref_perfil),
        version: 1,
        metadata: Metadata {
            timestamp: ahora(),
            tools: Tools {
                components: vec![ToolComponent {
                    kind: "application",
                    name: "quipu-cbom",
                    version: env!("CARGO_PKG_VERSION"),
                }],
            },
            component: AppComponent {
                kind: "library",
                bom_ref: ref_perfil.clone(),
                name: d.perfil.nombre.clone(),
                version: d.perfil.version.clone(),
                description: d.perfil.descripcion.clone(),
                licenses: vec![LicenseWrap { license: LicenseId { id: d.perfil.licencia.clone() } }],
                external_references: vec![ExtRef { kind: "vcs", url: d.perfil.repositorio.clone() }],
                properties: vec![
                    Prop { name: "quipu:validado-fips-140-3".into(), value: fips.into() },
                    Prop { name: "quipu:conformidad".into(), value: d.perfil.nota_conformidad },
                ],
            },
        },
        components,
    };

    let salida = serde_json::to_string_pretty(&cbom).expect("serializar CBOM");
    std::io::stdout().write_all(salida.as_bytes()).unwrap();
    std::io::stdout().write_all(b"\n").unwrap();
}
