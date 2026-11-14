//! Vista HTML presentable del CBOM firmado, para el portafolio (D11).
//!
//! Lee uno o varios `cbom.json` YA generados y su `<cbom>.sig.json` hermano, y
//! emite UNA página autocontenida (CSS propio embebido, sin CDN ni red — D26) que
//! presenta la "radiografía criptográfica" de cada perfil: sus activos, el
//! INVARIANTE de cada perfil computado con su verde/rojo, y el estado de la firma.
//!
//! Qué NO hace, a propósito: no firma ni verifica criptográficamente (eso es del
//! core, `examples/verificar_cbom`). Aquí solo se CRUZA el SHA-256 del artefacto
//! contra el que registra el `.sig.json` —para decir "la firma es de ESTE CBOM" o
//! "la firma quedó vieja"— y se transcriben los campos de la firma. La página es
//! tan veraz como el CBOM, que a su vez es tan veraz como el descriptor curado.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Un activo criptográfico leído del CBOM (no del descriptor: la vista refleja el
/// artefacto FIRMADO, no la fuente).
struct Activo {
    nombre: String,
    modulo: String,
    primitive: String,
    parameter_set: String,
    classical_level: Option<u64>,
    nist_pq_level: u64,
    cnsa: String,
    rol: Option<String>,
    canal: Option<String>,
    rationale: String,
}

struct Perfil {
    nombre: String,
    version: String,
    descripcion: String,
    licencia: String,
    conformidad: String,
    validado_fips: String,
    activos: Vec<Activo>,
    /// Estado de la firma hermana (`<cbom>.sig.json`), si existe.
    firma: Option<Firma>,
    /// SHA-256 del propio `cbom.json` (calculado aquí).
    sha256: String,
}

struct Firma {
    algoritmo: String,
    clave: String,
    huella_clave: String,
    longitud_firma: u64,
    /// SHA-256 que la firma dice haber firmado.
    sha256_firmado: String,
}

/// Escape HTML mínimo para texto en nodos y atributos.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Busca `properties[].value` por `name` en un nodo de CycloneDX.
fn prop<'a>(props: &'a Value, nombre: &str) -> Option<&'a str> {
    props
        .as_array()?
        .iter()
        .find(|p| p.get("name").and_then(Value::as_str) == Some(nombre))
        .and_then(|p| p.get("value"))
        .and_then(Value::as_str)
}

/// Lee un perfil desde el contenido de su `cbom.json` (y el `.sig.json` opcional).
fn leer_perfil(cbom_crudo: &str, sig_crudo: Option<&str>) -> Result<Perfil, String> {
    let v: Value = serde_json::from_str(cbom_crudo).map_err(|e| format!("CBOM mal formado: {e}"))?;

    let comp = v
        .get("metadata")
        .and_then(|m| m.get("component"))
        .ok_or("CBOM sin metadata.component")?;
    let cp = comp
        .get("properties")
        .cloned()
        .unwrap_or(Value::Array(vec![]));

    let activos = v
        .get("components")
        .and_then(Value::as_array)
        .ok_or("CBOM sin components[]")?
        .iter()
        .map(|c| {
            let ap = c
                .get("cryptoProperties")
                .and_then(|x| x.get("algorithmProperties"));
            let props = c.get("properties").cloned().unwrap_or(Value::Array(vec![]));
            Activo {
                nombre: c.get("name").and_then(Value::as_str).unwrap_or("?").to_string(),
                modulo: prop(&props, "quipu:modulo").unwrap_or("").to_string(),
                primitive: ap
                    .and_then(|x| x.get("primitive"))
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_string(),
                parameter_set: ap
                    .and_then(|x| x.get("parameterSetIdentifier"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                classical_level: ap
                    .and_then(|x| x.get("classicalSecurityLevel"))
                    .and_then(Value::as_u64),
                nist_pq_level: ap
                    .and_then(|x| x.get("nistQuantumSecurityLevel"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                cnsa: prop(&props, "quipu:cnsa").unwrap_or("").to_string(),
                rol: prop(&props, "quipu:rol").map(str::to_string),
                canal: prop(&props, "quipu:canal").map(str::to_string),
                rationale: prop(&props, "quipu:rationale")
                    .or_else(|| c.get("description").and_then(Value::as_str))
                    .unwrap_or("")
                    .to_string(),
            }
        })
        .collect();

    let firma = sig_crudo.and_then(|s| {
        let sv: Value = serde_json::from_str(s).ok()?;
        Some(Firma {
            algoritmo: sv.get("algoritmo").and_then(Value::as_str).unwrap_or("?").to_string(),
            clave: sv.get("clave").and_then(Value::as_str).unwrap_or("(demo)").to_string(),
            huella_clave: sv.get("huella_clave").and_then(Value::as_str).unwrap_or("").to_string(),
            longitud_firma: sv.get("longitud_firma").and_then(Value::as_u64).unwrap_or(0),
            sha256_firmado: sv
                .get("sha256_artefacto")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
    });

    Ok(Perfil {
        nombre: comp.get("name").and_then(Value::as_str).unwrap_or("?").to_string(),
        version: comp.get("version").and_then(Value::as_str).unwrap_or("").to_string(),
        descripcion: comp.get("description").and_then(Value::as_str).unwrap_or("").to_string(),
        licencia: comp
            .get("licenses")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|l| l.get("license"))
            .and_then(|l| l.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        conformidad: prop(&cp, "quipu:conformidad").unwrap_or("").to_string(),
        validado_fips: prop(&cp, "quipu:validado-fips-140-3").unwrap_or("no").to_string(),
        activos,
        firma,
        sha256: hex(&Sha256::digest(cbom_crudo.as_bytes())),
    })
}

// ---------- El invariante, computado (con su verde/rojo) ----------

/// Un canal asimétrico (kem, firma) resiste si empareja un socio clásico con uno
/// PQ. Quitar el socio PQ lo marca roto — es el caso rojo del README.
struct FilaCanal {
    canal: String,
    clasico: Vec<String>,
    pq: Vec<String>,
    resiste: bool,
}

enum Invariante {
    /// Perfil híbrido: cada canal asimétrico empareja clásico + PQ.
    Hibrido { canales: Vec<FilaCanal>, pasa: bool },
    /// Perfil CNSA puro: 0 primitivas asimétricas cuántico-vulnerables entre las requeridas.
    /// `requeridos` = cuántos activos declaran `cnsa:"requerido"`; si es 0, la afirmación
    /// es VACUA y no debe salir verde (D20/D30: verde por camino no recorrido).
    Cnsa { vulnerables: Vec<String>, requeridas_pq: Vec<String>, requeridos: usize, pasa: bool },
}

/// Asimétrico = todo lo que NO sea simétrico/hash/derivación/DRBG/MAC. Se cierra
/// por defecto (D20/D23): una primitiva DESCONOCIDA cae del lado «asimétrica»
/// —«revisar»—, no del lado «n/a». Antes esto era una lista blanca
/// (`kem|signature|keyagreement`) y se cegó ante el vocabulario real del repo
/// —`keyagree`, sin sufijo—: un acuerdo de clave clásico requerido desaparecía del
/// cómputo y el invariante CNSA salía verde en falso (concilio 2026-09-08, opus/
/// sonnet/fable por ejecución). El precio de cerrar por defecto: una primitiva
/// simétrica nueva no listada saldría marcada hasta añadirla aquí — la dirección
/// segura, no la ciega.
fn es_asimetrico(primitive: &str) -> bool {
    !matches!(primitive, "ae" | "hash" | "kdf" | "drbg" | "mac")
}

fn calcular_invariante(p: &Perfil) -> Invariante {
    let hibrido = p.activos.iter().any(|a| a.rol.is_some());
    if hibrido {
        // Agrupar por canal, quedándonos con los asimétricos (kem, firma).
        let mut canales: Vec<FilaCanal> = Vec::new();
        for a in &p.activos {
            let Some(canal) = &a.canal else { continue };
            if canal != "kem" && canal != "firma" {
                continue;
            }
            let fila = match canales.iter_mut().find(|f| &f.canal == canal) {
                Some(f) => f,
                None => {
                    canales.push(FilaCanal {
                        canal: canal.clone(),
                        clasico: vec![],
                        pq: vec![],
                        resiste: false,
                    });
                    canales.last_mut().unwrap()
                }
            };
            match a.rol.as_deref() {
                Some("clasico") => fila.clasico.push(a.nombre.clone()),
                Some("pq") => fila.pq.push(a.nombre.clone()),
                _ => {}
            }
        }
        // Resiste el canal que empareja AMBAS familias: un socio clásico Y uno PQ.
        // Solo-clásico cae con la cuántica; solo-PQ cae si la familia PQ se rompe —y
        // el texto verde promete resistir «aunque caiga una de las dos familias»,
        // que EXIGE las dos. Antes solo miraba `!pq.is_empty()`, más laxo que su
        // propia promesa (concilio 2026-09-08). El par rojo cubre los dos lados (D33).
        for f in &mut canales {
            f.resiste = !f.clasico.is_empty() && !f.pq.is_empty();
        }
        let pasa = !canales.is_empty() && canales.iter().all(|f| f.resiste);
        Invariante::Hibrido { canales, pasa }
    } else {
        // CNSA puro: ningún asimétrico REQUERIDO puede ser cuántico-vulnerable
        // (nivel PQ 0). Los ML-* tienen nivel >= 1.
        let mut vulnerables = Vec::new();
        let mut requeridas_pq = Vec::new();
        let mut requeridos = 0usize;
        for a in &p.activos {
            if a.cnsa != "requerido" {
                continue;
            }
            requeridos += 1;
            if es_asimetrico(&a.primitive) {
                if a.nist_pq_level == 0 {
                    vulnerables.push(a.nombre.clone());
                } else {
                    requeridas_pq.push(a.nombre.clone());
                }
            }
        }
        // Verde EXIGE que exista al menos un requerido: «0 vulnerables entre las
        // requeridas» es vacuamente cierto si no hay ninguna requerida (todas mal
        // etiquetadas), y eso no puede pasar por sano (D20/D30).
        let pasa = vulnerables.is_empty() && requeridos > 0;
        Invariante::Cnsa { vulnerables, requeridas_pq, requeridos, pasa }
    }
}

// ---------- Render ----------

const CSS: &str = r#"
:root{--bg:#f7f6f3;--card:#fff;--ink:#1b1b1a;--muted:#6b6a66;--line:#e3e1db;
--ok:#1a7f4b;--ok-bg:#e6f4ec;--bad:#b3261e;--bad-bg:#fbe9e7;--pq:#2f5fd0;--cl:#8a6d1f;--accent:#b3852a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:32px 20px 64px}
header h1{font-size:26px;margin:0 0 4px}
header p.sub{color:var(--muted);margin:0 0 6px;font-size:15px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:22px 24px;margin:22px 0;box-shadow:0 1px 2px rgba(0,0,0,.03)}
.card h2{margin:0 0 2px;font-size:20px}
.card h2 .ver{color:var(--muted);font-weight:500;font-size:15px}
.card p.desc{color:#38372f;margin:8px 0 16px}
.inv{border-radius:10px;padding:12px 16px;margin:0 0 18px;font-size:14px}
.inv.ok{background:var(--ok-bg);border:1px solid #bfe3ce}
.inv.bad{background:var(--bad-bg);border:1px solid #f2c4bf}
.inv .badge{font-weight:700;letter-spacing:.02em}
.inv.ok .badge{color:var(--ok)}
.inv.bad .badge{color:var(--bad)}
.chan{margin:8px 0 0;font-size:13.5px;color:#3a3a36}
.chan .c{display:inline-block;min-width:62px;font-weight:600;text-transform:capitalize}
.tag{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;margin:1px 3px 1px 0;border:1px solid}
.tag.pq{color:var(--pq);border-color:#c3d0f2;background:#eef2fc}
.tag.cl{color:var(--cl);border-color:#e6d9ac;background:#f7f0da}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
td.mono,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;border-radius:6px;padding:0 7px;font-size:12px;font-weight:600}
.pill.req{background:#eef2fc;color:var(--pq)}
.pill.aux{background:#f0efea;color:var(--muted)}
.pill.out{background:#f7f0da;color:var(--cl)}
.sig{margin-top:16px;border-top:1px dashed var(--line);padding-top:14px;font-size:13.5px}
.sig .st{font-weight:700}
.sig .st.ok{color:var(--ok)}
.sig .st.bad{color:var(--bad)}
.sig dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;margin:8px 0 0}
.sig dt{color:var(--muted)}
.sig dd{margin:0;word-break:break-all}
.limit{color:var(--muted);font-size:13px;margin-top:10px;font-style:italic}
footer{color:var(--muted);font-size:12.5px;margin-top:28px;text-align:center;line-height:1.7}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;
background:#efeee9;border-radius:5px;padding:1px 5px}
"#;

fn render_activos(p: &Perfil, out: &mut String) {
    out.push_str("<table><thead><tr>");
    out.push_str("<th>Activo</th><th>Primitiva</th><th>Parámetro</th>");
    out.push_str("<th>Clásico</th><th>NIST PQ</th><th>CNSA</th><th>Módulo</th>");
    out.push_str("</tr></thead><tbody>\n");
    for a in &p.activos {
        out.push_str(&format!("<tr><td title=\"{}\"><strong>", esc(&a.rationale)));
        out.push_str(&esc(&a.nombre));
        out.push_str("</strong>");
        if let Some(rol) = &a.rol {
            let cls = match rol.as_str() {
                "pq" => "tag pq",
                "clasico" => "tag cl",
                _ => "tag",
            };
            out.push_str(&format!(
                " <span class=\"{cls}\">{}</span>",
                esc(rol)
            ));
        }
        out.push_str("</td>");
        out.push_str(&format!("<td>{}</td>", esc(&a.primitive)));
        out.push_str(&format!("<td class=\"mono\">{}</td>", esc(&a.parameter_set)));
        out.push_str(&format!(
            "<td class=\"num\">{}</td>",
            a.classical_level.map(|n| n.to_string()).unwrap_or_else(|| "—".into())
        ));
        out.push_str(&format!(
            "<td class=\"num\">{}</td>",
            if a.nist_pq_level == 0 { "—".to_string() } else { format!("cat {}", a.nist_pq_level) }
        ));
        let (pill, txt) = match a.cnsa.as_str() {
            "requerido" => ("pill req", "requerido"),
            "auxiliar" => ("pill aux", "auxiliar"),
            "fuera-de-alcance" => ("pill out", "fuera de alcance"),
            "no-aplica" => ("pill aux", "n/a"),
            otro => ("pill aux", otro),
        };
        out.push_str(&format!("<td><span class=\"{pill}\">{}</span></td>", esc(txt)));
        out.push_str(&format!("<td class=\"mono\">{}</td>", esc(&a.modulo)));
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table>\n");
}

fn render_invariante(p: &Perfil, out: &mut String) {
    match calcular_invariante(p) {
        Invariante::Hibrido { canales, pasa } => {
            let cls = if pasa { "ok" } else { "bad" };
            let badge = if pasa { "INVARIANTE ✔" } else { "INVARIANTE ✘" };
            out.push_str(&format!("<div class=\"inv {cls}\"><span class=\"badge\">{badge}</span> — "));
            out.push_str("Ningún canal asimétrico depende solo de lo clásico: KEM y firma emparejan una primitiva clásica con una PQ, así que el canal resiste aunque una de las dos familias caiga.");
            for f in &canales {
                let marca = if f.resiste { "✔" } else { "✘ (sin socio PQ)" };
                out.push_str(&format!(
                    "<div class=\"chan\"><span class=\"c\">{}</span> {marca} &nbsp;",
                    esc(&f.canal)
                ));
                for n in &f.clasico {
                    out.push_str(&format!("<span class=\"tag cl\">{}</span>", esc(n)));
                }
                for n in &f.pq {
                    out.push_str(&format!("<span class=\"tag pq\">{}</span>", esc(n)));
                }
                out.push_str("</div>");
            }
            out.push_str("</div>\n");
        }
        Invariante::Cnsa { vulnerables, requeridas_pq, requeridos, pasa } => {
            let cls = if pasa { "ok" } else { "bad" };
            let n = vulnerables.len();
            let badge = if pasa { "INVARIANTE ✔" } else { "INVARIANTE ✘" };
            out.push_str(&format!("<div class=\"inv {cls}\"><span class=\"badge\">{badge}</span> — "));
            if requeridos == 0 {
                out.push_str("no hay ninguna primitiva declarada como requerida por CNSA 2.0: el invariante no puede AFIRMARSE (revisa el campo <code>quipu:cnsa</code> del descriptor).</div>\n");
                return;
            }
            out.push_str(&format!(
                "{n} primitivas cuántico-vulnerables entre las requeridas por CNSA 2.0. "
            ));
            if !requeridas_pq.is_empty() {
                out.push_str("Los establecimientos de clave y firmas requeridos son puros post-cuánticos: ");
                out.push_str(
                    &requeridas_pq
                        .iter()
                        .map(|n| format!("<span class=\"tag pq\">{}</span>", esc(n)))
                        .collect::<String>(),
                );
            }
            if !vulnerables.is_empty() {
                out.push_str(" ROTO por: ");
                out.push_str(
                    &vulnerables
                        .iter()
                        .map(|n| format!("<span class=\"tag cl\">{}</span>", esc(n)))
                        .collect::<String>(),
                );
            }
            out.push_str("</div>\n");
        }
    }
}

fn render_firma(p: &Perfil, out: &mut String) {
    out.push_str("<div class=\"sig\">");
    match &p.firma {
        None => {
            out.push_str("<span class=\"st\">Firma:</span> no hay <code>.sig.json</code> junto a este CBOM.");
        }
        Some(f) => {
            let al_dia = f.sha256_firmado == p.sha256;
            let (cls, txt) = if al_dia {
                ("ok", "firma al día — atada a este CBOM exacto")
            } else {
                ("bad", "FIRMA VIEJA — el CBOM cambió desde que se firmó (vuelve a firmar)")
            };
            out.push_str(&format!("<span class=\"st {cls}\">Firma: {txt}</span>"));
            out.push_str("<dl>");
            out.push_str(&format!("<dt>Algoritmo</dt><dd class=\"mono\">{}</dd>", esc(&f.algoritmo)));
            out.push_str(&format!(
                "<dt>Longitud</dt><dd class=\"mono\">{} bytes</dd>",
                f.longitud_firma
            ));
            out.push_str(&format!("<dt>Clave</dt><dd class=\"mono\">{}", esc(&f.clave)));
            if !f.huella_clave.is_empty() {
                out.push_str(&format!(" · huella {}", esc(&f.huella_clave)));
            }
            out.push_str("</dd>");
            out.push_str(&format!("<dt>SHA-256 CBOM</dt><dd class=\"mono\">{}</dd>", esc(&p.sha256)));
            out.push_str("</dl>");
            out.push_str("<p class=\"limit\">La firma se comprueba criptográficamente, de forma independiente, con <code>cargo run --release --example verificar_cbom -- &lt;cbom.json&gt;</code> en el core. Esta vista solo cruza el SHA-256.</p>");
        }
    }
    out.push_str("</div>\n");
}

fn render_perfil(p: &Perfil, out: &mut String) {
    out.push_str("<section class=\"card\">");
    out.push_str(&format!(
        "<h2>{} <span class=\"ver\">v{}</span></h2>",
        esc(&p.nombre),
        esc(&p.version)
    ));
    out.push_str(&format!("<p class=\"desc\">{}</p>", esc(&p.descripcion)));
    render_invariante(p, out);
    render_activos(p, out);
    out.push_str(&format!(
        "<p class=\"limit\">Licencia {} · FIPS 140-3 validado: {} · {}</p>",
        esc(&p.licencia),
        esc(&p.validado_fips),
        esc(&p.conformidad)
    ));
    render_firma(p, out);
    out.push_str("</section>\n");
}

/// Entrada del subcomando. `entradas` = pares (contenido cbom.json, contenido sig opcional).
/// `sello` = timestamp reproducible ya formateado.
pub fn render(entradas: &[(String, Option<String>)], sello: &str) -> Result<String, String> {
    let perfiles: Vec<Perfil> = entradas
        .iter()
        .map(|(cbom, sig)| leer_perfil(cbom, sig.as_deref()))
        .collect::<Result<_, _>>()?;

    let mut cuerpo = String::new();
    for p in &perfiles {
        render_perfil(p, &mut cuerpo);
    }

    let contraste = if perfiles.len() >= 2 {
        "<p class=\"desc\">El contraste es la pieza: el perfil <strong>CNSA</strong> es puro (cumple el mandato de la NSA, pero si una familia PQ cae no queda socio); el <strong>híbrido</strong> resiste aunque caiga una de las dos familias. El CBOM lo hace medible y verificable, no un adjetivo.</p>"
    } else {
        ""
    };

    Ok(format!(
        "<!doctype html>\n<html lang=\"es\"><head><meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Radiografía criptográfica de Quipu — CBOM</title>\n\
         <style>{CSS}</style></head>\n<body><div class=\"wrap\">\n\
         <header><h1>Radiografía criptográfica de Quipu</h1>\n\
         <p class=\"sub\">CBOM (Cryptography Bill of Materials, CycloneDX 1.6) — el inventario firmable de las primitivas criptográficas de Quipu, con su invariante verificable.</p>\n\
         {contraste}</header>\n\
         {cuerpo}\
         <footer>Generado por <code>quipu-cbom</code> · {sello} · reproducible con <code>SOURCE_DATE_EPOCH</code>.<br>\
         Autodescripción (Ángulo A): la vista refleja el descriptor curado, no escanea nada. La detección sobre terceros vive en <code>nexus</code>.</footer>\n\
         </div></body></html>\n"
    ))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Un CBOM híbrido mínimo con un canal (firma) que empareja clásico + PQ.
    fn cbom_hibrido(con_pq: bool) -> String {
        let mut comps = vec![serde_json::json!({
            "type":"cryptographic-asset","name":"Ed25519",
            "cryptoProperties":{"algorithmProperties":{
                "primitive":"signature","parameterSetIdentifier":"Ed25519",
                "classicalSecurityLevel":128,"nistQuantumSecurityLevel":0}},
            "properties":[{"name":"quipu:rol","value":"clasico"},
                          {"name":"quipu:canal","value":"firma"},
                          {"name":"quipu:cnsa","value":"no-aplica"}]
        })];
        if con_pq {
            comps.push(serde_json::json!({
                "type":"cryptographic-asset","name":"ML-DSA-87",
                "cryptoProperties":{"algorithmProperties":{
                    "primitive":"signature","parameterSetIdentifier":"ML-DSA-87",
                    "classicalSecurityLevel":256,"nistQuantumSecurityLevel":5}},
                "properties":[{"name":"quipu:rol","value":"pq"},
                              {"name":"quipu:canal","value":"firma"},
                              {"name":"quipu:cnsa","value":"no-aplica"}]
            }));
        }
        serde_json::json!({
            "bomFormat":"CycloneDX","specVersion":"1.6",
            "metadata":{"component":{"type":"library","name":"quipu","version":"0.12.0",
                "description":"híbrido","licenses":[{"license":{"id":"AGPL-3.0-or-later"}}],
                "properties":[]}},
            "components": comps
        })
        .to_string()
    }

    #[test]
    fn hibrido_con_socio_pq_pasa() {
        let p = leer_perfil(&cbom_hibrido(true), None).unwrap();
        match calcular_invariante(&p) {
            Invariante::Hibrido { pasa, canales } => {
                assert!(pasa, "el canal firma con clásico+PQ DEBE pasar");
                assert!(canales.iter().all(|c| c.resiste));
            }
            _ => panic!("debería detectarse híbrido"),
        }
    }

    // CASO ROJO (D33): quitar el socio PQ del canal lo marca ROTO. Es exactamente
    // el mutante del README: "quitar el socio PQ de un canal lo marca roto".
    #[test]
    fn hibrido_sin_socio_pq_rompe() {
        let p = leer_perfil(&cbom_hibrido(false), None).unwrap();
        match calcular_invariante(&p) {
            Invariante::Hibrido { pasa, canales } => {
                assert!(!pasa, "un canal firma SOLO-clásico NO debe pasar el invariante");
                assert!(canales.iter().any(|c| !c.resiste));
            }
            _ => panic!("debería detectarse híbrido"),
        }
    }

    // El cruce de SHA distingue firma al día de firma vieja: si el .sig apunta a
    // otro SHA, la vista debe marcarla vieja (control positivo + rojo).
    #[test]
    fn firma_vieja_se_detecta() {
        let cbom = cbom_hibrido(true);
        let sha_real = hex(&Sha256::digest(cbom.as_bytes()));
        let sig_al_dia = serde_json::json!({"algoritmo":"x","sha256_artefacto":sha_real}).to_string();
        let sig_vieja = serde_json::json!({"algoritmo":"x","sha256_artefacto":"deadbeef"}).to_string();

        let p_ok = leer_perfil(&cbom, Some(&sig_al_dia)).unwrap();
        assert_eq!(p_ok.firma.as_ref().unwrap().sha256_firmado, p_ok.sha256, "al día: SHAs iguales");

        let p_mal = leer_perfil(&cbom, Some(&sig_vieja)).unwrap();
        assert_ne!(p_mal.firma.as_ref().unwrap().sha256_firmado, p_mal.sha256, "vieja: SHAs distintos");
    }

    // CBOM estilo CNSA (SIN quipu:rol → rama CNSA del invariante). Cada activo:
    // (nombre, primitive, cnsa, nist_pq_level).
    fn cbom_cnsa(activos: &[(&str, &str, &str, u64)]) -> String {
        let comps: Vec<_> = activos
            .iter()
            .map(|(n, prim, cnsa, pq)| {
                serde_json::json!({
                    "type":"cryptographic-asset","name":n,
                    "cryptoProperties":{"algorithmProperties":{
                        "primitive":prim,"parameterSetIdentifier":"x",
                        "nistQuantumSecurityLevel":pq}},
                    "properties":[{"name":"quipu:cnsa","value":cnsa}]
                })
            })
            .collect();
        serde_json::json!({
            "bomFormat":"CycloneDX","specVersion":"1.6",
            "metadata":{"component":{"type":"library","name":"quipu-cnsa","version":"0.1.1",
                "description":"cnsa","licenses":[{"license":{"id":"AGPL-3.0-or-later"}}],
                "properties":[]}},
            "components": comps
        })
        .to_string()
    }

    // CASO ROJO del hallazgo del concilio (2026-09-08): un acuerdo de clave CLÁSICO
    // requerido (`keyagree`, nivel PQ 0) DEBE salir vulnerable. Antes `es_asimetrico`
    // casaba solo "keyagreement" y este activo se caía del cómputo → falso VERDE.
    #[test]
    fn cnsa_keyagree_clasico_requerido_rompe() {
        let cbom = cbom_cnsa(&[
            ("AES-256-GCM", "ae", "requerido", 5),
            ("X25519", "keyagree", "requerido", 0), // clásico, cuántico-vulnerable
            ("ML-KEM-1024", "kem", "requerido", 5),
        ]);
        let p = leer_perfil(&cbom, None).unwrap();
        match calcular_invariante(&p) {
            Invariante::Cnsa { pasa, vulnerables, .. } => {
                assert!(!pasa, "un keyagree clásico requerido DEBE romper el invariante CNSA");
                assert!(vulnerables.iter().any(|n| n == "X25519"), "X25519 debe estar en vulnerables");
            }
            _ => panic!("debería detectarse CNSA (sin rol)"),
        }
    }

    // Control positivo: el mismo perfil SIN el keyagree clásico pasa (si no, el test
    // de arriba pasaría por cegar todo, no por discriminar).
    #[test]
    fn cnsa_sin_clasico_vulnerable_pasa() {
        let cbom = cbom_cnsa(&[
            ("AES-256-GCM", "ae", "requerido", 5),
            ("ML-DSA-87", "signature", "requerido", 5),
            ("ML-KEM-1024", "kem", "requerido", 5),
        ]);
        let p = leer_perfil(&cbom, None).unwrap();
        match calcular_invariante(&p) {
            Invariante::Cnsa { pasa, .. } => assert!(pasa, "CNSA puro post-cuántico DEBE pasar"),
            _ => panic!("debería detectarse CNSA"),
        }
    }

    // CASO ROJO de la guardia de vacuidad: un perfil sin NINGÚN requerido (todos mal
    // etiquetados) NO puede salir verde por «0 vulnerables» vacuo (D20/D30).
    #[test]
    fn cnsa_vacuo_no_pasa() {
        let cbom = cbom_cnsa(&[
            ("RSA-2048", "signature", "requeridoo", 0), // typo: no cuenta como requerido
        ]);
        let p = leer_perfil(&cbom, None).unwrap();
        match calcular_invariante(&p) {
            Invariante::Cnsa { pasa, requeridos, .. } => {
                assert_eq!(requeridos, 0, "ningún activo bien etiquetado como requerido");
                assert!(!pasa, "invariante VACUO no puede salir verde");
            }
            _ => panic!("debería detectarse CNSA"),
        }
    }

    // CASO ROJO del segundo falso negativo (comparte causa): un canal híbrido SOLO-PQ,
    // sin socio clásico, NO debe pasar — el texto verde promete resistir «aunque caiga
    // una de las dos familias», que exige las dos.
    #[test]
    fn hibrido_solo_pq_sin_clasico_rompe() {
        let cbom = serde_json::json!({
            "bomFormat":"CycloneDX","specVersion":"1.6",
            "metadata":{"component":{"type":"library","name":"quipu","version":"0.12.0",
                "description":"híbrido","licenses":[{"license":{"id":"AGPL-3.0-or-later"}}],
                "properties":[]}},
            "components":[serde_json::json!({
                "type":"cryptographic-asset","name":"ML-KEM-1024",
                "cryptoProperties":{"algorithmProperties":{
                    "primitive":"kem","parameterSetIdentifier":"ML-KEM-1024",
                    "nistQuantumSecurityLevel":5}},
                "properties":[{"name":"quipu:rol","value":"pq"},
                              {"name":"quipu:canal","value":"kem"}]
            })]
        }).to_string();
        let p = leer_perfil(&cbom, None).unwrap();
        match calcular_invariante(&p) {
            Invariante::Hibrido { pasa, canales } => {
                assert!(!pasa, "un canal SOLO-PQ (sin clásico) NO debe pasar el invariante híbrido");
                assert!(canales.iter().any(|c| !c.resiste));
            }
            _ => panic!("debería detectarse híbrido"),
        }
    }
}
