// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024-2026 Juan Carlos Isaza Arenas

//! Almacén de clientes y API keys (SQLite).
//!
//! Es la ÚNICA costura entre el plano de datos (este servidor) y el plano de
//! control (pagos): la pasarela escribe (emite/revoca/activa keys), el servidor
//! lee (valida en cada petición). Ver docs/quipu-oprf-server-plan.md.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use subtle::ConstantTimeEq;

use crate::keys::{self, GeneratedKey};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS customer(
    id           TEXT PRIMARY KEY,
    email        TEXT NOT NULL,
    plan         TEXT NOT NULL,
    provider_ref TEXT,
    created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_key(
    id            TEXT PRIMARY KEY,
    customer_id   TEXT NOT NULL REFERENCES customer(id),
    prefix        TEXT NOT NULL UNIQUE,
    key_hash      BLOB NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    quota_monthly INTEGER NOT NULL,
    expires_at    INTEGER,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER,
    revoked_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_key_prefix ON api_key(prefix);
CREATE TABLE IF NOT EXISTS usage(
    key_id TEXT NOT NULL REFERENCES api_key(id),
    period TEXT NOT NULL,
    count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(key_id, period)
);
";

/// Resultado de validar una key presentada. Solo `Valid` autoriza la evaluación.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthResult {
    Valid {
        key_id: String,
        customer_id: String,
        quota_monthly: u64,
        used: u64,
        /// Plan del cliente. Lo necesita la ruta de evaluación para aplicar los
        /// límites de ráfaga que le corresponden (ver `plans::limits_for`).
        plan: String,
    },
    /// Formato inválido o key inexistente (mismo mensaje: no filtrar cuáles existen).
    Unknown,
    Inactive,
    Expired,
    QuotaExceeded,
}

pub struct Store {
    conn: Connection,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("reloj")
        .as_secs() as i64
}

/// Periodo de facturación actual como "YYYY-MM" (UTC), sin dependencias de fechas.
fn current_period() -> String {
    period_of(now())
}

fn period_of(unix_secs: i64) -> String {
    let (y, m, _d) = civil_from_days(unix_secs.div_euclid(86_400));
    format!("{y:04}-{m:02}")
}

/// Algoritmo de Howard Hinnant: días desde 1970-01-01 -> (año, mes, día) UTC.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

impl Store {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let store = Self {
            conn: Connection::open(path)?,
        };
        store.init()?;
        Ok(store)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let store = Self {
            conn: Connection::open_in_memory()?,
        };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(SCHEMA)
    }

    /// Crea un cliente y devuelve su id.
    pub fn create_customer(&self, email: &str, plan: &str) -> rusqlite::Result<String> {
        let id = keys::random_id();
        self.conn.execute(
            "INSERT INTO customer(id, email, plan, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, email, plan, now()],
        )?;
        Ok(id)
    }

    /// Emite una API key para un cliente. Devuelve el secreto (mostrar UNA vez).
    pub fn issue_key(
        &self,
        customer_id: &str,
        quota_monthly: u64,
        expires_at: Option<i64>,
    ) -> rusqlite::Result<GeneratedKey> {
        let key = keys::generate();
        let id = keys::random_id();
        self.conn.execute(
            "INSERT INTO api_key(id, customer_id, prefix, key_hash, active, quota_monthly, \
             expires_at, created_at) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)",
            params![
                id,
                customer_id,
                key.prefix,
                key.hash.as_slice(),
                quota_monthly as i64,
                expires_at,
                now()
            ],
        )?;
        Ok(key)
    }

    /// Valida una key presentada SIN consumir cuota (la lectura de autorización).
    pub fn verify(&self, presented: &str) -> rusqlite::Result<AuthResult> {
        let Some((prefix, hash)) = keys::parse(presented) else {
            return Ok(AuthResult::Unknown);
        };

        let row = self
            .conn
            .query_row(
                "SELECT k.id, k.customer_id, k.key_hash, k.active, k.quota_monthly, \
                        k.expires_at, c.plan \
                 FROM api_key k JOIN customer c ON c.id = k.customer_id \
                 WHERE k.prefix = ?1",
                params![prefix],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Option<i64>>(5)?,
                        r.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?;

        let Some((key_id, customer_id, stored_hash, active, quota, expires_at, plan)) = row else {
            return Ok(AuthResult::Unknown);
        };

        // Comparación en tiempo constante contra el hash almacenado.
        if stored_hash.len() != hash.len() || stored_hash.as_slice().ct_eq(hash.as_slice()).unwrap_u8() != 1 {
            return Ok(AuthResult::Unknown);
        }
        if active == 0 {
            return Ok(AuthResult::Inactive);
        }
        if let Some(exp) = expires_at
            && now() >= exp {
                return Ok(AuthResult::Expired);
            }

        let used = self.usage_count(&key_id, &current_period())?;
        let quota = quota as u64;
        if used >= quota {
            return Ok(AuthResult::QuotaExceeded);
        }

        Ok(AuthResult::Valid {
            key_id,
            customer_id,
            quota_monthly: quota,
            used,
            plan,
        })
    }

    /// Registra una evaluación exitosa: +1 en el periodo actual y `last_used_at`.
    pub fn record_usage(&self, key_id: &str) -> rusqlite::Result<()> {
        let period = current_period();
        self.conn.execute(
            "INSERT INTO usage(key_id, period, count) VALUES (?1, ?2, 1) \
             ON CONFLICT(key_id, period) DO UPDATE SET count = count + 1",
            params![key_id, period],
        )?;
        self.conn.execute(
            "UPDATE api_key SET last_used_at = ?1 WHERE id = ?2",
            params![now(), key_id],
        )?;
        Ok(())
    }

    fn usage_count(&self, key_id: &str, period: &str) -> rusqlite::Result<u64> {
        let count: Option<i64> = self
            .conn
            .query_row(
                "SELECT count FROM usage WHERE key_id = ?1 AND period = ?2",
                params![key_id, period],
                |r| r.get(0),
            )
            .optional()?;
        Ok(count.unwrap_or(0) as u64)
    }

    /// Activa o desactiva una key por su `prefix` (lo que hace el webhook de pagos).
    pub fn set_active(&self, prefix: &str, active: bool) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE api_key SET active = ?1 WHERE prefix = ?2",
            params![active as i64, prefix],
        )
    }

    /// Revoca una key: la desactiva y marca `revoked_at`.
    pub fn revoke(&self, prefix: &str) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE api_key SET active = 0, revoked_at = ?1 WHERE prefix = ?2",
            params![now(), prefix],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded() -> (Store, String, String) {
        let store = Store::open_in_memory().unwrap();
        let customer = store.create_customer("dev@example.com", "beta").unwrap();
        let key = store.issue_key(&customer, 5, None).unwrap();
        (store, customer, key.secret)
    }

    #[test]
    fn valid_key_authorizes() {
        let (store, customer, secret) = seeded();
        match store.verify(&secret).unwrap() {
            AuthResult::Valid {
                customer_id, used, ..
            } => {
                assert_eq!(customer_id, customer);
                assert_eq!(used, 0);
            }
            other => panic!("esperaba Valid, fue {other:?}"),
        }
    }

    #[test]
    fn unknown_and_tampered_keys_rejected() {
        let (store, _c, secret) = seeded();
        assert_eq!(store.verify("garbage").unwrap(), AuthResult::Unknown);
        // Misma longitud/prefijo pero hash distinto -> Unknown (no autoriza).
        let mut tampered = secret.clone();
        tampered.pop();
        tampered.push(if secret.ends_with('0') { '1' } else { '0' });
        assert_eq!(store.verify(&tampered).unwrap(), AuthResult::Unknown);
    }

    #[test]
    fn revoke_deactivates_immediately() {
        let (store, _c, secret) = seeded();
        let (prefix, _) = keys::parse(&secret).unwrap();
        store.revoke(&prefix).unwrap();
        assert_eq!(store.verify(&secret).unwrap(), AuthResult::Inactive);
    }

    #[test]
    fn quota_is_enforced() {
        let (store, _c, secret) = seeded(); // cuota 5
        let key_id = match store.verify(&secret).unwrap() {
            AuthResult::Valid { key_id, .. } => key_id,
            other => panic!("{other:?}"),
        };
        for _ in 0..5 {
            store.record_usage(&key_id).unwrap();
        }
        assert_eq!(store.verify(&secret).unwrap(), AuthResult::QuotaExceeded);
    }

    #[test]
    fn expired_key_rejected() {
        let store = Store::open_in_memory().unwrap();
        let customer = store.create_customer("dev@example.com", "beta").unwrap();
        let key = store.issue_key(&customer, 5, Some(now() - 1)).unwrap();
        assert_eq!(store.verify(&key.secret).unwrap(), AuthResult::Expired);
    }

    #[test]
    fn period_format_is_year_month() {
        // 2026-07-10 ~ unix 1_783_000_000 cae en 2026-06/07; validamos el formato.
        let p = period_of(1_783_000_000);
        assert_eq!(p.len(), 7);
        assert_eq!(&p[4..5], "-");
        // 1970-01-01
        assert_eq!(period_of(0), "1970-01");
    }
}
