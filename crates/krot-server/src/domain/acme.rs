//! ACME HTTP-01 client for the apex-domain certificate.
//!
//! Owns two pieces of state:
//!
//! - a [`ChallengeStore`] shared with `domain/http.rs`, which serves
//!   `GET /.well-known/acme-challenge/<token>` by looking up
//!   `token → key_authorization`;
//! - the on-disk `data_dir/acme/{account.json, cert.pem, key.pem}` cache.
//!
//! The current implementation acquires a fresh certificate on every server
//! start when the on-disk cache is missing. Renewal-before-expiry is a
//! documented TODO (`renew_if_needed` is a placeholder that always
//! decides "renew").

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{info, warn};

use crate::error::ServerError;

const POLL_ATTEMPTS: usize = 60;

/// `token → key_authorization` map that the HTTP-01 responder consults.
pub type ChallengeStore = Arc<RwLock<HashMap<String, String>>>;

#[must_use]
pub fn new_store() -> ChallengeStore {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Serve the response for a stored `/.well-known/acme-challenge/<token>`.
pub fn lookup_challenge(store: &ChallengeStore, token: &str) -> Option<String> {
    store.read().unwrap().get(token).cloned()
}

/// Acquire (or reuse) a valid apex certificate.
///
/// Blocks until the ACME server issues a certificate; the caller MUST make
/// sure the port-80 HTTP router (which reads from `challenges`) is already
/// serving before invoking this.
pub async fn acquire_cert(
    contact: &str,
    apex: &str,
    directory: Option<&str>,
    data_dir: &Path,
    challenges: ChallengeStore,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ServerError> {
    let acme_dir = data_dir.join("acme");
    fs::create_dir_all(&acme_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // §12.1: "Certificate material is persisted under the server data
        // directory (default /var/lib/krot/acme/), mode 0700."
        fs::set_permissions(&acme_dir, fs::Permissions::from_mode(0o700))?;
    }

    if let Some(pair) = try_load_cached(&acme_dir)? {
        info!("reusing cached ACME certificate");
        return Ok(pair);
    }

    let dir_url = directory.unwrap_or(LetsEncrypt::Staging.url());
    info!(apex, dir_url, "requesting fresh ACME certificate");

    let account = load_or_create_account(&acme_dir, contact, dir_url).await?;

    let identifier = Identifier::Dns(apex.to_string());
    let mut order = account
        .new_order(&NewOrder::new(&[identifier]))
        .await
        .map_err(|e| ServerError::Keys(format!("new_order: {e}")))?;

    // §12.1: iterate authorizations, provision the http-01 response in
    // the shared challenge store, then mark each challenge ready.
    {
        let mut authzs = order.authorizations();
        while let Some(authz) = authzs.next().await {
            let mut authz = authz.map_err(|e| ServerError::Keys(format!("authorizations: {e}")))?;
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| ServerError::Keys("no http-01 challenge offered".into()))?;
            let key_auth = challenge.key_authorization();
            challenges
                .write()
                .unwrap()
                .insert(challenge.token.clone(), key_auth.as_str().to_string());
            challenge
                .set_ready()
                .await
                .map_err(|e| ServerError::Keys(format!("set_challenge_ready: {e}")))?;
    }
    }
    let status = order
        .poll_ready(
            &RetryPolicy::new()
                .initial_delay(Duration::from_millis(500))
                .backoff(2.0)
                .timeout(Duration::from_secs(POLL_ATTEMPTS as u64)),
        )
        .await
        .map_err(|e| ServerError::Keys(format!("order not ready: {e}")))?;
    if status != OrderStatus::Ready {
        return Err(ServerError::Keys("acme order invalid".into()));
    }
    let cert_key = KeyPair::generate().map_err(ServerError::Rcgen)?;
    let mut params = CertificateParams::new(vec![apex.to_string()]).map_err(ServerError::Rcgen)?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, apex);
    params.distinguished_name = dn;
    let csr = params
        .serialize_request(&cert_key)
        .map_err(ServerError::Rcgen)?;

    order
        .finalize_csr(csr.der())
        .await
        .map_err(|e| ServerError::Keys(format!("finalize: {e}")))?;

    let mut cert_pem: Option<String> = None;
    for _ in 0..POLL_ATTEMPTS {
        if let Some(pem) = order
            .certificate()
            .await
            .map_err(|e| ServerError::Keys(format!("certificate poll: {e}")))?
        {
            cert_pem = Some(pem);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let cert_pem =
        cert_pem.ok_or_else(|| ServerError::Keys("acme did not return a certificate".into()))?;

    // ACME succeeded — flush the token cache so nothing lingers.
    challenges.write().unwrap().clear();

    fs::write(acme_dir.join("cert.pem"), &cert_pem)?;
    fs::write(acme_dir.join("key.pem"), cert_key.serialize_pem())?;

    let chain = parse_cert_chain(&cert_pem)?;
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.serialize_der()));
    Ok((chain, key_der))
}

async fn load_or_create_account(
    acme_dir: &Path,
    contact: &str,
    directory: &str,
) -> Result<Account, ServerError> {
    let creds_path = acme_dir.join("account.json");
    if creds_path.exists() {
        let text = fs::read_to_string(&creds_path)?;
        let creds: AccountCredentials = serde_json::from_str(&text)
            .map_err(|e| ServerError::Keys(format!("bad account.json: {e}")))?;
        return Account::builder()
            .map_err(|e| ServerError::Keys(format!("account builder: {e}")))?
            .from_credentials(creds)
            .await
            .map_err(|e| ServerError::Keys(format!("account restore: {e}")));
    }
    let contact_owned = contact.to_string();
    let contacts: Vec<&str> = vec![contact_owned.as_str()];
    let (account, creds) = Account::builder()
        .map_err(|e| ServerError::Keys(format!("account builder: {e}")))?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory.to_string(),
            None,
        )
        .await
        .map_err(|e| ServerError::Keys(format!("account create: {e}")))?;

    let text = serde_json::to_string_pretty(&creds)
        .map_err(|e| ServerError::Keys(format!("serialize creds: {e}")))?;
    fs::write(&creds_path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&creds_path, fs::Permissions::from_mode(0o600));
    }
    Ok(account)
}

/// Days before `notAfter` at which a cached certificate is considered stale
/// and re-acquired. Matches the LE guidance of a 30-day renewal window.
pub const RENEWAL_THRESHOLD_DAYS: i64 = 30;

/// Attempt to reuse an already-issued certificate. Parses the leaf cert
/// and treats it as fresh only when it is at least [`RENEWAL_THRESHOLD_DAYS`]
/// away from `notAfter`.
fn try_load_cached(
    acme_dir: &Path,
) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>, ServerError> {
    let cert_path = acme_dir.join("cert.pem");
    let key_path = acme_dir.join("key.pem");
    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }
    let cert_pem = fs::read_to_string(&cert_path)?;
    let key_pem = fs::read_to_string(&key_path)?;
    let chain = match parse_cert_chain(&cert_pem) {
        Ok(c) => c,
        Err(e) => {
            warn!("cached cert unreadable, requesting fresh one: {e}");
            return Ok(None);
        }
    };
    let leaf = chain
        .first()
        .ok_or_else(|| ServerError::Keys("cert chain is empty".into()))?;
    if !cert_still_fresh(leaf.as_ref(), RENEWAL_THRESHOLD_DAYS)? {
        info!("cached cert within renewal window, requesting fresh one");
        return Ok(None);
    }
    let key_der = key_from_pem(&key_pem)?;
    Ok(Some((chain, key_der)))
}

/// Returns `true` when `cert_der` is still valid for at least `threshold_days`
/// days past today.
pub fn cert_still_fresh(cert_der: &[u8], threshold_days: i64) -> Result<bool, ServerError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| ServerError::Keys(format!("cert parse: {e}")))?;
    let not_after_ts = parsed.validity().not_after.timestamp();
    let not_after = time::OffsetDateTime::from_unix_timestamp(not_after_ts)
        .map_err(|_| ServerError::Keys("bad notAfter timestamp".into()))?;
    let threshold = time::OffsetDateTime::now_utc() + time::Duration::days(threshold_days);
    Ok(not_after >= threshold)
}

fn parse_cert_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>, ServerError> {
    use base64::Engine as _;
    let mut out = Vec::new();
    let mut inside = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            inside = true;
            b64.clear();
            continue;
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            inside = false;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| ServerError::Keys(format!("bad cert base64: {e}")))?;
            out.push(CertificateDer::from(bytes));
            continue;
        }
        if inside {
            b64.push_str(line.trim());
        }
    }
    if out.is_empty() {
        return Err(ServerError::Keys("no CERTIFICATE blocks in chain".into()));
    }
    Ok(out)
}

fn key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>, ServerError> {
    use base64::Engine as _;
    let mut inside = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        if line.contains("BEGIN") && line.contains("PRIVATE KEY") {
            inside = true;
            b64.clear();
            continue;
        }
        if line.contains("END") && line.contains("PRIVATE KEY") {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| ServerError::Keys(format!("bad key base64: {e}")))?;
            return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes)));
        }
        if inside {
            b64.push_str(line.trim());
        }
    }
    Err(ServerError::Keys(
        "no PRIVATE KEY block in cached key".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_returns_stored_value() {
        let store = new_store();
        store
            .write()
            .unwrap()
            .insert("abc".into(), "abc.thumbprint".into());
        assert_eq!(
            lookup_challenge(&store, "abc").as_deref(),
            Some("abc.thumbprint")
        );
        assert!(lookup_challenge(&store, "missing").is_none());
    }

    #[test]
    fn expiry_check_treats_short_lived_cert_as_stale() {
        // Generate a self-signed cert that expires in 5 days — should be
        // treated as needing renewal at the 30-day threshold.
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["example.test".into()]).unwrap();
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + time::Duration::days(5);
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        assert!(!cert_still_fresh(&der, 30).unwrap());
        assert!(cert_still_fresh(&der, 3).unwrap());
    }
}
