//! Signature-chain verification for pinned installer artifacts.
//!
//! A profile pins an artifact's SHA-256. This module proves that the pinned digest is the one
//! the vendor signed: it fetches the vendor's checksum document over HTTPS, verifies its
//! OpenPGP signature against a vendor key whose fingerprint is pinned here, and requires the
//! profile's digest to appear in the signed text for the exact artifact filename.

use pgp::composed::{CleartextSignedMessage, Deserializable, DetachedSignature, SignedPublicKey};
use pgp::types::KeyDetails;

use super::{
    escape_json, find_profile, http_client, json_pair, validate_https_response, NoUsbError,
};

/// A vendor signing key shipped with NoUSB. The fingerprint was cross-checked against the
/// vendor's own publication before it was pinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedSigningKey {
    pub id: &'static str,
    pub owner: &'static str,
    pub fingerprint: &'static str,
    pub published_at: &'static str,
    armored: &'static str,
}

pub const PINNED_SIGNING_KEYS: [PinnedSigningKey; 2] = [
    PinnedSigningKey {
        id: "ubuntu-cdimage-2012",
        owner: "Ubuntu CD Image Automatic Signing Key (2012) <cdimage@ubuntu.com>",
        fingerprint: "843938DF228D22F7B3742BC0D94AA3F0EFE21092",
        published_at: "https://ubuntu.com/tutorials/how-to-verify-ubuntu",
        armored: include_str!("../../nousb-installer-profiles/keys/ubuntu-cdimage-2012.asc"),
    },
    PinnedSigningKey {
        id: "fedora-44",
        owner: "Fedora (44) <fedora-44-primary@fedoraproject.org>",
        fingerprint: "36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6",
        published_at: "https://fedoraproject.org/security/",
        armored: include_str!("../../nousb-installer-profiles/keys/fedora-44.asc"),
    },
];

pub fn pinned_signing_key(id: &str) -> Result<&'static PinnedSigningKey, NoUsbError> {
    PINNED_SIGNING_KEYS
        .iter()
        .find(|key| key.id == id)
        .ok_or_else(|| NoUsbError::ProfileParse(format!("unknown signing_key {id}")))
}

impl PinnedSigningKey {
    /// Parses the embedded key and refuses it unless its fingerprint and self-signatures check out.
    fn load(&self) -> Result<SignedPublicKey, NoUsbError> {
        let (key, _) = SignedPublicKey::from_string(self.armored).map_err(|error| {
            NoUsbError::Verification(format!("embedded key {} is unreadable: {error}", self.id))
        })?;
        let fingerprint = format!("{:X}", key.fingerprint());
        if fingerprint != self.fingerprint {
            return Err(NoUsbError::Verification(format!(
                "embedded key {} has fingerprint {fingerprint}, expected {}",
                self.id, self.fingerprint
            )));
        }
        key.verify_bindings().map_err(|error| {
            NoUsbError::Verification(format!(
                "embedded key {} self-signatures fail: {error}",
                self.id
            ))
        })?;
        Ok(key)
    }
}

/// The OpenPGP framing a vendor uses for its checksum document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumSignatureFormat {
    /// A plain checksum file plus a separate binary or armored signature (Ubuntu).
    Detached,
    /// A clearsigned checksum file (Fedora).
    Cleartext,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureVerification {
    pub profile_id: String,
    pub key_id: String,
    pub key_fingerprint: String,
    pub checksum_url: String,
    pub signature_url: Option<String>,
    pub format: ChecksumSignatureFormat,
    pub artifact_filename: String,
    pub pinned_sha256: String,
    pub signature_valid: bool,
    pub pinned_digest_signed: bool,
}

impl SignatureVerification {
    pub fn verified(&self) -> bool {
        self.signature_valid && self.pinned_digest_signed
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{{},{},{},{},\"signature_url\":{},\"format\":\"{}\",{},{},\"signature_valid\":{},\"pinned_digest_signed\":{},\"verified\":{}}}",
            json_pair("profile_id", &self.profile_id),
            json_pair("key_id", &self.key_id),
            json_pair("key_fingerprint", &self.key_fingerprint),
            json_pair("checksum_url", &self.checksum_url),
            self.signature_url
                .as_deref()
                .map(|url| format!("\"{}\"", escape_json(url)))
                .unwrap_or_else(|| "null".into()),
            match self.format {
                ChecksumSignatureFormat::Detached => "detached",
                ChecksumSignatureFormat::Cleartext => "cleartext",
            },
            json_pair("artifact_filename", &self.artifact_filename),
            json_pair("pinned_sha256", &self.pinned_sha256),
            self.signature_valid,
            self.pinned_digest_signed,
            self.verified(),
        )
    }
}

/// Verifies a detached signature over `content` with the pinned key or any of its subkeys.
pub fn verify_detached_signature(
    key: &PinnedSigningKey,
    content: &[u8],
    signature: &[u8],
) -> Result<(), NoUsbError> {
    let public_key = key.load()?;
    let signature = if signature.starts_with(b"-----BEGIN PGP SIGNATURE-----") {
        DetachedSignature::from_armor_single(signature).map(|(signature, _)| signature)
    } else {
        DetachedSignature::from_bytes(signature)
    }
    .map_err(|error| NoUsbError::Verification(format!("unreadable signature: {error}")))?;
    if signature.verify(&public_key, content).is_ok()
        || public_key
            .public_subkeys
            .iter()
            .any(|subkey| signature.verify(subkey, content).is_ok())
    {
        Ok(())
    } else {
        Err(NoUsbError::Verification(format!(
            "signature was not made by pinned key {} ({})",
            key.id, key.fingerprint
        )))
    }
}

/// Verifies a clearsigned document and returns the signed text.
pub fn verify_cleartext_signature(
    key: &PinnedSigningKey,
    document: &str,
) -> Result<String, NoUsbError> {
    let public_key = key.load()?;
    let (message, _) = CleartextSignedMessage::from_string(document).map_err(|error| {
        NoUsbError::Verification(format!("unreadable clearsigned document: {error}"))
    })?;
    let signed = message.verify(&public_key).is_ok()
        || public_key
            .public_subkeys
            .iter()
            .any(|subkey| message.verify(subkey).is_ok());
    if !signed {
        return Err(NoUsbError::Verification(format!(
            "clearsigned document was not signed by pinned key {} ({})",
            key.id, key.fingerprint
        )));
    }
    Ok(message.signed_text())
}

/// True when `checksums` lists `sha256` for exactly `filename`, in either the GNU coreutils
/// layout (`<hex> *<file>`) Ubuntu uses or the BSD layout (`SHA256 (<file>) = <hex>`) Fedora uses.
pub fn checksum_document_lists(checksums: &str, filename: &str, sha256: &str) -> bool {
    checksums.lines().any(|line| {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("SHA256 (") {
            return rest.split_once(") = ").is_some_and(|(name, digest)| {
                name == filename && digest.eq_ignore_ascii_case(sha256)
            });
        }
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
            (Some(digest), Some(name), None) => {
                digest.eq_ignore_ascii_case(sha256) && name.trim_start_matches('*') == filename
            }
            _ => false,
        }
    })
}

/// Downloads a small document over HTTPS with the same downgrade checks as artifact downloads.
pub fn fetch_https_bytes(url: &str) -> Result<Vec<u8>, NoUsbError> {
    let response = http_client()?
        .get(url)
        .send()
        .map_err(|error| NoUsbError::Io(format!("cannot fetch {url}: {error}")))?;
    validate_https_response(&response)?;
    if !response.status().is_success() {
        return Err(NoUsbError::ArtifactUnavailable(format!(
            "{url} returned HTTP {}",
            response.status()
        )));
    }
    response
        .bytes()
        .map(|bytes| bytes.to_vec())
        .map_err(|error| NoUsbError::Io(format!("cannot read {url}: {error}")))
}

/// Downloads a profile's checksum document (and detached signature) and proves that the
/// profile's pinned SHA-256 is vendor-signed. Never touches the artifact itself.
pub fn verify_profile_signature(profile_id: &str) -> Result<SignatureVerification, NoUsbError> {
    let profile = find_profile(profile_id)?;
    let key_id = profile.signing_key.clone().ok_or_else(|| {
        NoUsbError::ArtifactUnavailable(format!(
            "{profile_id} has no pinned vendor signing key; its digest cannot be signature-checked"
        ))
    })?;
    let key = pinned_signing_key(&key_id)?;
    let filename = profile.artifact_filename.clone().ok_or_else(|| {
        NoUsbError::ArtifactUnavailable(format!("{profile_id} has no pinned artifact filename"))
    })?;
    let checksum_bytes = fetch_https_bytes(&profile.checksum_url)?;
    let detached = profile
        .signature_url
        .as_ref()
        .filter(|url| **url != profile.checksum_url)
        .cloned();
    let (format, signed_text) = match &detached {
        Some(signature_url) => {
            let signature = fetch_https_bytes(signature_url)?;
            verify_detached_signature(key, &checksum_bytes, &signature)?;
            (
                ChecksumSignatureFormat::Detached,
                String::from_utf8_lossy(&checksum_bytes).into_owned(),
            )
        }
        None => (
            ChecksumSignatureFormat::Cleartext,
            verify_cleartext_signature(key, &String::from_utf8_lossy(&checksum_bytes))?,
        ),
    };
    let pinned_digest_signed = checksum_document_lists(&signed_text, &filename, &profile.sha256);
    let verification = SignatureVerification {
        profile_id: profile.id,
        key_id: key.id.into(),
        key_fingerprint: key.fingerprint.into(),
        checksum_url: profile.checksum_url,
        signature_url: detached,
        format,
        artifact_filename: filename,
        pinned_sha256: profile.sha256,
        signature_valid: true,
        pinned_digest_signed,
    };
    if !verification.pinned_digest_signed {
        return Err(NoUsbError::Verification(format!(
            "the vendor-signed checksum document does not list the pinned digest for {}",
            verification.artifact_filename
        )));
    }
    Ok(verification)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured 2026-10-22 from releases.ubuntu.com/24.04 and download.fedoraproject.org.
    const UBUNTU_SHA256SUMS: &[u8] = include_bytes!("../tests/fixtures/ubuntu-24.04-SHA256SUMS");
    const UBUNTU_SHA256SUMS_GPG: &[u8] =
        include_bytes!("../tests/fixtures/ubuntu-24.04-SHA256SUMS.gpg");
    const FEDORA_CHECKSUM: &str =
        include_str!("../tests/fixtures/Fedora-Workstation-44-1.7-x86_64-CHECKSUM");

    #[test]
    fn embedded_keys_match_their_pinned_fingerprints() {
        for key in PINNED_SIGNING_KEYS {
            key.load().unwrap();
        }
        assert!(pinned_signing_key("nobody").is_err());
    }

    #[test]
    fn ubuntu_detached_signature_verifies_and_lists_the_pinned_server_digest() {
        let key = pinned_signing_key("ubuntu-cdimage-2012").unwrap();
        verify_detached_signature(key, UBUNTU_SHA256SUMS, UBUNTU_SHA256SUMS_GPG).unwrap();
        let server = find_profile("ubuntu-24.04-server").unwrap();
        assert!(checksum_document_lists(
            &String::from_utf8_lossy(UBUNTU_SHA256SUMS),
            server.artifact_filename.as_deref().unwrap(),
            &server.sha256,
        ));

        let mut tampered = UBUNTU_SHA256SUMS.to_vec();
        tampered[0] ^= 1;
        assert!(verify_detached_signature(key, &tampered, UBUNTU_SHA256SUMS_GPG).is_err());
        let fedora = pinned_signing_key("fedora-44").unwrap();
        assert!(
            verify_detached_signature(fedora, UBUNTU_SHA256SUMS, UBUNTU_SHA256SUMS_GPG).is_err()
        );
    }

    #[test]
    fn fedora_clearsigned_checksum_verifies_and_lists_the_pinned_digest() {
        let key = pinned_signing_key("fedora-44").unwrap();
        let signed = verify_cleartext_signature(key, FEDORA_CHECKSUM).unwrap();
        let fedora = find_profile("fedora-44-workstation").unwrap();
        assert!(checksum_document_lists(
            &signed,
            fedora.artifact_filename.as_deref().unwrap(),
            &fedora.sha256,
        ));
        let tampered = FEDORA_CHECKSUM.replacen("1620295f", "0620295f", 1);
        assert!(verify_cleartext_signature(key, &tampered).is_err());
        let ubuntu = pinned_signing_key("ubuntu-cdimage-2012").unwrap();
        assert!(verify_cleartext_signature(ubuntu, FEDORA_CHECKSUM).is_err());
    }

    #[test]
    fn checksum_lines_must_match_filename_and_digest_exactly() {
        let gnu = "abc123 *ubuntu.iso\nfff000 *other.iso\n";
        assert!(checksum_document_lists(gnu, "ubuntu.iso", "ABC123"));
        assert!(!checksum_document_lists(gnu, "ubuntu.iso", "fff000"));
        assert!(!checksum_document_lists(gnu, "buntu.iso", "abc123"));
        let bsd = "# comment\nSHA256 (fedora.iso) = abc123\n";
        assert!(checksum_document_lists(bsd, "fedora.iso", "abc123"));
        assert!(!checksum_document_lists(bsd, "fedora.iso", "abc124"));
    }
}
