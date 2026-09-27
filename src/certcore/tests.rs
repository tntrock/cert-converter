//! 測試用憑證/私鑰位於 tests/fixtures（以 openssl 產生，僅供測試，非真實憑證）。

use super::*;

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/",
            $name
        ))
        .as_slice()
    };
}

fn items(bytes: &[u8]) -> Items {
    match detect(bytes).unwrap() {
        Loaded::Items(items) => items,
        Loaded::LockedPfx { .. } => panic!("unexpected PFX"),
    }
}

fn cn(der: &[u8]) -> String {
    cert_info(der).unwrap().common_name.unwrap()
}

fn pem_key(pem: &str) -> LoadedKey {
    items(pem.as_bytes()).key.unwrap()
}

#[test]
fn detects_der_cert_and_reads_info() {
    let it = items(fixture!("rsa.der"));
    assert_eq!(it.source, Source::DerCert);
    let info = cert_info(&it.certs[0]).unwrap();
    assert_eq!(info.common_name.as_deref(), Some("rsa.example.test"));
    assert!(info.not_after.ends_with("UTC"));
    assert!(info.days_left > 365);
    assert!(info.sans.contains(&"DNS: www.example.test".to_string()));
    assert!(info.sans.contains(&"IP: 192.0.2.1".to_string()));
    assert!(info.sans.contains(&"IP: 2001:db8::1".to_string()));
}

#[test]
fn pem_with_text_preamble_is_detected() {
    // `openssl x509 -text` 的輸出：PEM 區塊前有超過 1 KB 的文字說明
    let it = items(fixture!("rsa-with-text.pem"));
    assert_eq!(it.source, Source::Pem);
    assert_eq!(it.certs.len(), 1);
}

#[test]
fn utf16_pem_is_detected() {
    let it = items(fixture!("rsa-utf16.crt"));
    assert_eq!(it.certs[0], fixture!("rsa.der"));
}

#[test]
fn misordered_chain_is_sorted_and_key_matches() {
    let it = items(fixture!("rsa-bundle-misordered.pem"));
    let names: Vec<String> = it.certs.iter().map(|c| cn(c)).collect();
    assert_eq!(
        names,
        ["rsa.example.test", "Test Intermediate CA", "Test Root CA"]
    );
    assert_eq!(it.key_matches_leaf(), Some(true));
}

#[test]
fn chain_without_key_is_sorted() {
    let it = items(fixture!("rsa-certs-only.pem"));
    assert_eq!(cn(&it.certs[0]), "rsa.example.test");
}

#[test]
fn pkcs7_der_and_pem() {
    for bytes in [fixture!("chain.p7b"), fixture!("chain-pem.p7b")] {
        let it = items(bytes);
        assert_eq!(it.certs.len(), 2);
        assert_eq!(cn(&it.certs[0]), "rsa.example.test");
    }
}

#[test]
fn der_keys_are_detected() {
    assert_eq!(
        items(fixture!("rsa-pkcs8.der")).key.unwrap().kind,
        KeyKind::Pkcs8
    );
    assert_eq!(
        items(fixture!("rsa-pkcs1.der")).key.unwrap().kind,
        KeyKind::Pkcs1Rsa
    );
}

#[test]
fn key_algorithms() {
    let alg = |b: &[u8]| key_alg(&items(b).key.unwrap());
    assert_eq!(alg(fixture!("rsa.key")), KeyAlg::Rsa);
    assert_eq!(alg(fixture!("rsa-pkcs1.key")), KeyAlg::Rsa);
    assert_eq!(alg(fixture!("p256.key")), KeyAlg::EcP256);
    assert_eq!(alg(fixture!("p256-sec1.key")), KeyAlg::EcP256);
    assert_eq!(alg(fixture!("p384.key")), KeyAlg::EcP384);
    assert_eq!(alg(fixture!("ed25519.key")), KeyAlg::Ed25519);
    // EC 的 PKCS#8 私鑰不應提供 PKCS#1 選項
    assert_eq!(
        key_formats(&items(fixture!("p256.key")).key.unwrap()),
        vec![KeyFormat::Pkcs8, KeyFormat::Sec1]
    );
}

#[test]
fn rsa_pkcs1_pkcs8_roundtrip() {
    let pkcs1 = items(fixture!("rsa-pkcs1.key")).key.unwrap();
    let pkcs8 = pem_key(&export_key_pem(&pkcs1, KeyFormat::Pkcs8).unwrap());
    assert_eq!(pkcs8.kind, KeyKind::Pkcs8);
    assert!(*pkcs8.der == fixture!("rsa-pkcs8.der"));
    let back = pem_key(&export_key_pem(&pkcs8, KeyFormat::Pkcs1).unwrap());
    assert_eq!(back.kind, KeyKind::Pkcs1Rsa);
    assert!(*back.der == fixture!("rsa-pkcs1.der"));
}

#[test]
fn ec_sec1_pkcs8_roundtrip() {
    for (sec1_pem, pkcs8_pem) in [
        (fixture!("p256-sec1.key"), fixture!("p256.key")),
        (fixture!("p384-sec1.key"), fixture!("p384.key")),
    ] {
        let sec1 = items(sec1_pem).key.unwrap();
        let pkcs8 = pem_key(&export_key_pem(&sec1, KeyFormat::Pkcs8).unwrap());
        let original = items(pkcs8_pem).key.unwrap();
        assert_eq!(
            key_public_bits(&pkcs8).unwrap(),
            key_public_bits(&original).unwrap()
        );
        let back = pem_key(&export_key_pem(&pkcs8, KeyFormat::Sec1).unwrap());
        assert_eq!(back.kind, KeyKind::Sec1Ec);
        assert!(export_key_pem(&pkcs8, KeyFormat::Pkcs1).is_err());
    }
}

#[test]
fn encrypted_pkcs8_key() {
    let it = items(fixture!("rsa-enc-pkcs8.key"));
    assert!(it.key.is_none());
    let enc = it.encrypted_key.unwrap();
    assert!(decrypt_key(&enc, "wrong").is_err());
    let key = decrypt_key(&enc, "secret").unwrap();
    assert!(*key.der == fixture!("rsa-pkcs8.der"));
}

#[test]
fn legacy_encrypted_pem_keys() {
    for bytes in [
        fixture!("rsa-legacy-enc-des3.key"),
        fixture!("rsa-legacy-enc-aes128.key"),
        fixture!("p256-legacy-enc.key"),
    ] {
        let it = items(bytes);
        // 帶 Proc-Type 標頭的加密私鑰不能被當成未加密的私鑰
        assert!(it.key.is_none());
        let enc = it.encrypted_key.unwrap();
        assert!(matches!(enc, EncryptedKey::LegacyPem { .. }));
        assert!(decrypt_key(&enc, "wrong").is_err());
        let key = decrypt_key(&enc, "secret").unwrap();
        assert!(any_key_to_pkcs8_der(&key).is_ok());
    }
}

#[test]
fn unlock_modern_and_legacy_pfx() {
    for (bytes, leaf) in [
        (fixture!("rsa-modern.pfx"), "rsa.example.test"),
        (fixture!("p256-legacy.pfx"), "p256.example.test"),
    ] {
        let Loaded::LockedPfx { data } = detect(bytes).unwrap() else {
            panic!("not detected as PFX");
        };
        assert!(unlock_pfx(&data, "wrong").is_err());
        let it = unlock_pfx(&data, "secret").unwrap();
        assert_eq!(it.certs.len(), 2);
        assert_eq!(cn(&it.certs[0]), leaf);
        assert_eq!(it.key_matches_leaf(), Some(true));
    }
}

#[test]
fn build_pfx_roundtrip_both_modes() {
    let it = items(fixture!("rsa-bundle-misordered.pem"));
    let key = it.key.as_ref().unwrap();
    for legacy in [false, true] {
        let pfx = build_pfx(&it.certs, key, "pw", legacy).unwrap();
        let back = unlock_pfx(&pfx, "pw").unwrap();
        assert_eq!(back.certs, it.certs);
        assert_eq!(back.key_matches_leaf(), Some(true));
    }
}

#[test]
fn build_pfx_with_ec_key() {
    let certs = items(fixture!("p256.crt")).certs;
    let key = items(fixture!("p256-sec1.key")).key.unwrap();
    let pfx = build_pfx(&certs, &key, "pw", false).unwrap();
    assert!(unlock_pfx(&pfx, "pw").is_ok());
}

#[test]
fn build_pfx_rejects_mismatched_key() {
    let certs = items(fixture!("rsa.crt")).certs;
    let key = items(fixture!("p256.key")).key.unwrap();
    let err = build_pfx(&certs, &key, "pw", false).unwrap_err();
    assert!(err.to_string().contains("不成對"));
}

#[test]
fn pem_output_uses_lf() {
    let pem = der_to_pem("CERTIFICATE", fixture!("rsa.der"));
    assert!(!pem.contains('\r'));
}

#[test]
fn garbage_is_rejected() {
    assert!(detect(b"hello world").is_err());
    assert!(detect(&[0x30, 0x03, 0x02, 0x01, 0x00]).is_err());
}

#[test]
fn evp_bytes_to_key_matches_openssl() {
    // openssl enc -aes-256-cbc -k secret -S 0102030405060708 -md md5 -P
    let key = evp_bytes_to_key(b"secret", &[1, 2, 3, 4, 5, 6, 7, 8], 32);
    assert_eq!(
        hex_upper(&key).replace(':', ""),
        "C9E5A1BD216DBE1317E230CEF48F38EE7F0E17AD64022144BCCEC4A1AA2879AB"
    );
}
