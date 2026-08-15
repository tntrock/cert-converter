//! 核心邏輯：格式偵測、憑證解析、各種轉換。
//! 這個模組刻意與 GUI 分離，方便單獨測試與維護。
//!
//! 安全性設計：所有私鑰/憑證資料僅存在於記憶體，不寫任何暫存檔；
//! 全程無任何網路呼叫，可在完全離線環境使用。

use anyhow::{anyhow, bail, Result};

use p12_keystore::{
    Certificate as P12Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, MacAlgorithm,
    Pkcs12ImportPolicy, PrivateKey as P12PrivateKey, PrivateKeyChain,
};

use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::RsaPrivateKey;

use ::pem as pemc;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

// ----------------------------------------------------------------------------
// 資料型別
// ----------------------------------------------------------------------------

/// 私鑰的編碼種類
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyKind {
    /// PKCS#8：`-----BEGIN PRIVATE KEY-----`（可為 RSA / EC / Ed25519…）
    Pkcs8,
    /// PKCS#1：`-----BEGIN RSA PRIVATE KEY-----`（RSA 專用）
    Pkcs1Rsa,
    /// SEC1：`-----BEGIN EC PRIVATE KEY-----`（EC 專用）
    Sec1Ec,
}

impl KeyKind {
    pub fn label(&self) -> &'static str {
        match self {
            KeyKind::Pkcs8 => "PKCS#8 私鑰",
            KeyKind::Pkcs1Rsa => "PKCS#1 (RSA) 私鑰",
            KeyKind::Sec1Ec => "SEC1 (EC) 私鑰",
        }
    }
}

#[derive(Clone)]
pub struct LoadedKey {
    pub kind: KeyKind,
    pub der: Vec<u8>,
}

/// 偵測後的輸入內容
#[derive(Clone)]
pub enum Loaded {
    /// PFX/PKCS#12（尚未解鎖，需密碼）
    Pfx { data: Vec<u8> },
    /// PEM 檔（可能同時含憑證與私鑰）
    Pem {
        certs: Vec<Vec<u8>>, // 每個元素為一張憑證的 DER
        key: Option<LoadedKey>,
        encrypted_key: bool, // 是否偵測到「加密的」PEM 私鑰
    },
    /// 單張 DER 憑證
    DerCert { der: Vec<u8> },
}

impl Loaded {
    pub fn type_label(&self) -> String {
        match self {
            Loaded::Pfx { .. } => "PFX / PKCS#12（需密碼解鎖）".to_string(),
            Loaded::DerCert { .. } => "DER 憑證".to_string(),
            Loaded::Pem {
                certs,
                key,
                encrypted_key,
            } => {
                let mut parts = Vec::new();
                if !certs.is_empty() {
                    parts.push(format!("{} 張憑證", certs.len()));
                }
                if let Some(k) = key {
                    parts.push(k.kind.label().to_string());
                } else if *encrypted_key {
                    parts.push("加密私鑰".to_string());
                }
                if parts.is_empty() {
                    "PEM（內容無法辨識）".to_string()
                } else {
                    format!("PEM（{}）", parts.join(" + "))
                }
            }
        }
    }
}

/// 憑證資訊（供 GUI 顯示）
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    pub sha256: String,
    pub key_type: String,
    pub sans: Vec<String>,
}

// ----------------------------------------------------------------------------
// 偵測
// ----------------------------------------------------------------------------

/// 依內容自動判斷輸入檔案的格式。
pub fn detect(bytes: &[u8]) -> Result<Loaded> {
    // 先看是不是文字 PEM
    if looks_like_pem(bytes) {
        return parse_pem(bytes);
    }

    // 二進位：先試 DER 憑證
    if let Ok((_rem, _cert)) = X509Certificate::from_der(bytes) {
        return Ok(Loaded::DerCert {
            der: bytes.to_vec(),
        });
    }

    // 其餘二進位一律當作 PFX（實際是否正確會在輸入密碼解鎖時得知）
    Ok(Loaded::Pfx {
        data: bytes.to_vec(),
    })
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    // 掃描前面一小段是否出現 PEM 標頭
    let head_len = bytes.len().min(1024);
    if let Ok(head) = std::str::from_utf8(&bytes[..head_len]) {
        head.contains("-----BEGIN")
    } else {
        false
    }
}

fn parse_pem(bytes: &[u8]) -> Result<Loaded> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| anyhow!("PEM 檔含有非 UTF-8 內容，無法解析"))?;
    let blocks = pemc::parse_many(text).map_err(|e| anyhow!("PEM 解析失敗：{e}"))?;

    let mut certs = Vec::new();
    let mut key: Option<LoadedKey> = None;
    let mut encrypted_key = false;

    for b in &blocks {
        match b.tag() {
            "CERTIFICATE" => certs.push(b.contents().to_vec()),
            "PRIVATE KEY" => {
                key.get_or_insert(LoadedKey {
                    kind: KeyKind::Pkcs8,
                    der: b.contents().to_vec(),
                });
            }
            "RSA PRIVATE KEY" => {
                key.get_or_insert(LoadedKey {
                    kind: KeyKind::Pkcs1Rsa,
                    der: b.contents().to_vec(),
                });
            }
            "EC PRIVATE KEY" => {
                key.get_or_insert(LoadedKey {
                    kind: KeyKind::Sec1Ec,
                    der: b.contents().to_vec(),
                });
            }
            "ENCRYPTED PRIVATE KEY" => encrypted_key = true,
            _ => {} // 忽略其他區塊（例如 DH PARAMETERS、PUBLIC KEY…）
        }
    }

    if certs.is_empty() && key.is_none() && !encrypted_key {
        bail!("PEM 檔中找不到憑證或私鑰");
    }

    Ok(Loaded::Pem {
        certs,
        key,
        encrypted_key,
    })
}

// ----------------------------------------------------------------------------
// 憑證資訊
// ----------------------------------------------------------------------------

pub fn cert_info(der: &[u8]) -> Result<CertInfo> {
    let (_rem, c) = X509Certificate::from_der(der).map_err(|e| anyhow!("憑證解析失敗：{e}"))?;

    // SAN
    let mut sans = Vec::new();
    for ext in c.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                match gn {
                    GeneralName::DNSName(s) => sans.push(format!("DNS: {s}")),
                    GeneralName::IPAddress(ip) => sans.push(format!("IP: {}", fmt_ip(ip))),
                    GeneralName::RFC822Name(s) => sans.push(format!("Email: {s}")),
                    GeneralName::URI(s) => sans.push(format!("URI: {s}")),
                    _ => {}
                }
            }
        }
    }

    // 金鑰類型（依 SubjectPublicKeyInfo 的演算法 OID 判斷）
    let key_type = {
        let oid = c.public_key().algorithm.algorithm.to_id_string();
        match oid.as_str() {
            "1.2.840.113549.1.1.1" => "RSA".to_string(),
            "1.2.840.10045.2.1" => "EC (ECDSA)".to_string(),
            "1.3.101.112" => "Ed25519".to_string(),
            "1.3.101.113" => "Ed448".to_string(),
            other => format!("其他 (OID {other})"),
        }
    };

    let sha256 = hex_upper(&Sha256::digest(der));

    Ok(CertInfo {
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        not_before: c.validity().not_before.to_string(),
        not_after: c.validity().not_after.to_string(),
        serial: c.tbs_certificate.raw_serial_as_string(),
        sha256,
        key_type,
        sans,
    })
}

// ----------------------------------------------------------------------------
// 轉換：憑證 PEM <-> DER
// ----------------------------------------------------------------------------

pub fn der_to_pem(tag: &str, der: &[u8]) -> String {
    let p = pemc::Pem::new(tag.to_string(), der.to_vec());
    pemc::encode(&p)
}

pub fn cert_der_to_pem(der: &[u8]) -> String {
    der_to_pem("CERTIFICATE", der)
}

// ----------------------------------------------------------------------------
// 轉換：私鑰格式
// ----------------------------------------------------------------------------

/// 任意支援的私鑰 -> PKCS#8 DER（打包 PFX 時 p12-keystore 需要 PKCS#8）。
pub fn any_key_to_pkcs8_der(key: &LoadedKey) -> Result<Vec<u8>> {
    match key.kind {
        KeyKind::Pkcs8 => Ok(key.der.clone()),
        KeyKind::Pkcs1Rsa => pkcs1_to_pkcs8_der(&key.der),
        KeyKind::Sec1Ec => sec1_to_pkcs8_der(&key.der),
    }
}

pub fn pkcs1_to_pkcs8_der(pkcs1_der: &[u8]) -> Result<Vec<u8>> {
    let key = RsaPrivateKey::from_pkcs1_der(pkcs1_der)
        .map_err(|e| anyhow!("PKCS#1 私鑰解析失敗：{e}"))?;
    let doc = key
        .to_pkcs8_der()
        .map_err(|e| anyhow!("轉 PKCS#8 失敗：{e}"))?;
    Ok(doc.as_bytes().to_vec())
}

pub fn pkcs8_to_pkcs1_der(pkcs8_der: &[u8]) -> Result<Vec<u8>> {
    let key = RsaPrivateKey::from_pkcs8_der(pkcs8_der)
        .map_err(|e| anyhow!("PKCS#8 私鑰解析失敗（PKCS#1 僅適用 RSA 金鑰）：{e}"))?;
    let doc = key
        .to_pkcs1_der()
        .map_err(|e| anyhow!("轉 PKCS#1 失敗：{e}"))?;
    Ok(doc.as_bytes().to_vec())
}

fn sec1_to_pkcs8_der(sec1_der: &[u8]) -> Result<Vec<u8>> {
    // 依序嘗試最常見的兩條曲線 P-256 / P-384
    if let Ok(sk) = p256::SecretKey::from_sec1_der(sec1_der) {
        let doc = sk
            .to_pkcs8_der()
            .map_err(|e| anyhow!("EC(P-256) 轉 PKCS#8 失敗：{e}"))?;
        return Ok(doc.as_bytes().to_vec());
    }
    if let Ok(sk) = p384::SecretKey::from_sec1_der(sec1_der) {
        let doc = sk
            .to_pkcs8_der()
            .map_err(|e| anyhow!("EC(P-384) 轉 PKCS#8 失敗：{e}"))?;
        return Ok(doc.as_bytes().to_vec());
    }
    bail!("不支援的 EC 曲線（目前支援 P-256 / P-384）")
}

/// 依「來源種類」決定另一個可轉換的目標格式，回傳 (PEM 標籤, PEM 內容)。
pub fn convert_key_to_other_pem(key: &LoadedKey) -> Result<(String, String)> {
    match key.kind {
        KeyKind::Pkcs1Rsa => {
            let der = pkcs1_to_pkcs8_der(&key.der)?;
            Ok(("PKCS#8".to_string(), der_to_pem("PRIVATE KEY", &der)))
        }
        KeyKind::Sec1Ec => {
            let der = sec1_to_pkcs8_der(&key.der)?;
            Ok(("PKCS#8".to_string(), der_to_pem("PRIVATE KEY", &der)))
        }
        KeyKind::Pkcs8 => {
            // PKCS#8 -> PKCS#1（僅 RSA 可行）
            let der = pkcs8_to_pkcs1_der(&key.der)?;
            Ok((
                "PKCS#1 (RSA)".to_string(),
                der_to_pem("RSA PRIVATE KEY", &der),
            ))
        }
    }
}

/// 這把私鑰是否有「轉成另一種格式」的動作可提供。
pub fn key_convert_button_label(kind: KeyKind) -> &'static str {
    match kind {
        KeyKind::Pkcs1Rsa => "私鑰 PKCS#1 → PKCS#8（.key）",
        KeyKind::Sec1Ec => "EC 私鑰 SEC1 → PKCS#8（.key）",
        KeyKind::Pkcs8 => "私鑰 PKCS#8 → PKCS#1 RSA（.key）",
    }
}

// ----------------------------------------------------------------------------
// 轉換：PFX <-> PEM
// ----------------------------------------------------------------------------

/// 解鎖 PFX，輸出「私鑰 + 憑證鏈」的合併 PEM，並回傳葉憑證 DER（供顯示）。
pub fn pfx_to_pem_bundle(data: &[u8], password: &str) -> Result<(String, Option<Vec<u8>>)> {
    let ks = KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Strict)
        .map_err(|e| anyhow!("PFX 解析失敗（密碼可能錯誤，或使用不支援的加密）：{e}"))?;

    let mut out = String::new();
    let mut leaf_der: Option<Vec<u8>> = None;

    if let Some((_alias, chain)) = ks.private_key_chain() {
        // 私鑰（p12-keystore 內部一律以 PKCS#8 儲存）
        out.push_str(&der_to_pem("PRIVATE KEY", chain.key().as_der()));
        // 憑證鏈：第一張是葉憑證
        for (i, cert) in chain.certs().iter().enumerate() {
            if i == 0 {
                leaf_der = Some(cert.as_der().to_vec());
            }
            out.push_str(&cert_der_to_pem(cert.as_der()));
        }
    } else {
        bail!("這個 PFX 內沒有私鑰鏈（可能是純憑證的 truststore）");
    }

    Ok((out, leaf_der))
}

/// 用「憑證(可多張，葉憑證在前) + 私鑰」打包成 PFX。
pub fn build_pfx(
    certs: &[Vec<u8>],
    key: &LoadedKey,
    password: &str,
    legacy: bool,
) -> Result<Vec<u8>> {
    if certs.is_empty() {
        bail!("找不到憑證，無法打包 PFX");
    }

    let key_pkcs8 = any_key_to_pkcs8_der(key)?;
    let p12_key = P12PrivateKey::from_der(&key_pkcs8).map_err(|e| anyhow!("私鑰載入失敗：{e}"))?;

    let mut p12_certs = Vec::with_capacity(certs.len());
    for der in certs {
        p12_certs.push(P12Certificate::from_der(der).map_err(|e| anyhow!("憑證載入失敗：{e}"))?);
    }

    let chain = PrivateKeyChain::new(b"cert-converter".to_vec(), p12_key, p12_certs);
    let mut ks = KeyStore::new();
    ks.add_entry("cert", KeyStoreEntry::PrivateKeyChain(chain));

    let (enc, mac) = if legacy {
        // 舊式相容：3DES + HMAC-SHA1，相容於舊版 Windows/IIS、舊版 Java 等
        (
            EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc,
            MacAlgorithm::HmacSha1,
        )
    } else {
        // 現代：AES-256 + HMAC-SHA256（安全性高，OpenSSL 3 之後的預設）
        (
            EncryptionAlgorithm::PbeWithHmacSha256AndAes256,
            MacAlgorithm::HmacSha256,
        )
    };

    let bytes = ks
        .writer(password)
        .encryption_algorithm(enc)
        .mac_algorithm(mac)
        .write()
        .map_err(|e| anyhow!("PFX 產生失敗：{e}"))?;

    Ok(bytes)
}

// ----------------------------------------------------------------------------
// 小工具
// ----------------------------------------------------------------------------

fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}

fn fmt_ip(ip: &[u8]) -> String {
    match ip.len() {
        4 => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
        16 => {
            let mut parts = Vec::new();
            for chunk in ip.chunks(2) {
                parts.push(format!("{:x}", ((chunk[0] as u16) << 8) | chunk[1] as u16));
            }
            parts.join(":")
        }
        _ => hex_upper(ip),
    }
}
