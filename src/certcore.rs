//! 核心邏輯：格式偵測、憑證解析、各種轉換。
//! 這個模組刻意與 GUI 分離，方便單獨測試與維護。
//!
//! 安全性設計：所有私鑰/憑證資料僅存在於記憶體，不寫任何暫存檔；
//! 私鑰與密碼以 `Zeroizing` 包裝，釋放時會清零；
//! 全程無任何網路呼叫，可在完全離線環境使用。

use anyhow::{anyhow, bail, Context, Result};
use zeroize::Zeroizing;

use p12_keystore::{
    Certificate as P12Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, MacAlgorithm,
    Pkcs12ImportPolicy, PrivateKey as P12PrivateKey, PrivateKeyChain,
};

use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
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

/// 私鑰的演算法
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum KeyAlg {
    Rsa,
    EcP256,
    EcP384,
    Ed25519,
    Other(String),
}

impl KeyAlg {
    pub fn label(&self) -> String {
        match self {
            KeyAlg::Rsa => "RSA".to_string(),
            KeyAlg::EcP256 => "EC P-256".to_string(),
            KeyAlg::EcP384 => "EC P-384".to_string(),
            KeyAlg::Ed25519 => "Ed25519".to_string(),
            KeyAlg::Other(oid) => format!("其他 (OID {oid})"),
        }
    }
}

/// 私鑰可輸出的格式
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyFormat {
    Pkcs8,
    Pkcs1,
    Sec1,
}

impl KeyFormat {
    pub fn label(&self) -> &'static str {
        match self {
            KeyFormat::Pkcs8 => "PKCS#8",
            KeyFormat::Pkcs1 => "PKCS#1 (RSA)",
            KeyFormat::Sec1 => "SEC1 (EC)",
        }
    }

    pub fn file_suffix(&self) -> &'static str {
        match self {
            KeyFormat::Pkcs8 => "pkcs8",
            KeyFormat::Pkcs1 => "pkcs1",
            KeyFormat::Sec1 => "sec1",
        }
    }

    fn kind(&self) -> KeyKind {
        match self {
            KeyFormat::Pkcs8 => KeyKind::Pkcs8,
            KeyFormat::Pkcs1 => KeyKind::Pkcs1Rsa,
            KeyFormat::Sec1 => KeyKind::Sec1Ec,
        }
    }
}

#[derive(Clone)]
pub struct LoadedKey {
    pub kind: KeyKind,
    pub der: Zeroizing<Vec<u8>>,
}

impl LoadedKey {
    pub(crate) fn new(kind: KeyKind, der: &[u8]) -> Self {
        LoadedKey {
            kind,
            der: Zeroizing::new(der.to_vec()),
        }
    }
}

/// 需要密碼才能解開的私鑰
#[derive(Clone)]
pub enum EncryptedKey {
    /// `-----BEGIN ENCRYPTED PRIVATE KEY-----`（PKCS#8 + PBES2）
    Pkcs8 { der: Vec<u8> },
    /// 舊式 OpenSSL 加密 PEM（含 `Proc-Type: 4,ENCRYPTED` / `DEK-Info` 標頭）
    LegacyPem {
        kind: KeyKind,
        dek_info: String,
        data: Vec<u8>,
    },
}

/// 內容的來源格式（僅供顯示）
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    Pem,
    DerCert,
    DerKey,
    Pkcs7,
    Pfx,
    Generated,
}

/// 已解開、可直接轉換的內容
#[derive(Clone)]
pub struct Items {
    pub source: Source,
    /// 每個元素為一張憑證的 DER；經 `normalize()` 後葉憑證在前、依簽發順序排列
    pub certs: Vec<Vec<u8>>,
    pub key: Option<LoadedKey>,
    pub encrypted_key: Option<EncryptedKey>,
    /// 載入過程的附註（例如 PFX 內有多把私鑰）
    pub notes: Vec<String>,
}

/// 偵測後的輸入內容
#[derive(Clone)]
pub enum Loaded {
    /// PFX/PKCS#12（尚未解鎖，需密碼）
    LockedPfx {
        data: Vec<u8>,
    },
    Items(Items),
}

impl Loaded {
    pub fn type_label(&self) -> String {
        match self {
            Loaded::LockedPfx { .. } => "PFX / PKCS#12（需密碼解鎖）".to_string(),
            Loaded::Items(items) => items.type_label(),
        }
    }
}

impl Items {
    pub(crate) fn new(source: Source) -> Self {
        Items {
            source,
            certs: Vec::new(),
            key: None,
            encrypted_key: None,
            notes: Vec::new(),
        }
    }

    pub fn type_label(&self) -> String {
        let src = match self.source {
            Source::Pem => "PEM",
            Source::DerCert => "DER 憑證",
            Source::DerKey => "DER 私鑰",
            Source::Pkcs7 => "PKCS#7 (.p7b)",
            Source::Pfx => "PFX（已解鎖）",
            Source::Generated => "新產生的自簽憑證",
        };
        let mut parts = Vec::new();
        if !self.certs.is_empty() {
            parts.push(format!("{} 張憑證", self.certs.len()));
        }
        if let Some(k) = &self.key {
            parts.push(k.kind.label().to_string());
        } else if self.encrypted_key.is_some() {
            parts.push("加密私鑰".to_string());
        }
        if parts.is_empty() {
            format!("{src}（內容無法辨識）")
        } else {
            format!("{src}（{}）", parts.join(" + "))
        }
    }

    /// 依私鑰找出葉憑證，並把憑證鏈排成「葉 → 中繼 → 根」。
    pub fn normalize(&mut self) {
        let leaf = self
            .key
            .as_ref()
            .and_then(|k| key_public_bits(k).ok().flatten())
            .and_then(|bits| {
                self.certs
                    .iter()
                    .position(|c| cert_public_bits(c).as_deref() == Some(bits.as_slice()))
            });
        self.certs = order_chain(std::mem::take(&mut self.certs), leaf);
    }

    /// 私鑰是否與葉憑證成對。`None` 表示無法判斷（缺憑證/私鑰，或不支援的演算法）。
    pub fn key_matches_leaf(&self) -> Option<bool> {
        let key = self.key.as_ref()?;
        let leaf = self.certs.first()?;
        let bits = key_public_bits(key).ok()??;
        Some(cert_public_bits(leaf).as_deref() == Some(bits.as_slice()))
    }
}

/// 憑證資訊（供 GUI 顯示）
pub struct CertInfo {
    pub subject: String,
    pub common_name: Option<String>,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    /// 距到期的天數（負數代表已過期）
    pub days_left: i64,
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
    if let Some(text) = decode_text(bytes) {
        if text.contains("-----BEGIN ") {
            return parse_pem(&text).map(Loaded::Items);
        }
    }

    if !bytes.starts_with(&[0x30]) {
        bail!("無法辨識的檔案格式（不是 PEM，也不是 DER/PFX）");
    }

    if is_pfx(bytes) {
        return Ok(Loaded::LockedPfx {
            data: bytes.to_vec(),
        });
    }

    if X509Certificate::from_der(bytes).is_ok() {
        let mut items = Items::new(Source::DerCert);
        items.certs.push(bytes.to_vec());
        return Ok(Loaded::Items(items));
    }

    if let Some(certs) = parse_pkcs7_certs(bytes) {
        let mut items = Items::new(Source::Pkcs7);
        items.certs = certs;
        items.normalize();
        return Ok(Loaded::Items(items));
    }

    if let Some(key) = detect_der_key(bytes) {
        let mut items = Items::new(Source::DerKey);
        items.key = Some(key);
        return Ok(Loaded::Items(items));
    }

    if pkcs8::EncryptedPrivateKeyInfo::try_from(bytes).is_ok() {
        let mut items = Items::new(Source::DerKey);
        items.encrypted_key = Some(EncryptedKey::Pkcs8 {
            der: bytes.to_vec(),
        });
        return Ok(Loaded::Items(items));
    }

    bail!("無法辨識的 DER 內容（不是憑證、私鑰、PKCS#7 或 PFX）")
}

/// 把檔案內容解成文字。支援 UTF-8（含 BOM）與 UTF-16（需有 BOM，Windows 記事本常見）。
/// 二進位檔回傳 `None`。
fn decode_text(bytes: &[u8]) -> Option<String> {
    let utf16 = |be: bool| {
        let (pairs, _) = bytes[2..].as_chunks::<2>();
        let units: Vec<u16> = pairs
            .iter()
            .map(|c| {
                if be {
                    u16::from_be_bytes([c[0], c[1]])
                } else {
                    u16::from_le_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return Some(utf16(true));
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return Some(utf16(false));
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    // DER 一定以 SEQUENCE (0x30) 開頭，且通常含有 NUL 等控制字元
    if bytes.first() == Some(&0x30) && bytes.iter().any(|&b| b < 0x09) {
        return None;
    }
    // 非 UTF-8 的註解（例如 Big5 中文）以替代字元處理，不影響 PEM 區塊本身
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn parse_pem(text: &str) -> Result<Items> {
    let blocks = pemc::parse_many(text).map_err(|e| anyhow!("PEM 解析失敗：{e}"))?;

    let mut items = Items::new(Source::Pem);
    let mut key_count = 0;

    for b in &blocks {
        let legacy_encrypted = b
            .headers()
            .get("Proc-Type")
            .is_some_and(|v| v.contains("ENCRYPTED"));
        let key_kind = match b.tag() {
            "CERTIFICATE" | "X509 CERTIFICATE" => {
                items.certs.push(b.contents().to_vec());
                None
            }
            "PKCS7" => {
                let certs = parse_pkcs7_certs(b.contents())
                    .ok_or_else(|| anyhow!("PKCS#7 內容解析失敗"))?;
                items.certs.extend(certs);
                None
            }
            "PRIVATE KEY" => Some(KeyKind::Pkcs8),
            "RSA PRIVATE KEY" => Some(KeyKind::Pkcs1Rsa),
            "EC PRIVATE KEY" => Some(KeyKind::Sec1Ec),
            "ENCRYPTED PRIVATE KEY" => {
                key_count += 1;
                if items.key.is_none() && items.encrypted_key.is_none() {
                    items.encrypted_key = Some(EncryptedKey::Pkcs8 {
                        der: b.contents().to_vec(),
                    });
                }
                None
            }
            _ => None, // 忽略其他區塊（例如 DH PARAMETERS、PUBLIC KEY…）
        };

        if let Some(kind) = key_kind {
            key_count += 1;
            if items.key.is_some() || items.encrypted_key.is_some() {
                continue;
            }
            if legacy_encrypted {
                let dek_info = b
                    .headers()
                    .get("DEK-Info")
                    .ok_or_else(|| anyhow!("加密的 PEM 私鑰缺少 DEK-Info 標頭"))?;
                items.encrypted_key = Some(EncryptedKey::LegacyPem {
                    kind,
                    dek_info: dek_info.to_string(),
                    data: b.contents().to_vec(),
                });
            } else {
                items.key = Some(LoadedKey::new(kind, b.contents()));
            }
        }
    }

    if items.certs.is_empty() && items.key.is_none() && items.encrypted_key.is_none() {
        bail!("PEM 檔中找不到憑證或私鑰");
    }
    if key_count > 1 {
        items
            .notes
            .push(format!("檔案內有 {key_count} 把私鑰，只使用第一把。"));
    }
    items.normalize();
    Ok(items)
}

/// PFX 結構：SEQUENCE { version INTEGER (3), authSafe ContentInfo, macData OPTIONAL }
fn is_pfx(bytes: &[u8]) -> bool {
    let Some((0x30, body, _)) = read_tlv(bytes) else {
        return false;
    };
    let Some((0x02, version, rest)) = read_tlv(body) else {
        return false;
    };
    version == [3] && rest.first() == Some(&0x30)
}

fn detect_der_key(bytes: &[u8]) -> Option<LoadedKey> {
    if pkcs8::PrivateKeyInfo::try_from(bytes).is_ok() {
        return Some(LoadedKey::new(KeyKind::Pkcs8, bytes));
    }
    if RsaPrivateKey::from_pkcs1_der(bytes).is_ok() {
        return Some(LoadedKey::new(KeyKind::Pkcs1Rsa, bytes));
    }
    if p256::SecretKey::from_sec1_der(bytes).is_ok()
        || p384::SecretKey::from_sec1_der(bytes).is_ok()
    {
        return Some(LoadedKey::new(KeyKind::Sec1Ec, bytes));
    }
    None
}

// ----------------------------------------------------------------------------
// 最小化 DER 讀取（PKCS#7 / PFX 結構判斷用）
// ----------------------------------------------------------------------------

/// 讀一個 TLV，回傳 (tag, 內容, 剩餘位元組)。僅支援單位元組 tag。
fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&len0, rest) = rest.split_first()?;
    let (len, rest) = if len0 < 0x80 {
        (len0 as usize, rest)
    } else {
        let n = (len0 & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// OID 1.2.840.113549.1.7.2 (signedData)
const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

/// 從 PKCS#7 SignedData（.p7b）取出所有憑證。
fn parse_pkcs7_certs(der: &[u8]) -> Option<Vec<Vec<u8>>> {
    let Some((0x30, content_info, _)) = read_tlv(der) else {
        return None;
    };
    let Some((0x06, oid, rest)) = read_tlv(content_info) else {
        return None;
    };
    if oid != OID_SIGNED_DATA {
        return None;
    }
    let Some((0xA0, explicit, _)) = read_tlv(rest) else {
        return None;
    };
    let Some((0x30, signed_data, _)) = read_tlv(explicit) else {
        return None;
    };
    let Some((0x02, _version, rest)) = read_tlv(signed_data) else {
        return None;
    };
    let Some((0x31, _digest_algs, rest)) = read_tlv(rest) else {
        return None;
    };
    let Some((0x30, _encap, rest)) = read_tlv(rest) else {
        return None;
    };

    let mut certs = Vec::new();
    // certificates [0] IMPLICIT SET OF Certificate OPTIONAL
    if let Some((0xA0, mut set, _)) = read_tlv(rest) {
        while !set.is_empty() {
            let (tag, _, next) = read_tlv(set)?;
            if tag == 0x30 {
                certs.push(set[..set.len() - next.len()].to_vec());
            }
            set = next;
        }
    }
    if certs.is_empty() {
        return None;
    }
    Some(certs)
}

// ----------------------------------------------------------------------------
// 憑證資訊 / 憑證鏈
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

    let now = ASN1Time::now().timestamp();
    let days_left = (c.validity().not_after.timestamp() - now).div_euclid(86_400);

    Ok(CertInfo {
        subject: c.subject().to_string(),
        common_name: common_name(&c),
        issuer: c.issuer().to_string(),
        not_before: fmt_time(&c.validity().not_before),
        not_after: fmt_time(&c.validity().not_after),
        days_left,
        serial: c.tbs_certificate.raw_serial_as_string(),
        sha256: hex_upper(&Sha256::digest(der)),
        key_type,
        sans,
    })
}

fn common_name(c: &X509Certificate) -> Option<String> {
    c.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
}

fn fmt_time(t: &ASN1Time) -> String {
    let dt = t.to_datetime();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// 憑證公鑰（SubjectPublicKeyInfo 的 BIT STRING 內容）
fn cert_public_bits(der: &[u8]) -> Option<Vec<u8>> {
    let (_, c) = X509Certificate::from_der(der).ok()?;
    Some(c.public_key().subject_public_key.data.to_vec())
}

/// 把憑證排成「葉 → 中繼 → 根」。`leaf` 為已知的葉憑證索引；
/// 未知時挑一張「不是其他任何憑證簽發者」的憑證當葉。無法串接的憑證依原順序附在最後。
fn order_chain(certs: Vec<Vec<u8>>, leaf: Option<usize>) -> Vec<Vec<u8>> {
    if certs.len() < 2 {
        return certs;
    }
    let names: Vec<Option<(Vec<u8>, Vec<u8>)>> = certs
        .iter()
        .map(|d| {
            X509Certificate::from_der(d)
                .ok()
                .map(|(_, c)| (c.subject().as_raw().to_vec(), c.issuer().as_raw().to_vec()))
        })
        .collect();

    let issues_other = |i: usize| {
        let Some((subj, _)) = &names[i] else {
            return false;
        };
        names
            .iter()
            .enumerate()
            .any(|(j, n)| j != i && n.as_ref().is_some_and(|(s, iss)| iss == subj && s != subj))
    };
    let leaf = leaf
        .or_else(|| (0..certs.len()).find(|&i| !issues_other(i)))
        .unwrap_or(0);

    let mut order = vec![leaf];
    let mut used = vec![false; certs.len()];
    used[leaf] = true;
    let mut cur = leaf;
    while let Some((subj, iss)) = &names[cur] {
        if subj == iss {
            break; // 自簽根憑證
        }
        let next = (0..certs.len())
            .find(|&j| !used[j] && names[j].as_ref().is_some_and(|(s, _)| s == iss));
        let Some(next) = next else { break };
        used[next] = true;
        order.push(next);
        cur = next;
    }
    order.extend((0..certs.len()).filter(|&j| !used[j]));

    let mut slots: Vec<Option<Vec<u8>>> = certs.into_iter().map(Some).collect();
    order.into_iter().filter_map(|i| slots[i].take()).collect()
}

// ----------------------------------------------------------------------------
// 轉換：PEM 編碼
// ----------------------------------------------------------------------------

/// 一律輸出 LF 換行（Linux 上的 Nginx/Apache 與 Windows 工具皆可讀）。
pub fn der_to_pem(tag: &str, der: &[u8]) -> String {
    let p = pemc::Pem::new(tag, der);
    pemc::encode_config(
        &p,
        pemc::EncodeConfig::new().set_line_ending(pemc::LineEnding::LF),
    )
}

pub fn certs_to_pem(certs: &[Vec<u8>]) -> String {
    certs.iter().map(|c| der_to_pem("CERTIFICATE", c)).collect()
}

// ----------------------------------------------------------------------------
// 私鑰：演算法、公鑰、格式轉換、解密
// ----------------------------------------------------------------------------

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_ED25519: &str = "1.3.101.112";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";

pub fn key_alg(key: &LoadedKey) -> KeyAlg {
    match key.kind {
        KeyKind::Pkcs1Rsa => KeyAlg::Rsa,
        KeyKind::Sec1Ec => {
            if p256::SecretKey::from_sec1_der(&key.der).is_ok() {
                KeyAlg::EcP256
            } else if p384::SecretKey::from_sec1_der(&key.der).is_ok() {
                KeyAlg::EcP384
            } else {
                KeyAlg::Other("EC（不支援的曲線）".to_string())
            }
        }
        KeyKind::Pkcs8 => {
            let Ok(info) = pkcs8::PrivateKeyInfo::try_from(key.der.as_slice()) else {
                return KeyAlg::Other("無法解析".to_string());
            };
            let oid = info.algorithm.oid.to_string();
            match oid.as_str() {
                OID_RSA => KeyAlg::Rsa,
                OID_ED25519 => KeyAlg::Ed25519,
                OID_EC => match info.algorithm.parameters_oid().map(|o| o.to_string()) {
                    Ok(c) if c == OID_P256 => KeyAlg::EcP256,
                    Ok(c) if c == OID_P384 => KeyAlg::EcP384,
                    Ok(c) => KeyAlg::Other(format!("EC 曲線 {c}")),
                    Err(_) => KeyAlg::Other("EC".to_string()),
                },
                _ => KeyAlg::Other(oid),
            }
        }
    }
}

/// 私鑰可轉出的格式（依演算法）。
pub fn key_formats(key: &LoadedKey) -> Vec<KeyFormat> {
    match key_alg(key) {
        KeyAlg::Rsa => vec![KeyFormat::Pkcs8, KeyFormat::Pkcs1],
        KeyAlg::EcP256 | KeyAlg::EcP384 => vec![KeyFormat::Pkcs8, KeyFormat::Sec1],
        _ => vec![KeyFormat::Pkcs8],
    }
}

/// 由私鑰推算出公鑰（SubjectPublicKeyInfo 的 BIT STRING 內容），用來比對憑證。
/// 不支援的演算法（例如 Ed25519）回傳 `Ok(None)`。
fn key_public_bits(key: &LoadedKey) -> Result<Option<Vec<u8>>> {
    let pkcs8 = any_key_to_pkcs8_der(key)?;
    let bits = match key_alg(key) {
        KeyAlg::Rsa => {
            let sk = RsaPrivateKey::from_pkcs8_der(&pkcs8)?;
            sk.to_public_key().to_pkcs1_der()?.as_bytes().to_vec()
        }
        KeyAlg::EcP256 => p256::SecretKey::from_pkcs8_der(&pkcs8)?
            .public_key()
            .to_sec1_bytes()
            .to_vec(),
        KeyAlg::EcP384 => p384::SecretKey::from_pkcs8_der(&pkcs8)?
            .public_key()
            .to_sec1_bytes()
            .to_vec(),
        _ => return Ok(None),
    };
    Ok(Some(bits))
}

/// 任意支援的私鑰 -> PKCS#8 DER（打包 PFX 時 p12-keystore 需要 PKCS#8）。
pub fn any_key_to_pkcs8_der(key: &LoadedKey) -> Result<Zeroizing<Vec<u8>>> {
    match key.kind {
        KeyKind::Pkcs8 => Ok(key.der.clone()),
        KeyKind::Pkcs1Rsa => {
            let sk = RsaPrivateKey::from_pkcs1_der(&key.der)
                .map_err(|e| anyhow!("PKCS#1 私鑰解析失敗：{e}"))?;
            let doc = sk
                .to_pkcs8_der()
                .map_err(|e| anyhow!("轉 PKCS#8 失敗：{e}"))?;
            Ok(Zeroizing::new(doc.as_bytes().to_vec()))
        }
        KeyKind::Sec1Ec => {
            // 依序嘗試最常見的兩條曲線 P-256 / P-384
            let doc = if let Ok(sk) = p256::SecretKey::from_sec1_der(&key.der) {
                sk.to_pkcs8_der()
            } else if let Ok(sk) = p384::SecretKey::from_sec1_der(&key.der) {
                sk.to_pkcs8_der()
            } else {
                bail!("不支援的 EC 曲線（目前支援 P-256 / P-384）")
            };
            let doc = doc.map_err(|e| anyhow!("EC 私鑰轉 PKCS#8 失敗：{e}"))?;
            Ok(Zeroizing::new(doc.as_bytes().to_vec()))
        }
    }
}

/// 把私鑰轉成指定格式的 PEM。
pub fn export_key_pem(key: &LoadedKey, format: KeyFormat) -> Result<Zeroizing<String>> {
    if format.kind() == key.kind {
        let tag = pem_tag(key.kind);
        return Ok(Zeroizing::new(der_to_pem(tag, &key.der)));
    }
    let pkcs8 = any_key_to_pkcs8_der(key)?;
    let der: Zeroizing<Vec<u8>> = match format {
        KeyFormat::Pkcs8 => pkcs8,
        KeyFormat::Pkcs1 => {
            let sk = RsaPrivateKey::from_pkcs8_der(&pkcs8)
                .map_err(|_| anyhow!("PKCS#1 僅適用 RSA 私鑰"))?;
            let doc = sk
                .to_pkcs1_der()
                .map_err(|e| anyhow!("轉 PKCS#1 失敗：{e}"))?;
            Zeroizing::new(doc.as_bytes().to_vec())
        }
        KeyFormat::Sec1 => {
            if let Ok(sk) = p256::SecretKey::from_pkcs8_der(&pkcs8) {
                sk.to_sec1_der().map_err(|e| anyhow!("轉 SEC1 失敗：{e}"))?
            } else if let Ok(sk) = p384::SecretKey::from_pkcs8_der(&pkcs8) {
                sk.to_sec1_der().map_err(|e| anyhow!("轉 SEC1 失敗：{e}"))?
            } else {
                bail!("SEC1 僅適用 EC P-256 / P-384 私鑰")
            }
        }
    };
    Ok(Zeroizing::new(der_to_pem(pem_tag(format.kind()), &der)))
}

fn pem_tag(kind: KeyKind) -> &'static str {
    match kind {
        KeyKind::Pkcs8 => "PRIVATE KEY",
        KeyKind::Pkcs1Rsa => "RSA PRIVATE KEY",
        KeyKind::Sec1Ec => "EC PRIVATE KEY",
    }
}

/// 用密碼解開加密的私鑰。
pub fn decrypt_key(enc: &EncryptedKey, password: &str) -> Result<LoadedKey> {
    let key = match enc {
        EncryptedKey::Pkcs8 { der } => {
            let info = pkcs8::EncryptedPrivateKeyInfo::try_from(der.as_slice())
                .map_err(|e| anyhow!("加密私鑰解析失敗：{e}"))?;
            let doc = info
                .decrypt(password)
                .map_err(|_| anyhow!("私鑰解密失敗（密碼錯誤，或使用不支援的加密演算法）"))?;
            LoadedKey::new(KeyKind::Pkcs8, doc.as_bytes())
        }
        EncryptedKey::LegacyPem {
            kind,
            dek_info,
            data,
        } => LoadedKey {
            kind: *kind,
            der: decrypt_legacy_pem(dek_info, data, password)?,
        },
    };
    // 驗證解出來的內容確實是私鑰（CBC padding 在密碼錯誤時仍有極小機率「剛好正確」）
    any_key_to_pkcs8_der(&key).map_err(|_| anyhow!("私鑰解密失敗（密碼錯誤）"))?;
    Ok(key)
}

/// 舊式 OpenSSL 加密 PEM：金鑰以 EVP_BytesToKey(MD5, salt = IV 前 8 bytes) 推導。
fn decrypt_legacy_pem(dek_info: &str, data: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

    let (cipher, iv_hex) = dek_info
        .split_once(',')
        .ok_or_else(|| anyhow!("DEK-Info 標頭格式錯誤"))?;
    let iv = hex_decode(iv_hex.trim()).ok_or_else(|| anyhow!("DEK-Info 的 IV 格式錯誤"))?;
    if iv.len() < 8 {
        bail!("DEK-Info 的 IV 長度錯誤");
    }
    let cipher = cipher.trim().to_ascii_uppercase();
    let key_len = match cipher.as_str() {
        "AES-128-CBC" => 16,
        "AES-192-CBC" | "DES-EDE3-CBC" => 24,
        "AES-256-CBC" => 32,
        other => bail!("不支援的舊式 PEM 加密演算法：{other}"),
    };
    let key = evp_bytes_to_key(password.as_bytes(), &iv[..8], key_len);

    let mut buf = Zeroizing::new(data.to_vec());
    let bad = |_| anyhow!("私鑰解密失敗（密碼錯誤）");
    let len = match cipher.as_str() {
        "AES-128-CBC" => cbc::Decryptor::<aes::Aes128>::new_from_slices(&key, &iv)?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(bad)?
            .len(),
        "AES-192-CBC" => cbc::Decryptor::<aes::Aes192>::new_from_slices(&key, &iv)?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(bad)?
            .len(),
        "AES-256-CBC" => cbc::Decryptor::<aes::Aes256>::new_from_slices(&key, &iv)?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(bad)?
            .len(),
        _ => cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(bad)?
            .len(),
    };
    buf.truncate(len);
    Ok(buf)
}

fn evp_bytes_to_key(password: &[u8], salt: &[u8], key_len: usize) -> Zeroizing<Vec<u8>> {
    use md5::Md5;
    let mut out = Zeroizing::new(Vec::with_capacity(key_len + 16));
    let mut prev = Zeroizing::new(Vec::new());
    while out.len() < key_len {
        let mut h = Md5::new();
        h.update(prev.as_slice());
        h.update(password);
        h.update(salt);
        *prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

// ----------------------------------------------------------------------------
// 轉換：PFX <-> PEM
// ----------------------------------------------------------------------------

/// 解鎖 PFX，取出私鑰與所有憑證。
pub fn unlock_pfx(data: &[u8], password: &str) -> Result<Items> {
    let open = |policy| {
        KeyStore::from_pkcs12(data, password, policy)
            .map_err(|e| anyhow!("PFX 解析失敗（密碼可能錯誤，或使用不支援的加密）：{e}"))
    };
    // Relaxed：取得私鑰（即使沒有 localKeyId 對應的憑證也保留）
    // Raw：取得所有憑證（包含未與私鑰串接的 CA 憑證）
    let relaxed = open(Pkcs12ImportPolicy::Relaxed)?;
    let raw = open(Pkcs12ImportPolicy::Raw)?;

    let mut items = Items::new(Source::Pfx);
    let mut key_count = 0;
    for (_alias, entry) in relaxed.entries() {
        if let KeyStoreEntry::PrivateKeyChain(chain) = entry {
            key_count += 1;
            if items.key.is_none() {
                items.key = Some(LoadedKey::new(KeyKind::Pkcs8, chain.key().as_der()));
            }
            push_unique(&mut items.certs, chain.certs().iter().map(|c| c.as_der()));
        }
    }
    for (_alias, entry) in raw.entries() {
        if let KeyStoreEntry::Certificate(cert) = entry {
            push_unique(&mut items.certs, std::iter::once(cert.as_der()));
        }
    }

    if items.key.is_none() && items.certs.is_empty() {
        bail!("這個 PFX 內沒有私鑰或憑證");
    }
    if items.key.is_none() {
        items
            .notes
            .push("這個 PFX 內沒有私鑰（純憑證的 truststore）。".to_string());
    }
    if key_count > 1 {
        items
            .notes
            .push(format!("PFX 內有 {key_count} 把私鑰，只使用第一把。"));
    }
    items.normalize();
    Ok(items)
}

fn push_unique<'a>(certs: &mut Vec<Vec<u8>>, new: impl Iterator<Item = &'a [u8]>) {
    for der in new {
        if !certs.iter().any(|c| c == der) {
            certs.push(der.to_vec());
        }
    }
}

/// 私鑰 + 完整憑證鏈的合併 PEM（私鑰未加密）。
pub fn pem_bundle(certs: &[Vec<u8>], key: &LoadedKey) -> Result<Zeroizing<String>> {
    let mut out = export_key_pem(key, KeyFormat::Pkcs8)?;
    out.push_str(&certs_to_pem(certs));
    Ok(out)
}

/// 用「憑證（可多張）+ 私鑰」打包成 PFX。
/// 會先確認私鑰與憑證成對，並把憑證鏈排成「葉 → 中繼 → 根」。
pub fn build_pfx(
    certs: &[Vec<u8>],
    key: &LoadedKey,
    password: &str,
    legacy: bool,
) -> Result<Vec<u8>> {
    if certs.is_empty() {
        bail!("找不到憑證，無法打包 PFX");
    }

    let leaf = match key_public_bits(key).context("私鑰解析失敗")? {
        Some(bits) => Some(
            certs
                .iter()
                .position(|c| cert_public_bits(c).as_deref() == Some(bits.as_slice()))
                .ok_or_else(|| anyhow!("私鑰與檔案中的任何一張憑證都不成對，請確認是否拿錯私鑰"))?,
        ),
        None => None, // 不支援比對的演算法（例如 Ed25519），依憑證鏈推斷
    };
    let certs = order_chain(certs.to_vec(), leaf);

    let key_pkcs8 = any_key_to_pkcs8_der(key)?;
    let p12_key = P12PrivateKey::from_der(&key_pkcs8).map_err(|e| anyhow!("私鑰載入失敗：{e}"))?;

    let mut p12_certs = Vec::with_capacity(certs.len());
    for der in &certs {
        p12_certs.push(P12Certificate::from_der(der).map_err(|e| anyhow!("憑證載入失敗：{e}"))?);
    }

    // 別名 (friendlyName) 用葉憑證的 CN，匯入 Windows 憑證存放區後較容易辨認
    let alias = X509Certificate::from_der(&certs[0])
        .ok()
        .and_then(|(_, c)| common_name(&c))
        .unwrap_or_else(|| "cert".to_string());
    let local_key_id = Sha256::digest(&certs[0])[..20].to_vec();

    let chain = PrivateKeyChain::new(local_key_id, p12_key, p12_certs);
    let mut ks = KeyStore::new();
    ks.add_entry(&alias, KeyStoreEntry::PrivateKeyChain(chain));

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

    ks.writer(password)
        .encryption_algorithm(enc)
        .mac_algorithm(mac)
        .write()
        .map_err(|e| anyhow!("PFX 產生失敗：{e}"))
}

// ----------------------------------------------------------------------------
// 小工具
// ----------------------------------------------------------------------------

fn hex_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn fmt_ip(ip: &[u8]) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};
    if let Ok(v4) = <[u8; 4]>::try_from(ip) {
        Ipv4Addr::from(v4).to_string()
    } else if let Ok(v6) = <[u8; 16]>::try_from(ip) {
        Ipv6Addr::from(v6).to_string()
    } else {
        hex_upper(ip)
    }
}

#[cfg(test)]
mod tests;
