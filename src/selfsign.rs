//! 建立自簽憑證（離線）：驗證表單、產生私鑰與 X.509 v3 自簽伺服器憑證。

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Result};
use rsa::pkcs8::EncodePrivateKey;
use rsa::rand_core::{OsRng, RngCore};
use rsa::signature::{Keypair, Signer};
use rsa::RsaPrivateKey;
use sha2::Sha256;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{Ia5String, OctetString, SetOfVec, Utf8StringRef};
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::der::referenced::OwnedToRef;
use x509_cert::der::{Any, Encode, Length, Writer};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{
    DynSignatureAlgorithmIdentifier, EncodePublicKey, SignatureBitStringEncoding,
    SubjectPublicKeyInfoOwned,
};
use x509_cert::time::{Time, Validity};

use crate::certcore::{Items, KeyKind, LoadedKey, Source};

/// 有效天數上限
pub const MAX_DAYS: u32 = 3650;
/// 超過這個天數時提醒 macOS / iOS 不接受
pub const LONG_VALIDITY_WARN_DAYS: u32 = 825;
/// X.520 對 CN / O 的長度上限（字元數）
const MAX_NAME_CHARS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum KeyType {
    #[default]
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcP256,
    EcP384,
}

impl KeyType {
    pub const ALL: [KeyType; 5] = [
        KeyType::Rsa2048,
        KeyType::Rsa3072,
        KeyType::Rsa4096,
        KeyType::EcP256,
        KeyType::EcP384,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            KeyType::Rsa2048 => "RSA 2048（相容性最佳）",
            KeyType::Rsa3072 => "RSA 3072",
            KeyType::Rsa4096 => "RSA 4096（產生較慢）",
            KeyType::EcP256 => "EC P-256",
            KeyType::EcP384 => "EC P-384",
        }
    }
}

/// 主體別名
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum San {
    Dns(String),
    Ip(IpAddr),
}

/// 表單內容
#[derive(Clone, Debug)]
pub struct SelfSignRequest {
    pub common_name: String,
    /// 空字串表示不填
    pub organization: String,
    /// 表單原始多行文字，一行一個
    pub sans: String,
    pub key_type: KeyType,
    pub days: u32,
}

impl Default for SelfSignRequest {
    fn default() -> Self {
        SelfSignRequest {
            common_name: String::new(),
            organization: String::new(),
            sans: String::new(),
            key_type: KeyType::default(),
            days: 365,
        }
    }
}

/// 驗證表單並整理出最終的 SAN 清單（CN 在最前面、已去重）。錯誤訊息可直接顯示給使用者。
pub fn validate(req: &SelfSignRequest) -> Result<Vec<San>> {
    let cn = req.common_name.trim();
    if cn.is_empty() {
        bail!("請輸入一般名稱 (CN)");
    }
    if cn.chars().count() > MAX_NAME_CHARS {
        bail!("一般名稱 (CN) 不可超過 {MAX_NAME_CHARS} 個字元");
    }
    if req.organization.trim().chars().count() > MAX_NAME_CHARS {
        bail!("組織 (O) 不可超過 {MAX_NAME_CHARS} 個字元");
    }
    if !(1..=MAX_DAYS).contains(&req.days) {
        bail!("有效天數必須介於 1 到 {MAX_DAYS} 天");
    }

    let mut sans: Vec<San> = Vec::new();
    // CN 若是合法的主機名稱或 IP 就自動加入 SAN；否則視為描述文字，不加入也不報錯
    if let Ok(san) = parse_san(cn) {
        sans.push(san);
    }
    for line in req.sans.lines() {
        let entry = line.trim();
        if entry.is_empty() {
            continue;
        }
        let san = parse_san(entry)?;
        if !sans.contains(&san) {
            sans.push(san);
        }
    }
    if sans.is_empty() {
        bail!("請至少提供一個有效的主機名稱或 IP（填在 CN 或主體別名）");
    }
    Ok(sans)
}

fn parse_san(entry: &str) -> Result<San> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Ok(San::Ip(ip));
    }
    if is_valid_dns_name(entry) {
        return Ok(San::Dns(entry.to_ascii_lowercase()));
    }
    bail!("「{entry}」不是有效的主機名稱或 IP 位址")
}

/// DNS 名稱：每段 1–63 字元，只含英數字與 `-`（不可在頭尾），總長 ≤ 253；
/// 萬用字元只能是最左邊一整段 `*`，且後面至少還有一段。
fn is_valid_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    // 最後一段全為數字的一定不是主機名稱，多半是打錯的 IP（例如 192.168.1.300），不可悄悄當成 DNS
    if labels
        .last()
        .is_some_and(|l| l.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    labels.iter().enumerate().all(|(i, label)| {
        if *label == "*" {
            return i == 0 && labels.len() > 1;
        }
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// CN 看起來像主機名稱或 IP（含 `.` 或 `:`、沒有空白）卻不合法時，回傳提示文字：
/// 這種 CN 不會自動加入 SAN，瀏覽器也就不會接受這個名稱。一般描述文字不提示。
pub fn cn_san_hint(common_name: &str) -> Option<String> {
    let cn = common_name.trim();
    let hostname_like =
        (cn.contains('.') || cn.contains(':')) && !cn.chars().any(char::is_whitespace);
    if hostname_like && parse_san(cn).is_err() {
        Some(format!(
            "CN「{cn}」不是有效的主機名稱或 IP，不會加入主體別名 (SAN)；瀏覽器不會接受這個名稱"
        ))
    } else {
        None
    }
}

/// 由 CN 產生預設的存檔檔名（不含副檔名），Windows 不允許的字元以 `_` 取代。
pub fn default_file_stem(common_name: &str) -> String {
    let stem: String = common_name
        .trim()
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    if stem.is_empty() {
        return "selfsigned".to_string();
    }
    // Windows 保留裝置名稱（CON、NUL、COM1…）不能當檔名，判斷的是第一個 . 之前的部分
    let (base, rest) = stem.split_at(stem.find('.').unwrap_or(stem.len()));
    let upper = base.to_ascii_uppercase();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.len() == 4
            && matches!(upper.as_bytes()[3], b'1'..=b'9'));
    if reserved {
        format!("{base}_{rest}")
    } else {
        stem
    }
}

const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

/// 產生私鑰與自簽憑證，回傳可直接載入主畫面的內容。
/// RSA 4096 在一般電腦上可能需要數秒，請勿在 UI 執行緒呼叫。
pub fn generate(req: &SelfSignRequest) -> Result<Items> {
    let sans = validate(req)?;
    let subject = subject_name(req.common_name.trim(), req.organization.trim())?;

    let (pkcs8, cert) = match req.key_type {
        KeyType::Rsa2048 => rsa_material(2048, subject, &sans, req.days)?,
        KeyType::Rsa3072 => rsa_material(3072, subject, &sans, req.days)?,
        KeyType::Rsa4096 => rsa_material(4096, subject, &sans, req.days)?,
        KeyType::EcP256 => {
            let signer = p256::ecdsa::SigningKey::random(&mut OsRng);
            let pkcs8 = signer
                .to_pkcs8_der()
                .map_err(|e| anyhow!("私鑰編碼失敗：{e}"))?;
            let cert = build_cert::<_, p256::ecdsa::DerSignature>(
                &signer, subject, &sans, req.days, false,
            )?;
            (pkcs8, cert)
        }
        KeyType::EcP384 => {
            let signer = p384::ecdsa::SigningKey::random(&mut OsRng);
            let pkcs8 = signer
                .to_pkcs8_der()
                .map_err(|e| anyhow!("私鑰編碼失敗：{e}"))?;
            let cert = build_cert::<_, p384::ecdsa::DerSignature>(
                &signer, subject, &sans, req.days, false,
            )?;
            (pkcs8, cert)
        }
    };

    let mut items = Items::new(Source::Generated);
    items.certs.push(cert);
    items.key = Some(LoadedKey::new(KeyKind::Pkcs8, pkcs8.as_bytes()));
    Ok(items)
}

fn rsa_material(
    bits: usize,
    subject: Name,
    sans: &[San],
    days: u32,
) -> Result<(pkcs8::SecretDocument, Vec<u8>)> {
    let key = RsaPrivateKey::new(&mut OsRng, bits).map_err(|e| anyhow!("RSA 金鑰產生失敗：{e}"))?;
    let pkcs8 = key
        .to_pkcs8_der()
        .map_err(|e| anyhow!("私鑰編碼失敗：{e}"))?;
    let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
    let cert = build_cert::<_, rsa::pkcs1v15::Signature>(&signer, subject, sans, days, true)?;
    Ok((pkcs8, cert))
}

/// Subject（= Issuer）。直接組 RDN，不經過字串解析，CN/O 內的逗號、引號、中文等都會原樣保留。
/// 編碼順序為 O、CN（顯示時多為「CN=…, O=…」）。
fn subject_name(common_name: &str, organization: &str) -> Result<Name> {
    let mut rdns = Vec::new();
    if !organization.is_empty() {
        rdns.push(rdn(OID_ORGANIZATION, organization)?);
    }
    rdns.push(rdn(OID_COMMON_NAME, common_name)?);
    Ok(RdnSequence(rdns))
}

fn rdn(oid: ObjectIdentifier, value: &str) -> Result<RelativeDistinguishedName> {
    let atv = AttributeTypeAndValue {
        oid,
        value: Any::from(Utf8StringRef::new(value)?),
    };
    Ok(RelativeDistinguishedName::from(SetOfVec::try_from(vec![
        atv,
    ])?))
}

fn build_cert<S, Sig>(
    signer: &S,
    subject: Name,
    sans: &[San],
    days: u32,
    key_encipherment: bool,
) -> Result<Vec<u8>>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<Sig>,
    S::VerifyingKey: EncodePublicKey,
    Sig: SignatureBitStringEncoding,
{
    let spki = SubjectPublicKeyInfoOwned::from_key(signer.verifying_key())?;

    // 往前推 5 分鐘，避免用戶端時鐘稍慢時出現「尚未生效」
    let not_before = SystemTime::now() - Duration::from_secs(5 * 60);
    let not_after = not_before + Duration::from_secs(u64::from(days) * 86_400);
    let validity = Validity {
        not_before: Time::try_from(not_before)?,
        not_after: Time::try_from(not_after)?,
    };

    // 16 bytes 亂數序號；最高位元清 0 確保為正整數，次高位元設 1 確保編碼長度固定為 16
    let mut serial = [0u8; 16];
    OsRng.fill_bytes(&mut serial);
    serial[0] = (serial[0] & 0x7f) | 0x40;

    let mut builder = CertificateBuilder::new(
        Profile::Manual { issuer: None },
        SerialNumber::new(&serial)?,
        validity,
        subject,
        spki.clone(),
        signer,
    )?;

    builder.add_extension(&SubjectKeyIdentifier::try_from(spki.owned_to_ref())?)?;
    builder.add_extension(&BasicConstraints {
        ca: false,
        path_len_constraint: None,
    })?;
    let usage = if key_encipherment {
        KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment
    } else {
        KeyUsages::DigitalSignature.into()
    };
    builder.add_extension(&KeyUsage(usage))?;
    builder.add_extension(&NonCritical(ExtendedKeyUsage(vec![OID_SERVER_AUTH])))?;

    let names = sans
        .iter()
        .map(|san| {
            Ok(match san {
                San::Dns(name) => GeneralName::DnsName(Ia5String::new(name)?),
                San::Ip(IpAddr::V4(ip)) => GeneralName::IpAddress(OctetString::new(ip.octets())?),
                San::Ip(IpAddr::V6(ip)) => GeneralName::IpAddress(OctetString::new(ip.octets())?),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    builder.add_extension(&SubjectAltName(names))?;

    let cert = builder.build::<Sig>()?;
    Ok(cert.to_der()?)
}

/// `x509-cert` 會把 extendedKeyUsage 標成 critical；業界慣例（mkcert、OpenSSL 預設）為 non-critical，
/// 部分舊軟體遇到 critical EKU 會拒絕憑證，因此包一層強制 non-critical。
struct NonCritical<T>(T);

impl<T: AssociatedOid> AssociatedOid for NonCritical<T> {
    const OID: ObjectIdentifier = T::OID;
}

impl<T: Encode> Encode for NonCritical<T> {
    fn encoded_len(&self) -> x509_cert::der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> x509_cert::der::Result<()> {
        self.0.encode(writer)
    }
}

impl<T: AssociatedOid + Encode> AsExtension for NonCritical<T> {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
