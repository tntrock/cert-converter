# 建立自簽憑證 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 讓使用者在 cert-converter 內離線產生一張自簽 TLS 伺服器憑證（含私鑰），產生後直接載入主畫面，用既有按鈕匯出。

**Architecture:** 新增 `src/selfsign.rs`（純邏輯：表單驗證 + 金鑰產生 + 以 `x509-cert` builder 組裝並簽署憑證，回傳 `certcore::Items`），
與 `src/selfsign_form.rs`（egui 表單視窗）。`main.rs` 在背景執行緒呼叫 `selfsign::generate`，以 `mpsc` channel 取回結果並 `set_loaded`。

**Tech Stack:** Rust 1.88+、eframe/egui 0.29、`x509-cert 0.2`（`builder` + `hazmat`）、`rsa 0.9`（`sha2`）、`p256`/`p384 0.13`（`ecdsa`）、既有的 `x509-parser 0.18`（測試解析用）。

**Spec:** `docs/superpowers/specs/2026-09-27-self-signed-cert-design.md`

## Global Constraints

- 全程離線、不做任何網路呼叫；不新增任何含 C 程式碼的相依（不可出現 `ring`、`aws-lc-*`、`openssl-sys`、`cc`）。
- `rust-version = "1.88"`；`cargo fmt --check` 與 `cargo clippy --all-targets --locked -- -D warnings` 必須通過。
- 私鑰一律以 `LoadedKey { kind: KeyKind::Pkcs8, der: Zeroizing<Vec<u8>> }` 保存。
- UI 與錯誤訊息使用繁體中文，風格與現有 `main.rs` 一致。
- 金鑰類型：RSA 2048（預設）/ RSA 3072 / RSA 4096 / EC P-256 / EC P-384。
- 有效天數：預設 365，範圍 1–3650；> 825 天顯示警告「macOS / iOS 不接受效期超過 825 天的 TLS 憑證」（不阻擋）。
- CN 必填、≤ 64 字元；O 選填、≤ 64 字元。
- 憑證擴充欄位：basicConstraints critical CA:FALSE；keyUsage critical（RSA：digitalSignature + keyEncipherment，EC：digitalSignature）；
  extendedKeyUsage **non-critical** serverAuth；subjectAltName；subjectKeyIdentifier。
- 生效時間 = 現在 − 5 分鐘；序號 16 bytes 亂數且為正整數。
- 版本號升為 `1.3.0`。

## Review Focus

1. CN / O 含 RFC 4514 特殊字元（`, + " \ < > ; = #`）或中文時，必須原樣寫入憑證，不可被截斷或產生失敗 → Task 2 `special_characters_in_subject_are_kept`。
2. 從 Windows 複製貼上的 SAN（CRLF 換行、前後空白、空白行）必須被正確忽略／修剪 → Task 1 `blank_lines_crlf_and_spaces_are_ignored`。
3. 大小寫不同或重複的 SAN、CN 已在 SAN 中，必須去重，不可產生重複的 SAN → Task 1 `duplicates_and_case_are_normalized`。
4. 萬用字元 CN（`*.example.local`）要成為有效 SAN，且預設檔名不可含 `*` → Task 1 `wildcard_rules`、`default_file_stem_sanitizes`；Task 2 `wildcard_cn_becomes_san`。
5. 產生中拖入檔案，不可在結果回來時被覆蓋而不自知 → Task 3 Step 5 手動檢查（拒絕拖放並顯示訊息）。

---

### Task 1: 表單驗證與資料型別（`src/selfsign.rs`）

**Files:**
- Create: `src/selfsign.rs`
- Create: `src/selfsign/tests.rs`
- Modify: `src/main.rs`（第 4 行 `mod certcore;` 之後加入模組宣告）

**Interfaces:**
- Consumes: 無
- Produces:
  - `pub enum KeyType { Rsa2048, Rsa3072, Rsa4096, EcP256, EcP384 }`（`Clone, Copy, PartialEq, Eq, Debug, Default`；`KeyType::ALL: [KeyType; 5]`；`fn label(&self) -> &'static str`）
  - `pub enum San { Dns(String), Ip(IpAddr) }`（`Clone, Debug, PartialEq, Eq`）
  - `pub struct SelfSignRequest { common_name: String, organization: String, sans: String, key_type: KeyType, days: u32 }`（`Clone, Debug`，`Default` 為 days = 365）
  - `pub const MAX_DAYS: u32 = 3650;`、`pub const LONG_VALIDITY_WARN_DAYS: u32 = 825;`
  - `pub fn validate(req: &SelfSignRequest) -> anyhow::Result<Vec<San>>`
  - `pub fn default_file_stem(common_name: &str) -> String`

- [ ] **Step 1: 寫失敗的測試**

`src/selfsign/tests.rs`：

```rust
use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn req(cn: &str, sans: &str) -> SelfSignRequest {
    SelfSignRequest {
        common_name: cn.into(),
        sans: sans.into(),
        ..Default::default()
    }
}

fn dns(s: &str) -> San {
    San::Dns(s.to_string())
}

#[test]
fn defaults() {
    let r = SelfSignRequest::default();
    assert_eq!(r.key_type, KeyType::Rsa2048);
    assert_eq!(r.days, 365);
}

#[test]
fn cn_is_added_to_sans_first() {
    assert_eq!(
        validate(&req("server.local", "www.local")).unwrap(),
        vec![dns("server.local"), dns("www.local")]
    );
}

#[test]
fn ip_sans_ipv4_and_ipv6() {
    assert_eq!(
        validate(&req("10.0.0.1", "::1\n2001:db8::1")).unwrap(),
        vec![
            San::Ip(Ipv4Addr::new(10, 0, 0, 1).into()),
            San::Ip(Ipv6Addr::LOCALHOST.into()),
            San::Ip("2001:db8::1".parse().unwrap()),
        ]
    );
}

#[test]
fn blank_lines_crlf_and_spaces_are_ignored() {
    assert_eq!(
        validate(&req(" a.local ", "  b.local  \r\n\r\n\tc.local\r\n")).unwrap(),
        vec![dns("a.local"), dns("b.local"), dns("c.local")]
    );
}

#[test]
fn duplicates_and_case_are_normalized() {
    assert_eq!(
        validate(&req("Server.Local", "server.local\nSERVER.LOCAL\n10.0.0.1\n10.0.0.1")).unwrap(),
        vec![dns("server.local"), San::Ip(Ipv4Addr::new(10, 0, 0, 1).into())]
    );
}

#[test]
fn wildcard_rules() {
    assert_eq!(
        validate(&req("*.example.local", "")).unwrap(),
        vec![dns("*.example.local")]
    );
    for bad in ["*", "a.*.local", "*a.local", "*.*.local"] {
        assert!(validate(&req("x.local", bad)).is_err(), "{bad}");
    }
}

#[test]
fn invalid_entries_are_rejected_with_the_entry_in_message() {
    let long_label = format!("{}.local", "a".repeat(64));
    for bad in [
        "under_score.local",
        "-a.local",
        "a-.local",
        ".a.local",
        "a.local.",
        "a..local",
        "[::1]",
        "a b.local",
        long_label.as_str(),
    ] {
        let err = validate(&req("x.local", bad)).unwrap_err().to_string();
        assert!(err.contains(bad), "{bad}: {err}");
    }
}

#[test]
fn non_hostname_cn_is_allowed_but_needs_a_san() {
    let err = validate(&req("測試伺服器", "")).unwrap_err().to_string();
    assert!(err.contains("至少"), "{err}");
    assert_eq!(
        validate(&req("測試伺服器", "host.local")).unwrap(),
        vec![dns("host.local")]
    );
}

#[test]
fn cn_and_organization_limits() {
    assert!(validate(&req("   ", "a.local")).is_err());
    assert!(validate(&req(&"a".repeat(65), "a.local")).is_err());
    assert!(validate(&req(&"a".repeat(64), "a.local")).is_ok());
    let mut r = req("a.local", "");
    r.organization = "組".repeat(65);
    assert!(validate(&r).is_err());
    r.organization = "組".repeat(64);
    assert!(validate(&r).is_ok());
}

#[test]
fn days_range() {
    for (days, ok) in [(0, false), (1, true), (MAX_DAYS, true), (MAX_DAYS + 1, false)] {
        let mut r = req("a.local", "");
        r.days = days;
        assert_eq!(validate(&r).is_ok(), ok, "{days}");
    }
}

#[test]
fn default_file_stem_sanitizes() {
    assert_eq!(default_file_stem("*.example.local"), "_.example.local");
    assert_eq!(default_file_stem("a/b:c?\"<>|\\d"), "a_b_c______d");
    assert_eq!(default_file_stem("   "), "selfsigned");
    assert_eq!(default_file_stem(" 測試 "), "測試");
}
```

`src/selfsign.rs`（只放宣告讓測試能編譯到「函式不存在」之前的程度——直接進 Step 3 也可）：

```rust
//! 建立自簽憑證（離線）：驗證表單、產生私鑰與 X.509 v3 自簽伺服器憑證。

#[cfg(test)]
mod tests;
```

`src/main.rs` 在 `mod certcore;` 下一行加入（`allow(dead_code)` 會在 Task 3 接上 GUI 後移除）：

```rust
#[allow(dead_code)]
mod selfsign;
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test selfsign`
Expected: 編譯失敗，錯誤為 `cannot find type SelfSignRequest` / `cannot find function validate` 等。

- [ ] **Step 3: 實作**

`src/selfsign.rs` 完整內容：

```rust
//! 建立自簽憑證（離線）：驗證表單、產生私鑰與 X.509 v3 自簽伺服器憑證。

use std::net::IpAddr;

use anyhow::{bail, Result};

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
        "selfsigned".to_string()
    } else {
        stem
    }
}

#[cfg(test)]
mod tests;
```

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test selfsign`
Expected: `test result: ok. 11 passed`（`selfsign::tests::*`）。

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`
Expected: 無警告。

- [ ] **Step 5: Commit**

```bash
git add src/selfsign.rs src/selfsign/tests.rs src/main.rs
git commit -m "Add self-signed certificate form validation"
```

---

### Task 2: 產生金鑰與自簽憑證（`selfsign::generate`）

**Files:**
- Modify: `Cargo.toml`（dependencies）
- Modify: `src/certcore.rs`（`Source` 新增 `Generated`；`Items::new`、`LoadedKey::new` 改為 `pub(crate)`）
- Modify: `src/selfsign.rs`（新增 `generate` 與輔助函式）
- Modify: `src/selfsign/tests.rs`（新增測試）

**Interfaces:**
- Consumes: Task 1 的 `SelfSignRequest`、`KeyType`、`San`、`validate`；`certcore::{Items, KeyKind, LoadedKey, Source}`
- Produces:
  - `certcore::Source::Generated`（`Items::type_label` 顯示「新產生的自簽憑證（…）」）
  - `pub(crate) fn Items::new(source: Source) -> Items`、`pub(crate) fn LoadedKey::new(kind: KeyKind, der: &[u8]) -> LoadedKey`
  - `pub fn generate(req: &SelfSignRequest) -> anyhow::Result<Items>`：回傳 `certs = [憑證 DER]`、`key = Some(PKCS#8)`、`source = Generated`

- [ ] **Step 1: 加入相依並調整 certcore 可見性**

`Cargo.toml`：把

```toml
rsa = "0.9"                       # RSA 私鑰 PKCS#1 <-> PKCS#8
p256 = { version = "0.13", features = ["pkcs8"] }   # EC(P-256) SEC1 -> PKCS#8
p384 = { version = "0.13", features = ["pkcs8"] }   # EC(P-384) SEC1 -> PKCS#8
```

改成

```toml
rsa = { version = "0.9", features = ["sha2"] }       # RSA 私鑰格式互轉、自簽憑證簽章
p256 = { version = "0.13", features = ["pkcs8", "ecdsa"] }   # EC(P-256)
p384 = { version = "0.13", features = ["pkcs8", "ecdsa"] }   # EC(P-384)
x509-cert = { version = "0.2", features = ["builder", "hazmat"] }  # 組裝自簽憑證
```

`src/certcore.rs`：

```rust
// Source 列舉加入最後一個變體
pub enum Source {
    Pem,
    DerCert,
    DerKey,
    Pkcs7,
    Pfx,
    Generated,
}
```

在 `Items::type_label` 的 `let src = match self.source { ... }` 加一行：

```rust
            Source::Generated => "新產生的自簽憑證",
```

把 `impl LoadedKey { fn new(` 改為 `pub(crate) fn new(`，`impl Items { fn new(` 改為 `pub(crate) fn new(`。

Run: `cargo build`
Expected: 編譯成功（相依下載完成）。

Run: `cargo tree -i ring; cargo tree -i aws-lc-sys; cargo tree -i openssl-sys`
Expected: 三者皆為 `error: package ID specification ... did not match any packages`（確認仍為純 Rust）。

- [ ] **Step 2: 寫失敗的測試**

在 `src/selfsign/tests.rs` 最上方的 `use` 之後加入：

```rust
use crate::certcore::{build_pfx, cert_info, unlock_pfx, Items, Source};
use x509_parser::prelude::*;

fn full_req(key_type: KeyType) -> SelfSignRequest {
    SelfSignRequest {
        common_name: "server.example.local".into(),
        organization: "測試 公司".into(),
        sans: "www.example.local\n192.168.1.10\n2001:db8::1".into(),
        key_type,
        days: 365,
    }
}

fn check_generated(key_type: KeyType, is_rsa: bool) -> Items {
    let items = generate(&full_req(key_type)).unwrap();
    assert_eq!(items.source, Source::Generated);
    assert_eq!(items.certs.len(), 1);
    assert_eq!(items.key_matches_leaf(), Some(true));

    let info = cert_info(&items.certs[0]).unwrap();
    assert_eq!(info.common_name.as_deref(), Some("server.example.local"));
    assert_eq!(info.subject, info.issuer);
    assert!(info.subject.contains("O=測試 公司"), "{}", info.subject);
    assert!((364..=365).contains(&info.days_left), "{}", info.days_left);
    for san in [
        "DNS: server.example.local",
        "DNS: www.example.local",
        "IP: 192.168.1.10",
        "IP: 2001:db8::1",
    ] {
        assert!(info.sans.contains(&san.to_string()), "{san}");
    }

    let (_, c) = X509Certificate::from_der(&items.certs[0]).unwrap();
    let serial = c.tbs_certificate.raw_serial();
    assert_eq!(serial.len(), 16);
    assert!(serial[0] < 0x80, "serial must be positive");

    let bc = c.basic_constraints().unwrap().unwrap();
    assert!(bc.critical);
    assert!(!bc.value.ca);

    let ku = c.key_usage().unwrap().unwrap();
    assert!(ku.critical);
    assert!(ku.value.digital_signature());
    assert_eq!(ku.value.key_encipherment(), is_rsa);
    assert!(!ku.value.non_repudiation());

    let eku = c.extended_key_usage().unwrap().unwrap();
    assert!(!eku.critical);
    assert!(eku.value.server_auth);

    assert!(c
        .extensions()
        .iter()
        .any(|e| matches!(e.parsed_extension(), ParsedExtension::SubjectKeyIdentifier(_))));

    let pfx = build_pfx(&items.certs, items.key.as_ref().unwrap(), "pw", false).unwrap();
    assert!(unlock_pfx(&pfx, "pw").is_ok());
    items
}

#[test]
fn generates_rsa_2048() {
    check_generated(KeyType::Rsa2048, true);
}

#[test]
fn generates_ec_p256() {
    check_generated(KeyType::EcP256, false);
}

#[test]
fn generates_ec_p384() {
    check_generated(KeyType::EcP384, false);
}

// debug 模式下產生 RSA 3072/4096 很慢，手動執行：cargo test --release -- --ignored
#[test]
#[ignore]
fn generates_rsa_3072() {
    check_generated(KeyType::Rsa3072, true);
}

#[test]
#[ignore]
fn generates_rsa_4096() {
    check_generated(KeyType::Rsa4096, true);
}

#[test]
fn special_characters_in_subject_are_kept() {
    let cn = "#a, b \"c\" + d=e <f>;g\\h 中文";
    let req = SelfSignRequest {
        common_name: cn.into(),
        organization: "O, \"quoted\" + 公司".into(),
        sans: "host.local".into(),
        key_type: KeyType::EcP256,
        days: 30,
    };
    let items = generate(&req).unwrap();
    let info = cert_info(&items.certs[0]).unwrap();
    assert_eq!(info.common_name.as_deref(), Some(cn));
    assert_eq!(info.sans, vec!["DNS: host.local".to_string()]);
}

#[test]
fn wildcard_cn_becomes_san() {
    let mut req = full_req(KeyType::EcP256);
    req.common_name = "*.example.local".into();
    req.sans.clear();
    let items = generate(&req).unwrap();
    let info = cert_info(&items.certs[0]).unwrap();
    assert_eq!(info.sans, vec!["DNS: *.example.local".to_string()]);
}

#[test]
fn max_validity_after_2049_uses_generalized_time() {
    let mut req = full_req(KeyType::EcP256);
    req.days = MAX_DAYS;
    let items = generate(&req).unwrap();
    let info = cert_info(&items.certs[0]).unwrap();
    assert!(
        (MAX_DAYS as i64 - 1..=MAX_DAYS as i64).contains(&info.days_left),
        "{}",
        info.days_left
    );
}

#[test]
fn generate_rejects_invalid_request() {
    let mut req = full_req(KeyType::EcP256);
    req.common_name.clear();
    assert!(generate(&req).is_err());
}
```

- [ ] **Step 3: 執行測試確認失敗**

Run: `cargo test selfsign`
Expected: 編譯失敗，`cannot find function generate in this scope`。

- [ ] **Step 4: 實作 `generate`**

在 `src/selfsign.rs` 的 `use` 區改為：

```rust
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
```

在 `default_file_stem` 之後、`#[cfg(test)]` 之前加入：

```rust
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
    Ok(RelativeDistinguishedName::from(SetOfVec::try_from(vec![atv])?))
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
```

`rsa_material` 使用的 `pkcs8::SecretDocument` 來自既有相依 `pkcs8 0.10`（`Cargo.toml` 已有），無需新增。

- [ ] **Step 5: 執行測試確認通過**

Run: `cargo test selfsign`
Expected: `test result: ok. 18 passed; 0 failed; 2 ignored`。

Run: `cargo test --release selfsign -- --ignored`
Expected: `generates_rsa_3072`、`generates_rsa_4096` 通過。

Run: `cargo test`
Expected: 既有 19 個 certcore 測試仍全數通過。

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`
Expected: 無警告。

- [ ] **Step 6: OpenSSL 互通性檢查（手動）**

在 `src/selfsign/tests.rs` 暫時加入以下測試（**不要 commit**），把三種金鑰的憑證寫到暫存目錄：

```rust
#[test]
fn tmp_dump_for_openssl() {
    let dir = std::env::temp_dir();
    for (name, kt) in [("rsa", KeyType::Rsa2048), ("p256", KeyType::EcP256), ("p384", KeyType::EcP384)] {
        let items = generate(&full_req(kt)).unwrap();
        std::fs::write(dir.join(format!("selfsign-{name}.der")), &items.certs[0]).unwrap();
    }
}
```

Run（Git Bash）：

```bash
cargo test tmp_dump_for_openssl
T=$(cygpath "$TEMP")
for n in rsa p256 p384; do
  MSYS_NO_PATHCONV=1 openssl x509 -inform DER -in "$T/selfsign-$n.der" -out "$T/selfsign-$n.pem"
  MSYS_NO_PATHCONV=1 openssl verify -CAfile "$T/selfsign-$n.pem" "$T/selfsign-$n.pem"
done
MSYS_NO_PATHCONV=1 openssl x509 -in "$T/selfsign-rsa.pem" -noout -text -nameopt utf8
```

Expected: 三個 `verify` 皆為 `: OK`；`-text` 顯示 `Basic Constraints: critical CA:FALSE`、`Key Usage: critical Digital Signature, Key Encipherment`、`Extended Key Usage:`（**沒有** critical）`TLS Web Server Authentication`、SAN 含兩個 DNS 與兩個 IP、`Signature Algorithm: sha256WithRSAEncryption`。

檢查完後移除 `tmp_dump_for_openssl`，確認 `git diff src/selfsign/tests.rs` 只剩 Step 2 的測試。

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/certcore.rs src/selfsign.rs src/selfsign/tests.rs
git commit -m "Generate self-signed server certificates with x509-cert"
```

---

### Task 3: GUI 表單與背景產生

**Files:**
- Create: `src/selfsign_form.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `selfsign::{generate, validate, default_file_stem, KeyType, SelfSignRequest, MAX_DAYS, LONG_VALIDITY_WARN_DAYS}`；`certcore::{Items, Loaded}`；`main.rs` 既有的 `App::set_loaded`、`App::reset`、`App::ok`、`App::err`、常數 `ORANGE`、`RED`
- Produces:
  - `selfsign_form::SelfSignForm { pub open: bool, pub request: SelfSignRequest, pub error: Option<String> }`（`Default`）
  - `SelfSignForm::show(&mut self, ctx: &egui::Context, busy: bool) -> Option<SelfSignRequest>`

- [ ] **Step 1: 建立表單元件**

`src/selfsign_form.rs`：

```rust
//! 「建立自簽憑證」表單視窗。只負責表單狀態與繪製；產生工作由 main.rs 在背景執行緒執行。

use crate::selfsign::{validate, KeyType, SelfSignRequest, LONG_VALIDITY_WARN_DAYS, MAX_DAYS};
use crate::{ORANGE, RED};

#[derive(Default)]
pub struct SelfSignForm {
    pub open: bool,
    pub request: SelfSignRequest,
    pub error: Option<String>,
}

impl SelfSignForm {
    /// 繪製表單。按下「產生」且驗證通過時回傳要送出的請求。
    /// `busy` 為 true（產生中）時停用所有欄位、不允許關閉，並顯示「產生中…」。
    pub fn show(&mut self, ctx: &egui::Context, busy: bool) -> Option<SelfSignRequest> {
        if !self.open {
            return None;
        }
        let mut submit = None;
        let mut open = true;
        egui::Window::new("建立自簽憑證")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(480.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.add_enabled_ui(!busy, |ui| {
                    egui::Grid::new("selfsign_grid")
                        .num_columns(2)
                        .spacing([12.0, 8.0])
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("一般名稱 (CN)").strong());
                            ui.add(
                                egui::TextEdit::singleline(&mut self.request.common_name)
                                    .hint_text("server.example.local")
                                    .desired_width(300.0),
                            );
                            ui.end_row();

                            ui.label(egui::RichText::new("主體別名 (SAN)").strong());
                            ui.vertical(|ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut self.request.sans)
                                        .hint_text("一行一個，例如：\nwww.example.local\n192.168.1.10")
                                        .desired_rows(3)
                                        .desired_width(300.0),
                                );
                                ui.label(
                                    egui::RichText::new("可填 DNS 名稱或 IP；CN 會自動加入")
                                        .small()
                                        .weak(),
                                );
                            });
                            ui.end_row();

                            ui.label(egui::RichText::new("組織 (O)").strong());
                            ui.add(
                                egui::TextEdit::singleline(&mut self.request.organization)
                                    .hint_text("選填")
                                    .desired_width(300.0),
                            );
                            ui.end_row();

                            ui.label(egui::RichText::new("金鑰類型").strong());
                            egui::ComboBox::from_id_salt("selfsign_key_type")
                                .selected_text(self.request.key_type.label())
                                .width(300.0)
                                .show_ui(ui, |ui| {
                                    for key_type in KeyType::ALL {
                                        ui.selectable_value(
                                            &mut self.request.key_type,
                                            key_type,
                                            key_type.label(),
                                        );
                                    }
                                });
                            ui.end_row();

                            ui.label(egui::RichText::new("有效天數").strong());
                            ui.add(
                                egui::DragValue::new(&mut self.request.days)
                                    .range(1..=MAX_DAYS)
                                    .suffix(" 天"),
                            );
                            ui.end_row();
                        });
                });

                if self.request.days > LONG_VALIDITY_WARN_DAYS {
                    ui.colored_label(
                        ORANGE,
                        format!(
                            "⚠ macOS / iOS 不接受效期超過 {LONG_VALIDITY_WARN_DAYS} 天的 TLS 憑證"
                        ),
                    );
                }
                if let Some(error) = &self.error {
                    ui.colored_label(RED, format!("✖ {error}"));
                }

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if busy {
                        ui.spinner();
                        ui.label("產生中…");
                    } else if ui.button("✨ 產生").clicked() {
                        match validate(&self.request) {
                            Ok(_) => {
                                self.error = None;
                                submit = Some(self.request.clone());
                            }
                            Err(e) => self.error = Some(e.to_string()),
                        }
                    }
                });
                ui.label(
                    egui::RichText::new(
                        "產生後會直接載入主畫面；私鑰只存在記憶體中，請記得用主畫面的按鈕匯出。",
                    )
                    .small()
                    .weak(),
                );
            });
        if !busy {
            self.open = open;
        }
        submit
    }
}
```

- [ ] **Step 2: 接上 main.rs**

1. 模組宣告：把 Task 1 加的

```rust
#[allow(dead_code)]
mod selfsign;
```

改為

```rust
mod selfsign;
mod selfsign_form;
```

2. `use` 區加入：

```rust
use certcore::Items;
use selfsign_form::SelfSignForm;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Duration;
```

（若 `certcore::{...}` 已有匯入清單，把 `Items` 併入該清單即可。）

3. 在 `enum Action` 定義之前加入：

```rust
/// 背景產生自簽憑證的工作
struct PendingGenerate {
    /// 產生完成後使用的預設檔名
    file_stem: String,
    rx: Receiver<anyhow::Result<Items>>,
}
```

4. `struct App` 在 `exe_sha256` 欄位之後加入：

```rust
    selfsign_form: SelfSignForm,
    pending: Option<PendingGenerate>,
    generated_stem: Option<String>, // 自簽憑證的預設檔名（沒有來源檔案時使用）
```

5. `fn reset` 內加入一行 `self.generated_stem = None;`。

6. `fn base_name` 改為：

```rust
    fn base_name(&self) -> String {
        self.file_path
            .as_ref()
            .and_then(|f| f.file_stem())
            .map(|s| s.to_string_lossy().to_string())
            .or_else(|| self.generated_stem.clone())
            .unwrap_or_else(|| "output".to_string())
    }
```

7. 在 `impl App` 內（`fn run` 之前）加入：

```rust
    fn start_generate(&mut self, request: selfsign::SelfSignRequest) {
        let (tx, rx) = mpsc::channel();
        let file_stem = selfsign::default_file_stem(&request.common_name);
        std::thread::spawn(move || {
            let _ = tx.send(selfsign::generate(&request));
        });
        self.pending = Some(PendingGenerate { file_stem, rx });
    }

    fn poll_generate(&mut self, ctx: &egui::Context) {
        let Some(pending) = &self.pending else {
            return;
        };
        match pending.rx.try_recv() {
            Err(TryRecvError::Empty) => ctx.request_repaint_after(Duration::from_millis(100)),
            Err(TryRecvError::Disconnected) => {
                self.pending = None;
                self.selfsign_form.error = Some("產生失敗（背景工作意外中止）".to_string());
                self.err("自簽憑證產生失敗（背景工作意外中止）");
            }
            Ok(result) => {
                let file_stem = self.pending.take().map(|p| p.file_stem).unwrap_or_default();
                match result {
                    Ok(items) => {
                        self.reset();
                        self.file_path = None;
                        self.generated_stem = Some(file_stem);
                        self.selfsign_form.open = false;
                        self.selfsign_form.error = None;
                        self.ok("已產生自簽憑證；私鑰尚未儲存，請記得匯出");
                        self.set_loaded(Loaded::Items(items));
                    }
                    Err(e) => {
                        self.selfsign_form.error = Some(e.to_string());
                        self.err(format!("自簽憑證產生失敗：{e}"));
                    }
                }
            }
        }
    }
```

8. `fn update` 的拖放處理改為（產生中拒絕載入，避免結果回來時覆蓋剛載入的檔案）：

```rust
        if let Some(path) = dropped {
            if self.pending.is_some() {
                self.err("自簽憑證產生中，請稍候再載入檔案");
            } else {
                self.load_file(&path);
            }
        }
```

9. `fn update` 中 `self.about_window(ctx);` 之前加入：

```rust
        if let Some(request) = self.selfsign_form.show(ctx, self.pending.is_some()) {
            self.start_generate(request);
        }
        self.poll_generate(ctx);
```

10. `fn header` 的右側按鈕區（`right_to_left` layout 內，「ℹ 關於」按鈕之後）加入：

```rust
                if ui.button("✨ 建立自簽憑證").clicked() {
                    self.selfsign_form.open = true;
                }
```

11. `Action::PickFile` 分支開頭加入同樣的保護：

```rust
            Action::PickFile => {
                if self.pending.is_some() {
                    self.err("自簽憑證產生中，請稍候再載入檔案");
                    return;
                }
```

（其後原本的 `if let Some(path) = rfd::FileDialog::new()` … 保持不變。）

- [ ] **Step 3: 編譯與靜態檢查**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: 無警告；所有測試通過（certcore 19 + selfsign 18，2 ignored）。

- [ ] **Step 4: 手動檢查表單畫面**

暫時在 `main()` 的 `let mut app = App::default();` 後加一行 `app.selfsign_form.open = true;`（**不要 commit**），執行 `cargo run`：

- 表單顯示五個欄位，金鑰類型預設「RSA 2048（相容性最佳）」、有效天數 365。
- CN 留空按「✨ 產生」→ 紅字「請輸入一般名稱 (CN)」。
- 有效天數拖到 826 以上 → 顯示橘色 825 天警告。
- CN 填 `server.example.local`、SAN 填 `192.168.1.10`、選 RSA 4096 → 按產生：顯示 spinner「產生中…」、欄位停用、右上 X 無法關閉；完成後表單關閉、主畫面顯示「新產生的自簽憑證（1 張憑證 + PKCS#8 私鑰）」、憑證內容與「✔ 私鑰與此憑證成對」。
- 按「憑證 → PEM（.crt）」，另存對話框預設檔名為 `server.example.local.crt`。

檢查完移除暫時加的那一行。

- [ ] **Step 5: 手動檢查產生中拖放**

`cargo run --release` 以外的 debug 版產生 RSA 4096 約需數秒到十數秒：開表單、選 RSA 4096、按產生，產生期間把 `tests/fixtures/rsa.crt` 拖進視窗。
Expected: 訊息區出現「✖ 自簽憑證產生中，請稍候再載入檔案」；產生完成後主畫面顯示新產生的憑證。

- [ ] **Step 6: Commit**

```bash
git add src/selfsign_form.rs src/main.rs
git commit -m "Add self-signed certificate form with background generation"
```

---

### Task 4: 文件與版本

**Files:**
- Modify: `README.md`
- Modify: `Cargo.toml`（version）、`Cargo.lock`

**Interfaces:**
- Consumes: Task 1–3 完成的功能
- Produces: v1.3.0 可發佈的原始碼

- [ ] **Step 1: 版本號**

`Cargo.toml`：`version = "1.2.1"` → `version = "1.3.0"`，然後執行 `cargo build` 更新 `Cargo.lock`。

- [ ] **Step 2: README**

在「## ✨ 功能」清單中，「**私鑰配對檢查**」那一項之後加入：

```markdown
- **建立自簽憑證**：離線產生私鑰與自簽 TLS 伺服器憑證（RSA 2048/3072/4096、EC P-256/P-384），
  可設定 CN、SAN（DNS / IP）、組織與有效天數，產生後直接匯出 PFX / PEM
```

在「## 📖 使用方式」第 4 點的清單最後加入：

```markdown
   - 按右上角「✨ 建立自簽憑證」→ 填寫 CN / SAN / 金鑰類型 / 有效天數 →「產生」→ 用主畫面的按鈕匯出
```

在「## 📖 使用方式」最後一個 `>` 提示區塊之後加入：

```markdown
> **自簽憑證的信任**：自簽憑證不是由公開 CA 簽發，瀏覽器預設會顯示「不安全」。
> 適合內網、測試環境與開發機；需在每台用戶端手動匯入信任
> （Windows：以系統管理員身分把 `.crt` 匯入「本機電腦 → 受信任的根憑證授權單位」）。
> **不適合用在對外公開的網站**，公開網站請向 CA 申請憑證。
```

在「### 目前不支援」清單加入一項：

```markdown
- 建立私有 CA、產生 CSR、向 CA（含 Let's Encrypt）申請憑證
```

- [ ] **Step 3: 最終檢查**

Run: `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked`
Expected: 全部通過。

- [ ] **Step 4: Commit**

```bash
git add README.md Cargo.toml Cargo.lock
git commit -m "Document self-signed certificates and bump version to 1.3.0"
```

- [ ] **Step 5: 推送、開 PR、審查、合併、發版**

依專案慣例：推送 `self-signed-cert` 分支 → 開 PR → 等 CI 通過 → 審查並以留言記錄結果 → `gh pr merge --merge --delete-branch`
→ 在 `main` 上建立並推送 `v1.3.0` tag → 等 Release workflow 完成 → 下載 exe 驗證 `SHA256SUMS.txt` 並啟動確認。
