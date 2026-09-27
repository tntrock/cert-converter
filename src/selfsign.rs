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
