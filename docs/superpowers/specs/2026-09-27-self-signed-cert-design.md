# 建立自簽憑證 — 設計文件

- 日期：2026-09-27
- 狀態：已與使用者確認設計，待審閱本文件
- 目標版本：v1.3.0

## 目的

讓使用者在工具內**離線**產生一張自簽的伺服器憑證（含私鑰），主要用於內網系統、測試環境與開發機。
產生後可直接用現有功能匯出成 PFX / PEM。

### 不在範圍內

- 私有 CA（先建根 CA 再簽發伺服器憑證）
- 產生 CSR、向任何 CA 申請憑證（含 Let's Encrypt / ACME）
- 任何網路連線
- 用戶端憑證、程式碼簽章憑證等非 TLS 伺服器用途

## 使用流程

1. 標題列新增「✨ 建立自簽憑證」按鈕，按下後開啟表單視窗（`egui::Window`）。
2. 使用者填寫表單、按「產生」。
3. 產生期間表單按鈕停用並顯示「產生中…」；GUI 不凍結。
4. 產生完成後關閉表單，結果以 `Loaded::Items`（`source = Source::Generated`）載入主畫面，
   等同使用者拖入一個含「1 張憑證 + PKCS#8 私鑰」的檔案：
   - 憑證資訊面板、私鑰配對檢查照常顯示
   - 匯出一律使用既有按鈕（憑證 → PEM/DER、私鑰 → PKCS#8/PKCS#1/SEC1、合併 PEM、產生 PFX）
   - 預設存檔檔名以 CN 為基礎（非法檔名字元以 `_` 取代，例如 `*.example.local` → `_.example.local`）
5. 狀態列顯示「已產生自簽憑證，私鑰尚未儲存，請記得匯出」。

## 表單欄位

| 欄位 | 預設 | 驗證規則 |
|---|---|---|
| 一般名稱 (CN) | 空白 | 必填；去除前後空白後不可為空；長度 ≤ 64 |
| 主體別名 (SAN) | 空白 | 多行文字，一行一個，忽略空白行；可解析為 IPv4/IPv6 的視為 IP，否則視為 DNS 名稱 |
| 組織 (O) | 空白 | 選填；長度 ≤ 64 |
| 金鑰類型 | RSA 2048 | RSA 2048 / RSA 3072 / RSA 4096 / EC P-256 / EC P-384 |
| 有效天數 | 365 | 整數 1–3650；> 825 天時顯示警告（不阻擋）：「macOS / iOS 不接受效期超過 825 天的 TLS 憑證」 |

DNS 名稱規則：只允許 `A-Z a-z 0-9 - . *`（`-` 不可在一段的頭尾；DNS 名稱一律轉小寫後去重）；`*` 只能出現在最左邊一段且整段為 `*`（如 `*.example.local`）；
每段 1–63 字元、總長 ≤ 253；不可以 `.` 開頭或結尾。最後一段不可全為數字（避免把打錯的 IP，例如 `192.168.1.300`，悄悄當成 DNS 名稱）。

CN 若不在 SAN 清單中，會自動加入（CN 可解析為 IP 時加為 IP SAN，否則依 DNS 規則驗證後加為 DNS SAN；
CN 不符合 DNS 規則時不加入 SAN、也不報錯，因為 CN 可以是任意描述文字）。
SAN 最終不可為空；若為空則顯示錯誤「請至少提供一個有效的主機名稱或 IP」。重複項目自動去除。

驗證錯誤在表單內以紅字顯示，不送出產生請求。

## 憑證內容

| 項目 | 內容 |
|---|---|
| 版本 | X.509 v3 |
| 序號 | 16 bytes 亂數，最高位元清 0（確保為正整數）、次高位元設 1（確保 DER 編碼長度固定為 16 bytes） |
| Subject / Issuer | 相同：`CN=<CN>`，有填組織時為 `O=<O>, CN=<CN>` |
| 生效時間 | 目前時間 − 5 分鐘（容忍時鐘誤差） |
| 到期時間 | 生效時間 + 有效天數 |
| basicConstraints | critical, `CA:FALSE` |
| keyUsage | critical；RSA：digitalSignature + keyEncipherment；EC：digitalSignature |
| extendedKeyUsage | non-critical，serverAuth（`x509-cert` 預設標 critical，需包一層強制 non-critical） |
| subjectAltName | 依上節規則產生的 DNS / IP 清單 |
| subjectKeyIdentifier | 公鑰的 SHA-1（RFC 5280 方法 1） |
| 簽章演算法 | RSA：sha256WithRSAEncryption（PKCS#1 v1.5）；P-256：ecdsa-with-SHA256；P-384：ecdsa-with-SHA384 |

設計理由：`CA:FALSE` + serverAuth 是 mkcert 等工具的慣例；Firefox 會拒絕把 `CA:TRUE` 的自簽憑證當伺服器憑證使用。

## 程式結構

### 新模組 `src/selfsign.rs`

只負責產生，不依賴 GUI：

```rust
pub enum KeyType { Rsa2048, Rsa3072, Rsa4096, EcP256, EcP384 }

pub struct SelfSignRequest {
    pub common_name: String,
    pub organization: String,   // 空字串表示不填
    pub sans: String,           // 表單原始多行文字
    pub key_type: KeyType,
    pub days: u32,
}

/// 驗證表單並整理成最終的 SAN 清單；錯誤訊息為中文，可直接顯示。
pub fn validate(req: &SelfSignRequest) -> Result<Vec<San>>;

/// 產生私鑰與自簽憑證，回傳可直接載入主畫面的 Items。
pub fn generate(req: &SelfSignRequest) -> Result<Items>;
```

- 金鑰產生：`rsa::RsaPrivateKey::new(&mut OsRng, bits)`、`p256/p384::SecretKey::random(&mut OsRng)`。
- 憑證組裝：`x509_cert::builder::CertificateBuilder`（`Profile::Manual { issuer: None }`，需 `hazmat` feature；`Profile::Leaf` 會多加 nonRepudiation，故不用），
  Subject 直接組成 `RdnSequence`（UTF8String），不經字串解析，特殊字元與中文原樣保留，
  簽章器為 `rsa::pkcs1v15::SigningKey<Sha256>`、`p256::ecdsa::SigningKey`、`p384::ecdsa::SigningKey`。
- 私鑰以 PKCS#8 DER 存入 `LoadedKey { kind: KeyKind::Pkcs8, der: Zeroizing<..> }`。
- `certcore::Source` 新增 `Generated` 變體，`type_label` 顯示「新產生的自簽憑證（1 張憑證 + PKCS#8 私鑰）」。

### 相依套件

- 新增 `x509-cert = { version = "0.2", features = ["builder", "hazmat"] }`（與現有 `rsa 0.9`、`p256/p384 0.13`、`pkcs8 0.10` 同一代 RustCrypto）
- `rsa` 開啟 `sha2` feature；`p256` / `p384` 開啟 `ecdsa` feature
- 亂數來源使用 `rand_core::OsRng`（透過既有套件 re-export，不另加相依）

全部為純 Rust，維持 README「不需要 OpenSSL」的說法。

### GUI（`src/main.rs`）

- `App` 新增 `selfsign: SelfSignForm`（表單欄位、錯誤訊息、是否開啟）與 `pending: Option<mpsc::Receiver<Result<Items>>>`。
- 按「產生」：先在 UI 執行緒呼叫 `validate`；通過後 `std::thread::spawn` 呼叫 `generate`，結果經 channel 回傳。
- `update()` 每幀 `try_recv`；等待中時呼叫 `ctx.request_repaint_after(100ms)` 讓畫面更新。
- 收到成功結果：關閉表單、`set_loaded(Loaded::Items(items))`、設定預設檔名；失敗：在表單顯示錯誤。
- 產生中停用「產生」按鈕、也不接受拖放新檔案覆蓋（避免結果回來時覆蓋使用者剛載入的檔案）。

## 錯誤處理

- 表單驗證錯誤：表單內紅字，不送出。
- 產生失敗（理論上只有亂數來源或編碼錯誤）：表單內紅字 + 狀態列錯誤訊息。
- 背景執行緒 panic：channel 斷線（`TryRecvError::Disconnected`），顯示「產生失敗」並恢復表單。
  （release 設定為 `panic = "abort"`，此情況實際上會結束程式；debug 下仍需正確處理。）

## 測試

單元測試（`src/selfsign/tests.rs`）：

- 每種金鑰類型各產生一次（`Cargo.toml` 加入 `[profile.dev.package."*"] opt-level = 2`，
  讓 RSA 3072/4096 在 debug 測試中也夠快，全部放進一般 `cargo test`；此做法沿用自 code-signer 專案）：
  - `x509-parser` 解析成功；Subject = Issuer；CN、O 正確
  - SAN 含預期的 DNS 與 IP（IPv4、IPv6）
  - 有效期 ≈ 指定天數（允許 5 分鐘誤差）
  - basicConstraints CA:FALSE、keyUsage、EKU serverAuth 存在
  - `Items::key_matches_leaf() == Some(true)`
  - `build_pfx` 成功且 `unlock_pfx` 可解回
- `validate`：空白 CN、非法 DNS 字元、`*` 位置錯誤、IP 格式、天數 0 / 3651、SAN 去重、CN 自動加入 SAN。

手動互通性檢查：

- `openssl x509 -in out.crt -text -noout` 檢查欄位
- `openssl verify -CAfile out.crt out.crt` 確認自簽簽章有效
- GUI 截圖確認表單排版與「產生中」狀態

## 文件

README「功能」與「使用方式」補上建立自簽憑證的說明，並註明：自簽憑證需手動匯入信任（Windows：匯入「受信任的根憑證授權單位」），不適合對外公開網站。
