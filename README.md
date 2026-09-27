# 憑證格式轉換工具（cert-converter）

[![CI](https://github.com/tntrock/cert-converter/actions/workflows/ci.yml/badge.svg)](https://github.com/tntrock/cert-converter/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tntrock/cert-converter)](https://github.com/tntrock/cert-converter/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

純 Rust、**完全離線**、**免安裝單一 exe** 的 Windows 憑證格式轉換 GUI 工具。
專為網頁憑證（SSL/TLS）日常維運設計，支援拖放操作與憑證內容檢視。

---

## 📥 下載

到 [Releases](https://github.com/tntrock/cert-converter/releases/latest) 下載 `cert-converter-vX.Y.Z-windows-x64.exe`，雙擊即可執行，不需安裝任何東西。

- 系統需求：Windows 10 / 11（64 位元）
- 可用同一頁的 `SHA256SUMS.txt` 驗證檔案完整性：
  ```powershell
  Get-FileHash .\cert-converter-*.exe -Algorithm SHA256
  ```
- 程式右上角的「ℹ 關於」會顯示版本、作者、官方下載網址，以及**目前執行檔的 SHA-256**，
  可直接和 Release 頁面的 `SHA256SUMS.txt` 比對，確認拿到的是官方版本。
- 本工具會處理私鑰，**請只從上方的官方 Releases 頁面下載**，不要使用來路不明的轉貼版本。
- 執行檔沒有數位簽章，第一次執行時 Windows SmartScreen 可能顯示「Windows 已保護您的電腦」，
  按「其他資訊」→「仍要執行」即可。若有疑慮，可依下方步驟自行從原始碼建置。

---

## ✨ 功能

- **拖放檔案** 或點選檔案，依「內容」自動辨識格式（不看副檔名）
- **憑證內容檢視**：一般名稱 (CN)、完整主體 (Subject)、簽發者、有效期間（UTC，並標示剩餘天數／已過期）、
  序號、SHA-256 指紋、SAN、金鑰類型
- **私鑰配對檢查**：自動確認私鑰與憑證是否成對，並把憑證鏈排成「葉 → 中繼 → 根」的正確順序
- **格式轉換**

  | 來源 | 可輸出 |
  |---|---|
  | `PFX` / `P12` | 私鑰 `.key`、憑證 `.crt`、中繼憑證鏈 `chain.crt`、完整憑證鏈 `fullchain.crt`、合併 PEM、重新打包 PFX（可改加密方式） |
  | `PEM`（憑證＋私鑰） | `PFX`（可選 **現代 AES-256** 或 **舊式相容 3DES**），以及上述各種 PEM 檔 |
  | 憑證 `PEM` / `DER` / `.p7b` | PEM ⇄ DER、憑證鏈 |
  | RSA 私鑰 | `PKCS#1` ⇄ `PKCS#8` |
  | EC 私鑰（P-256 / P-384） | `SEC1` ⇄ `PKCS#8` |
  | 加密私鑰 | 輸入密碼解密（`ENCRYPTED PRIVATE KEY` 與舊式 OpenSSL `Proc-Type: 4,ENCRYPTED` 皆支援） |

- **安全性**：全程無網路呼叫、不寫任何暫存檔，可在內網／離線環境使用

技術棧全部為**純 Rust**（`eframe`/`egui` + `p12-keystore` + `x509-parser` + `rsa`/`p256`/`p384`），
**不需要 OpenSSL**，最終產物為單一 `.exe`。

### 支援的輸入

| 類型 | 說明 |
|---|---|
| PEM | 憑證、私鑰、PKCS#7；可含多個區塊，區塊前後可有文字（例如 `openssl x509 -text` 的輸出）；UTF-8 或 UTF-16（Windows 記事本）皆可 |
| DER | 單張憑證、PKCS#1 / PKCS#8 / SEC1 私鑰、加密 PKCS#8 私鑰 |
| PKCS#7 | `.p7b` / `.p7c`（DER 或 PEM） |
| PFX / PKCS#12 | 現代 (AES-256 + PBKDF2) 與舊式 (3DES / RC2 + SHA1) 加密 |

### 目前不支援

- 其他 EC 曲線（P-521、secp256k1…）的 SEC1 轉換與配對檢查
- Ed25519 私鑰只能以 PKCS#8 輸出，也無法做配對檢查（仍可打包 PFX）
- 使用 MD5 或 RC4 的極舊 PFX / 加密私鑰（網頁憑證中極罕見）
- 一個檔案內有多把私鑰時，只會使用第一把
- 輸出「加密的」PEM 私鑰
- macOS / Linux（程式碼可編譯，但字型載入與測試僅針對 Windows）

---

## 📖 使用方式

1. 執行 `cert-converter.exe`。
2. 把憑證檔拖進視窗，或按「選擇檔案…」。
3. 上方會顯示**偵測到的格式**、**憑證內容**與**私鑰配對結果**。
4. 依內容出現對應的操作：
   - 載入 **PFX** → 輸入密碼 →「解鎖 PFX」→ 選擇要輸出的檔案
   - 載入**加密私鑰** → 輸入私鑰密碼 →「解密私鑰」
   - 載入含**憑證＋私鑰**的 PEM → 設定並確認密碼、選加密方式 →「產生 PFX」
   - 載入單張憑證或 `.p7b` → 輸出 PEM / DER / 憑證鏈
   - 載入私鑰 → 轉成 PKCS#1 / PKCS#8 / SEC1
5. 按下按鈕後會跳出「另存新檔」對話框，選位置儲存即可。

> **現代 vs 舊式相容**：預設用現代 AES-256（安全性高）。若把產生的 PFX 匯入到較舊系統
> （舊版 IIS / Java keytool / 網路設備）出現「密碼錯誤／無法匯入」，改選「舊式相容 (3DES)」重轉一次即可。

> **Nginx / Apache 要用哪個檔？**
> Nginx 的 `ssl_certificate` 用 `fullchain.crt`；Apache 2.4.8 以上的 `SSLCertificateFile` 也用 `fullchain.crt`，
> 較舊版本則是 `SSLCertificateFile` 用 `.crt`、`SSLCertificateChainFile` 用 `chain.crt`。私鑰用 `PKCS#8` 的 `.key` 即可。

---

## 🛠 從原始碼建置（Windows 64-bit）

### 1. 安裝工具鏈（僅第一次）
1. 安裝 **Rust**（1.88 以上）：到 <https://rustup.rs> 下載 `rustup-init.exe` 執行，一路 Enter 使用預設值。
2. 安裝 **Visual Studio C++ 生成工具**（MSVC 連結器，Rust 在 Windows 編譯原生程式必要）：
   下載 <https://visualstudio.microsoft.com/visual-cpp-build-tools/>，
   安裝時勾選「**使用 C++ 的桌面開發 (Desktop development with C++)**」。
3. 安裝完成後**重開一個新的終端機**（PowerShell 或 CMD）。

### 2. 編譯
在專案根目錄（含 `Cargo.toml` 的資料夾）執行：

```powershell
cargo build --release --locked
```

第一次會下載並編譯相依套件，需數分鐘。完成後產物在 `target\release\cert-converter.exe`，
即為**免安裝、可單獨複製**的執行檔（雙擊即可執行，不會跳出黑色主控台視窗）。

`Cargo.lock` 已納入版本控制，`--locked` 會使用與 Release 完全相同的相依套件版本。

### 3. 執行測試

```powershell
cargo test
```

測試使用 `tests/fixtures/` 內以 OpenSSL 產生的測試憑證與私鑰（僅供測試，非真實憑證）。

---

## 🧩 專案結構

```
cert-converter/
├─ Cargo.toml            相依套件與建置設定
├─ Cargo.lock            鎖定的相依套件版本
├─ LICENSE               MIT 授權
├─ src/
│  ├─ main.rs            GUI（eframe/egui）、拖放、字型、流程
│  ├─ certcore.rs        核心邏輯：格式偵測、憑證解析、各種轉換
│  └─ certcore/tests.rs  單元測試
├─ tests/fixtures/       測試用憑證/私鑰（非真實憑證）
└─ .github/workflows/    CI（fmt / clippy / test）與 Release 自動建置
```

---

## 🚀 發行新版本（維護者）

1. 修改 `Cargo.toml` 的 `version`（例如 `1.2.0`），並執行 `cargo build` 更新 `Cargo.lock`，提交後合併到 `main`。
2. 在 `main` 上建立並推送對應的 tag：
   ```powershell
   git tag v1.2.0
   git push origin v1.2.0
   ```
3. GitHub Actions 會自動測試、建置，並建立 Release、上傳 exe 與 `SHA256SUMS.txt`。

---

## 🩺 疑難排解

- **`link.exe not found` / 連結失敗**：沒裝到 MSVC C++ 生成工具，回到「從原始碼建置」步驟 1-2 重裝並勾選「使用 C++ 的桌面開發」。
- **中文顯示為方塊**：程式會自動載入系統的微軟正黑體（`C:\Windows\Fonts\msjh.ttc`）。
  若你的系統沒有該字型，請確認 `Fonts` 目錄至少有 `mingliu.ttc`、`msyh.ttc` 或 `simsun.ttc`。
- **PFX 解不開**：多半是密碼錯誤，或該 PFX 使用了 MD5 / RC4 的極舊加密（本工具不支援，這在網頁憑證極罕見）。
- **「私鑰與檔案中的憑證都不成對」**：私鑰和憑證不是同一組，常見原因是拿到舊的私鑰或別台主機的憑證，請重新確認檔案。
- **防毒軟體誤判**：不建議用 UPX 等工具壓縮執行檔，壓縮後的 exe 常被防毒軟體誤判為惡意程式。

---

## 🔒 安全備註

- 本工具**不連線、不上傳、不寫暫存檔**。
- 私鑰與密碼在程式內以 [`zeroize`](https://crates.io/crates/zeroize) 包裝，不再使用時會盡量清除記憶體內容
  （部分第三方函式庫與 GUI 元件內部的暫存複本無法完全保證）。
- **注意：輸出的 `.key` 與合併 PEM 檔都是「未加密」的私鑰**，請妥善保管，用完後刪除不需要的副本。
- 建議在受信任的機器上操作。

---

## 📄 授權

本專案以 [MIT License](LICENSE) 授權。
