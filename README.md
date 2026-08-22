# 憑證格式轉換工具（cert-converter）

純 Rust、**完全離線**、**免安裝** 的 Windows 憑證格式轉換 GUI 工具。  
專為網頁憑證（SSL/TLS）日常維運設計，支援拖放操作與憑證內容檢視。

---

## ✨ 功能

- **拖放檔案** 或點選檔案，自動辨識格式
- **憑證內容檢視**：主體(CN)、簽發者、有效期、序號、SHA-256 指紋、SAN、金鑰類型
- **格式轉換**
  - `PFX/P12` → `PEM`（解出私鑰＋憑證鏈的合併檔）
  - `PEM`（憑證＋私鑰）→ `PFX/P12`（可選**現代 AES-256** 或**舊式相容 3DES**）
  - 憑證 `PEM` ⇄ `DER`
  - 私鑰 `PKCS#1` ⇄ `PKCS#8`、EC `SEC1` → `PKCS#8`
- **安全性**：私鑰僅存於記憶體、不寫任何暫存檔；全程無網路呼叫，可在內網／離線環境使用

技術棧全部為**純 Rust**（`eframe`/`egui` + `p12-keystore` + `x509-parser` + `rsa`/`p256`/`p384`）

---

## 🛠 建置步驟（在 Windows 64-bit 上）

### 1. 安裝工具鏈（僅第一次）
1. 安裝 **Rust**：到 <https://rustup.rs> 下載 `rustup-init.exe` 執行，一路 Enter 使用預設值。
2. 安裝 **Visual Studio C++ 生成工具**（MSVC 連結器，Rust 在 Windows 編譯原生程式必要）：
   下載 <https://visualstudio.microsoft.com/visual-cpp-build-tools/>，
   安裝時勾選「**使用 C++ 的桌面開發 (Desktop development with C++)**」。
3. 安裝完成後**重開一個新的終端機**（PowerShell 或 CMD）。

### 2. 編譯
在專案根目錄（含 `Cargo.toml` 的資料夾）執行：

```powershell
cargo build --release
```

第一次會下載並編譯相依套件，需數分鐘。完成後產物在：

```
target\release\cert-converter.exe
```

### 3.（可選）進一步縮小體積
已在 `Cargo.toml` 設定體積最佳化。若想再壓縮，可用 [UPX](https://upx.github.io/)：

```powershell
upx --best --lzma target\release\cert-converter.exe
```

---

## 📖 使用方式

1. 執行 `cert-converter.exe`。
2. 把憑證檔拖進視窗，或按「選擇檔案…」。
3. 上方會顯示**偵測到的格式**與**憑證內容**。
4. 依內容出現對應的轉換按鈕：
   - 載入 **PFX** → 輸入密碼 → 「解鎖並輸出 PEM」
   - 載入含**憑證＋私鑰**的 **PEM** → 設定密碼、選加密方式 → 「產生 PFX」
   - 載入單張憑證 → PEM/DER 互轉
   - 載入私鑰 → PKCS#1 / PKCS#8 互轉
5. 按下按鈕後會跳出「另存新檔」對話框，選位置儲存即可。

> **現代 vs 舊式相容**：預設用現代 AES-256（安全性高）。若把產生的 PFX 匯入到較舊系統
> （舊版 IIS / Java keytool / 網路設備）出現「密碼錯誤／無法匯入」，改選「舊式相容 (3DES)」重轉一次即可。

---

## 🧩 專案結構

```
cert-converter/
├─ Cargo.toml         相依套件與建置設定
└─ src/
   ├─ main.rs         GUI（eframe/egui）、拖放、字型、流程
   └─ certcore.rs     核心邏輯：格式偵測、憑證解析、各種轉換
```

---

## 🩺 疑難排解

- **`link.exe not found` / 連結失敗**：沒裝到 MSVC C++ 生成工具，回到步驟 1-2 重裝並勾選「使用 C++ 的桌面開發」。
- **中文顯示為方塊**：程式會自動載入系統的微軟正黑體（`C:\Windows\Fonts\msjh.ttc`）。
  若你的系統沒有該字型，請確認 `Fonts` 目錄至少有 `mingliu.ttc` 或 `simsun.ttc`。
- **相依套件版本**：`Cargo.toml` 使用寬鬆版本號。若 `p12-keystore` 或 `egui` 有重大 API 變更導致
  編譯錯誤，可先鎖定近期版本，例如 `p12-keystore = "=0.3.0"`、`egui = "=0.29.1"`、`eframe = "=0.29.1"` 後重試。
- **PFX 解不開**：多半是密碼錯誤，或該 PFX 使用了 MD5-based 的舊加密（本工具不支援，這在網頁憑證極罕見）。

---

## 🔒 安全備註

- 本工具**不連線、不上傳、不寫暫存檔**，私鑰只在記憶體中處理，程式關閉即釋放。
- 建議在受信任的機器上操作，並妥善保管輸出的 `.pfx` / `.key` 檔（內含私鑰）。
