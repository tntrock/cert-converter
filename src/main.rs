// 發行版隱藏主控台視窗（純 GUI 應用）
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod certcore;
#[allow(dead_code)]
mod selfsign;

use certcore::{
    build_pfx, cert_info, certs_to_pem, decrypt_key, der_to_pem, detect, export_key_pem, key_alg,
    key_formats, pem_bundle, unlock_pfx, CertInfo, KeyFormat, Loaded,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([920.0, 720.0])
            .with_min_inner_size([760.0, 560.0])
            .with_title("憑證格式轉換工具"),
        ..Default::default()
    };

    eframe::run_native(
        "憑證格式轉換工具",
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            let mut app = App::default();
            // 支援「把檔案拖到 exe 上」或「開啟檔案的程式」：第一個參數為檔案路徑
            if let Some(path) = std::env::args_os().nth(1).filter(|p| !p.is_empty()) {
                app.load_file(Path::new(&path));
            }
            Ok(Box::new(app))
        }),
    )
}

/// 載入系統中文字型（離線、免內嵌）。優先使用微軟正黑體。
fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // 依序嘗試常見的繁中/中文字型
    let candidates = [
        r"C:\Windows\Fonts\msjh.ttc",    // 微軟正黑體
        r"C:\Windows\Fonts\msjhl.ttc",   // 微軟正黑體 Light
        r"C:\Windows\Fonts\mingliu.ttc", // 細明體
        r"C:\Windows\Fonts\msyh.ttc",    // 微軟雅黑（簡中，後備）
        r"C:\Windows\Fonts\simsun.ttc",  // 宋體（後備）
    ];

    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("cjk".to_owned(), egui::FontData::from_owned(bytes));
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "cjk".to_owned());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push("cjk".to_owned());
            break;
        }
    }

    ctx.set_fonts(fonts);
}

/// 使用者在這一幀按下的操作。先收集、畫完 UI 後再執行，
/// 避免在借用 `self.loaded` 時呼叫 `&mut self` 方法（也不必每幀複製私鑰）。
/// 輸出檔案：(預設檔名, 篩選器名稱, 副檔名, 內容)
type Output = (
    String,
    &'static str,
    &'static [&'static str],
    Zeroizing<Vec<u8>>,
);

enum Action {
    PickFile,
    Clear,
    UnlockPfx,
    UnlockKey,
    SaveCertPem,
    SaveCertDer,
    SaveChain,
    SaveFullchain,
    SaveKey(KeyFormat),
    SaveBundle,
    BuildPfx,
}

#[derive(Default)]
struct App {
    file_path: Option<PathBuf>,
    loaded: Option<Loaded>,
    info: Option<CertInfo>,
    info_note: Option<String>, // 憑證資訊尚未取得時的提示（例如 PFX 未解鎖）
    key_match: Option<bool>,   // 私鑰是否與葉憑證成對（載入時計算一次）

    // 密碼欄（釋放時清零）
    open_password: Zeroizing<String>, // 用來解鎖 PFX
    key_password: Zeroizing<String>,  // 用來解開加密私鑰
    out_password: Zeroizing<String>,  // 產生 PFX 時的密碼
    out_password2: Zeroizing<String>, // 再次輸入確認
    show_password: bool,
    show_about: bool,
    exe_sha256: Option<String>, // 目前執行檔的 SHA-256（開啟「關於」時才計算）
    legacy: bool,               // PFX 輸出：是否使用舊式相容加密

    // 狀態訊息（is_error, 內容）
    status: Vec<(bool, String)>,
}

impl App {
    fn ok(&mut self, msg: impl Into<String>) {
        self.status.push((false, msg.into()));
    }
    fn err(&mut self, msg: impl Into<String>) {
        self.status.push((true, msg.into()));
    }

    fn reset(&mut self) {
        self.loaded = None;
        self.info = None;
        self.info_note = None;
        self.key_match = None;
        self.open_password.clear();
        self.key_password.clear();
        self.out_password.clear();
        self.out_password2.clear();
        self.legacy = false;
    }

    fn load_file(&mut self, path: &Path) {
        self.reset();
        self.file_path = Some(path.to_path_buf());

        // 憑證檔通常只有數 KB，過大的檔案多半是拖錯檔，避免整個讀進記憶體
        const MAX_SIZE: u64 = 10 * 1024 * 1024;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > MAX_SIZE {
                self.err("檔案超過 10 MB，不像是憑證或金鑰檔");
                return;
            }
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => Zeroizing::new(b),
            Err(e) => {
                self.err(format!("讀取檔案失敗：{e}"));
                return;
            }
        };

        match detect(&bytes) {
            Ok(loaded) => {
                self.ok(format!("已載入：{}", loaded.type_label()));
                self.set_loaded(loaded);
            }
            Err(e) => self.err(format!("{e}")),
        }
    }

    /// 設定目前內容，並更新憑證資訊與附註。
    fn set_loaded(&mut self, loaded: Loaded) {
        self.info = None;
        self.info_note = None;
        self.key_match = None;
        match &loaded {
            Loaded::LockedPfx { .. } => {
                self.info_note = Some("輸入密碼解鎖後即可顯示憑證內容。".to_string());
            }
            Loaded::Items(items) => {
                if let Some(leaf) = items.certs.first() {
                    match cert_info(leaf) {
                        Ok(info) => self.info = Some(info),
                        Err(e) => self.info_note = Some(format!("無法解析憑證內容：{e}")),
                    }
                }
                self.key_match = items.key_matches_leaf();
                for note in items.notes.clone() {
                    self.ok(note);
                }
            }
        }
        self.loaded = Some(loaded);
    }

    /// 開啟儲存對話框並寫入位元組。使用者取消時回傳 false。
    fn save_bytes(&mut self, default_name: &str, filter: &str, exts: &[&str], data: &[u8]) -> bool {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(default_name)
            .add_filter(filter, exts)
            .save_file()
        else {
            return false;
        };
        match std::fs::write(&path, data) {
            Ok(_) => {
                self.ok(format!("已儲存：{}", path.display()));
                true
            }
            Err(e) => {
                self.err(format!("寫入失敗：{e}"));
                false
            }
        }
    }

    fn base_name(&self) -> String {
        self.file_path
            .as_ref()
            .and_then(|f| f.file_stem())
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "output".to_string())
    }

    fn run(&mut self, action: Action) {
        match action {
            Action::PickFile => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter(
                        "憑證/金鑰",
                        &[
                            "pfx", "p12", "pem", "crt", "cer", "der", "key", "p7b", "p7c",
                        ],
                    )
                    .add_filter("所有檔案", &["*"])
                    .pick_file()
                {
                    self.load_file(&path);
                }
                return;
            }
            Action::Clear => {
                self.file_path = None;
                self.reset();
                self.status.clear();
                return;
            }
            Action::UnlockPfx => {
                let Some(Loaded::LockedPfx { data }) = &self.loaded else {
                    return;
                };
                match unlock_pfx(data, &self.open_password) {
                    Ok(items) => {
                        self.open_password.clear();
                        self.ok(format!("PFX 已解鎖：{}", items.type_label()));
                        self.set_loaded(Loaded::Items(items));
                    }
                    Err(e) => self.err(format!("{e}")),
                }
                return;
            }
            Action::UnlockKey => {
                let Some(Loaded::Items(items)) = &self.loaded else {
                    return;
                };
                let Some(enc) = &items.encrypted_key else {
                    return;
                };
                match decrypt_key(enc, &self.key_password) {
                    Ok(key) => {
                        let mut items = items.clone();
                        items.key = Some(key);
                        items.encrypted_key = None;
                        items.notes.clear();
                        items.normalize();
                        self.key_password.clear();
                        self.ok("私鑰已解密");
                        self.set_loaded(Loaded::Items(items));
                    }
                    Err(e) => self.err(format!("{e}")),
                }
                return;
            }
            _ => {}
        }

        // 以下為輸出動作，需要已解開的內容
        let Some(Loaded::Items(items)) = &self.loaded else {
            return;
        };
        let base = self.base_name();
        let result: anyhow::Result<Output> = (|| {
            let key = || {
                items
                    .key
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("沒有可用的私鑰"))
            };
            let leaf = || {
                items
                    .certs
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("沒有可用的憑證"))
            };
            let bytes = |s: String| Zeroizing::new(s.into_bytes());
            Ok(match action {
                Action::SaveCertPem => (
                    format!("{base}.crt"),
                    "PEM 憑證",
                    &["crt", "pem", "cer"][..],
                    bytes(der_to_pem("CERTIFICATE", leaf()?)),
                ),
                Action::SaveCertDer => (
                    format!("{base}.der"),
                    "DER 憑證",
                    &["der", "cer"][..],
                    Zeroizing::new(leaf()?.clone()),
                ),
                Action::SaveChain => (
                    format!("{base}-chain.crt"),
                    "PEM 憑證鏈",
                    &["crt", "pem"][..],
                    bytes(certs_to_pem(&items.certs[1..])),
                ),
                Action::SaveFullchain => (
                    format!("{base}-fullchain.crt"),
                    "PEM 憑證鏈",
                    &["crt", "pem"][..],
                    bytes(certs_to_pem(&items.certs)),
                ),
                Action::SaveKey(format) => {
                    let pem = export_key_pem(key()?, format)?;
                    (
                        format!("{base}-{}.key", format.file_suffix()),
                        "私鑰 (PEM)",
                        &["key", "pem"][..],
                        Zeroizing::new(pem.as_bytes().to_vec()),
                    )
                }
                Action::SaveBundle => {
                    let pem = pem_bundle(&items.certs, key()?)?;
                    (
                        format!("{base}-bundle.pem"),
                        "PEM",
                        &["pem"][..],
                        Zeroizing::new(pem.as_bytes().to_vec()),
                    )
                }
                Action::BuildPfx => {
                    if self.out_password.is_empty() {
                        anyhow::bail!("請先設定 PFX 密碼");
                    }
                    if *self.out_password != *self.out_password2 {
                        anyhow::bail!("兩次輸入的 PFX 密碼不一致");
                    }
                    let pfx = build_pfx(&items.certs, key()?, &self.out_password, self.legacy)?;
                    (
                        format!("{base}.pfx"),
                        "PFX",
                        &["pfx", "p12"][..],
                        Zeroizing::new(pfx),
                    )
                }
                _ => unreachable!(),
            })
        })();

        match result {
            Ok((name, filter, exts, data)) => {
                self.save_bytes(&name, filter, exts, &data);
            }
            Err(e) => self.err(format!("{e}")),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 處理拖放檔案
        let dropped: Option<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .rev()
                .find_map(|f| f.path.clone())
        });
        if let Some(path) = dropped {
            self.load_file(&path);
        }

        let mut action = None;
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.header(ui);
                ui.separator();
                action = self.drop_zone(ui);
                ui.add_space(8.0);
                self.info_panel(ui);
                action = self.actions_panel(ui).or(action.take());
                ui.add_space(8.0);
                self.status_panel(ui);
            });
        });
        self.about_window(ctx);
        if let Some(action) = action {
            self.run(action);
        }
    }
}

// ---- 關於 ----
const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHOR: &str = "Allen Yen";
const AUTHOR_URL: &str = "https://allenyen.net";
const REPO_URL: &str = env!("CARGO_PKG_REPOSITORY");
const RELEASES_URL: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/releases");
const ISSUES_URL: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/issues");

/// 計算目前執行檔的 SHA-256，供使用者與 Release 頁面的 SHA256SUMS.txt 比對。
fn exe_sha256() -> String {
    std::env::current_exe()
        .and_then(std::fs::read)
        .map(|bytes| {
            Sha256::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        })
        .unwrap_or_else(|e| format!("無法計算：{e}"))
}

const GRAY: egui::Color32 = egui::Color32::from_rgb(140, 140, 140);
const GREEN: egui::Color32 = egui::Color32::from_rgb(40, 130, 70);
const ORANGE: egui::Color32 = egui::Color32::from_rgb(190, 110, 30);
const RED: egui::Color32 = egui::Color32::from_rgb(190, 60, 60);

// ---- UI 區塊 ----
impl App {
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("🔐 憑證格式轉換工具");
            ui.label(egui::RichText::new(format!("v{VERSION}")).weak());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("ℹ 關於").clicked() {
                    self.show_about = true;
                }
            });
        });
        ui.label(
            egui::RichText::new("純離線運作 · 私鑰僅存於記憶體、不寫暫存檔 · 免安裝單一執行檔")
                .small()
                .color(egui::Color32::from_rgb(120, 120, 120)),
        );
    }

    fn drop_zone(&mut self, ui: &mut egui::Ui) -> Option<Action> {
        let mut action = None;
        let (rect, _resp) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 92.0), egui::Sense::hover());
        let painter = ui.painter();
        painter.rect_stroke(
            rect,
            8.0,
            egui::Stroke::new(1.5_f32, egui::Color32::from_rgb(150, 160, 200)),
        );
        painter.text(
            rect.center() + egui::vec2(0.0, -10.0),
            egui::Align2::CENTER_CENTER,
            "把憑證檔案拖曳到這裡",
            egui::FontId::proportional(18.0),
            egui::Color32::from_rgb(90, 100, 140),
        );
        painter.text(
            rect.center() + egui::vec2(0.0, 16.0),
            egui::Align2::CENTER_CENTER,
            "支援 .pfx .p12 .pem .crt .cer .der .key .p7b",
            egui::FontId::proportional(12.0),
            GRAY,
        );

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("📂 選擇檔案…").clicked() {
                action = Some(Action::PickFile);
            }
            if self.loaded.is_some() && ui.button("🗑 清除").clicked() {
                action = Some(Action::Clear);
            }
            if let Some(path) = &self.file_path {
                ui.label(egui::RichText::new(format!("目前檔案：{}", path.display())).weak());
            }
        });

        if let Some(loaded) = &self.loaded {
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!("偵測結果：{}", loaded.type_label()))
                    .strong()
                    .color(egui::Color32::from_rgb(40, 110, 60)),
            );
        }
        action
    }

    fn info_panel(&mut self, ui: &mut egui::Ui) {
        if let Some(note) = &self.info_note {
            ui.label(egui::RichText::new(note).italics());
        }
        let Some(info) = &self.info else {
            return;
        };
        let key_match = self.key_match;

        egui::CollapsingHeader::new("📄 憑證內容")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("cert_info_grid")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .striped(true)
                    .show(ui, |ui| {
                        if let Some(cn) = &info.common_name {
                            row(ui, "一般名稱 (CN)", cn);
                        }
                        row(ui, "主體 (Subject)", &info.subject);
                        row(ui, "簽發者 (Issuer)", &info.issuer);
                        row(ui, "生效時間", &info.not_before);
                        ui.label(egui::RichText::new("到期時間").strong());
                        let (text, color) = if info.days_left < 0 {
                            (format!("{}（已過期）", info.not_after), RED)
                        } else if info.days_left <= 30 {
                            (
                                format!("{}（剩 {} 天，即將到期）", info.not_after, info.days_left),
                                ORANGE,
                            )
                        } else {
                            (
                                format!("{}（剩 {} 天）", info.not_after, info.days_left),
                                GREEN,
                            )
                        };
                        ui.colored_label(color, text);
                        ui.end_row();
                        row(ui, "序號", &info.serial);
                        row(ui, "金鑰類型", &info.key_type);
                        row(ui, "SHA-256 指紋", &info.sha256);
                        let sans = if info.sans.is_empty() {
                            "（無）".to_string()
                        } else {
                            info.sans.join("\n")
                        };
                        row(ui, "主體別名 (SAN)", &sans);
                        if let Some(m) = key_match {
                            ui.label(egui::RichText::new("私鑰配對").strong());
                            if m {
                                ui.colored_label(GREEN, "✔ 私鑰與此憑證成對");
                            } else {
                                ui.colored_label(RED, "✖ 私鑰與檔案中的憑證都不成對");
                            }
                            ui.end_row();
                        }
                    });
            });
    }

    fn password_field(ui: &mut egui::Ui, label: &str, value: &mut String, show: bool) -> bool {
        ui.horizontal(|ui| {
            ui.label(label);
            let resp = ui.add(
                egui::TextEdit::singleline(value)
                    .password(!show)
                    .desired_width(240.0),
            );
            resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
        })
        .inner
    }

    fn actions_panel(&mut self, ui: &mut egui::Ui) -> Option<Action> {
        let loaded = self.loaded.as_ref()?;
        let mut action = None;

        ui.add_space(6.0);
        ui.separator();
        ui.heading("轉換");

        let items = match loaded {
            Loaded::LockedPfx { .. } => {
                let enter = Self::password_field(
                    ui,
                    "PFX 密碼：",
                    &mut self.open_password,
                    self.show_password,
                );
                ui.checkbox(&mut self.show_password, "顯示密碼");
                if ui.button("🔓 解鎖 PFX").clicked() || enter {
                    action = Some(Action::UnlockPfx);
                }
                return action;
            }
            Loaded::Items(items) => items,
        };

        // 加密私鑰：先解密
        if items.encrypted_key.is_some() && items.key.is_none() {
            ui.group(|ui| {
                ui.label(egui::RichText::new("🔒 偵測到加密的私鑰").strong());
                let enter = Self::password_field(
                    ui,
                    "私鑰密碼：",
                    &mut self.key_password,
                    self.show_password,
                );
                ui.checkbox(&mut self.show_password, "顯示密碼");
                if ui.button("🔓 解密私鑰").clicked() || enter {
                    action = Some(Action::UnlockKey);
                }
            });
            ui.add_space(6.0);
        }

        // 憑證
        if !items.certs.is_empty() {
            ui.label(egui::RichText::new("憑證").strong());
            ui.horizontal_wrapped(|ui| {
                if ui.button("憑證 → PEM（.crt）").clicked() {
                    action = Some(Action::SaveCertPem);
                }
                if ui.button("憑證 → DER（.der）").clicked() {
                    action = Some(Action::SaveCertDer);
                }
                if items.certs.len() > 1 {
                    if ui
                        .button("中繼憑證鏈（chain.crt）")
                        .on_hover_text(
                            "不含葉憑證的中繼/根憑證，Apache 的 SSLCertificateChainFile 用",
                        )
                        .clicked()
                    {
                        action = Some(Action::SaveChain);
                    }
                    if ui
                        .button("完整憑證鏈（fullchain.crt）")
                        .on_hover_text("葉憑證＋中繼憑證，Nginx 的 ssl_certificate 用")
                        .clicked()
                    {
                        action = Some(Action::SaveFullchain);
                    }
                }
            });
            if items.certs.len() > 1 {
                ui.label(
                    egui::RichText::new("僅轉換葉憑證（第一張）；憑證鏈已依簽發順序自動排列。")
                        .small()
                        .color(GRAY),
                );
            }
        }

        // 私鑰
        if let Some(key) = &items.key {
            ui.add_space(4.0);
            ui.label(egui::RichText::new(format!("私鑰（{}）", key_alg(key).label())).strong());
            ui.horizontal_wrapped(|ui| {
                for format in key_formats(key) {
                    if ui
                        .button(format!("私鑰 → {}（.key）", format.label()))
                        .clicked()
                    {
                        action = Some(Action::SaveKey(format));
                    }
                }
                if !items.certs.is_empty() && ui.button("私鑰＋憑證鏈合併 PEM").clicked() {
                    action = Some(Action::SaveBundle);
                }
            });
            ui.label(
                egui::RichText::new("⚠ 輸出的私鑰檔「未加密」，請妥善保管。")
                    .small()
                    .color(ORANGE),
            );
        }

        // 憑證 + 私鑰 -> PFX
        if !items.certs.is_empty() && items.key.is_some() {
            ui.add_space(6.0);
            ui.group(|ui| {
                ui.label(egui::RichText::new("打包成 PFX / PKCS#12").strong());
                Self::password_field(ui, "設定密碼：", &mut self.out_password, self.show_password);
                Self::password_field(ui, "確認密碼：", &mut self.out_password2, self.show_password);
                ui.checkbox(&mut self.show_password, "顯示密碼");
                ui.horizontal(|ui| {
                    ui.label("加密方式：");
                    ui.radio_value(&mut self.legacy, false, "現代 (AES-256)");
                    ui.radio_value(&mut self.legacy, true, "舊式相容 (3DES)");
                });
                ui.label(
                    egui::RichText::new(
                        "提示：匯入到較舊的系統（舊版 IIS/Java/網路設備）若失敗，改用「舊式相容」再試一次。",
                    )
                    .small()
                    .color(GRAY),
                );

                if ui.button("📦 產生 PFX（.pfx）").clicked() {
                    action = Some(Action::BuildPfx);
                }
            });
        }

        if items.certs.is_empty() && items.key.is_none() && items.encrypted_key.is_none() {
            ui.label("沒有可轉換的內容。");
        }
        action
    }

    fn about_window(&mut self, ctx: &egui::Context) {
        if !self.show_about {
            return;
        }
        if self.exe_sha256.is_none() {
            self.exe_sha256 = Some(exe_sha256());
        }
        let mut open = true;
        egui::Window::new("關於")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(520.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.heading("🔐 憑證格式轉換工具（cert-converter）");
                ui.label(format!("版本 v{VERSION}"));
                ui.label("純 Rust、完全離線、免安裝的 Windows 憑證格式轉換工具。");
                ui.add_space(8.0);

                egui::Grid::new("about_grid")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("作者").strong());
                        ui.hyperlink_to(AUTHOR, AUTHOR_URL);
                        ui.end_row();
                        ui.label(egui::RichText::new("專案首頁").strong());
                        ui.hyperlink_to(REPO_URL, REPO_URL);
                        ui.end_row();
                        ui.label(egui::RichText::new("官方下載").strong());
                        ui.hyperlink_to(RELEASES_URL, RELEASES_URL);
                        ui.end_row();
                        ui.label(egui::RichText::new("問題回報").strong());
                        ui.hyperlink_to(ISSUES_URL, ISSUES_URL);
                        ui.end_row();
                        ui.label(egui::RichText::new("授權").strong());
                        ui.label("MIT License");
                        ui.end_row();
                    });

                ui.add_space(10.0);
                ui.group(|ui| {
                    ui.label(
                        egui::RichText::new("⚠ 請只從官方 GitHub Releases 下載")
                            .strong()
                            .color(ORANGE),
                    );
                    ui.label(
                        "本工具會處理私鑰，來路不明的版本可能被植入惡意程式。\n\
                         官方執行檔只發佈在上方的「官方下載」頁面，檔名為\n\
                         cert-converter-vX.Y.Z-windows-x64.exe，並附上 SHA256SUMS.txt。",
                    );
                    ui.add_space(4.0);
                    ui.label("目前這個執行檔的 SHA-256（應與 SHA256SUMS.txt 內的值相同）：");
                    let hash = self.exe_sha256.as_deref().unwrap_or_default();
                    ui.horizontal(|ui| {
                        ui.add(egui::Label::new(egui::RichText::new(hash).monospace()).wrap());
                        if ui.small_button("📋 複製").clicked() {
                            ui.ctx().copy_text(hash.to_string());
                        }
                    });
                });

                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new("點選連結會以預設瀏覽器開啟；除此之外本工具不會連線。")
                        .small()
                        .color(GRAY),
                );
            });
        self.show_about = open;
    }

    fn status_panel(&mut self, ui: &mut egui::Ui) {
        if self.status.is_empty() {
            return;
        }
        ui.separator();
        ui.horizontal(|ui| {
            ui.heading("訊息");
            if ui.button("清空").clicked() {
                self.status.clear();
            }
        });
        // 由新到舊顯示
        for (is_err, msg) in self.status.iter().rev() {
            let (color, prefix) = if *is_err {
                (RED, "✖ ")
            } else {
                (GREEN, "✔ ")
            };
            ui.colored_label(color, format!("{prefix}{msg}"));
        }
    }
}

fn row(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.label(egui::RichText::new(key).strong());
    ui.add(egui::Label::new(value).wrap());
    ui.end_row();
}
