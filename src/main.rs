// 發行版隱藏主控台視窗（純 GUI 應用）
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod certcore;

use certcore::{
    build_pfx, cert_der_to_pem, cert_info, convert_key_to_other_pem, detect,
    key_convert_button_label, pfx_to_pem_bundle, CertInfo, KeyKind, Loaded,
};
use std::path::{Path, PathBuf};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([920.0, 700.0])
            .with_min_inner_size([760.0, 560.0])
            .with_title("憑證格式轉換工具"),
        ..Default::default()
    };

    eframe::run_native(
        "憑證格式轉換工具",
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(App::default()))
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

#[derive(Default)]
struct App {
    file_name: Option<String>,
    loaded: Option<Loaded>,
    info: Option<CertInfo>,
    info_note: Option<String>, // 憑證資訊尚未取得時的提示（例如 PFX 未解鎖）

    // 密碼欄
    open_password: String, // 用來解鎖 PFX
    out_password: String,  // 產生 PFX 時的密碼
    legacy: bool,          // PFX 輸出：是否使用舊式相容加密

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
        self.open_password.clear();
        self.out_password.clear();
        self.legacy = false;
    }

    fn load_file(&mut self, path: &Path) {
        self.reset();
        self.file_name = Some(path.to_string_lossy().to_string());

        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                self.err(format!("讀取檔案失敗：{e}"));
                return;
            }
        };

        match detect(&bytes) {
            Ok(loaded) => {
                // 若能立刻取得葉憑證，就順便解析資訊
                match &loaded {
                    Loaded::DerCert { der } => self.compute_info(&der.clone()),
                    Loaded::Pem { certs, .. } => {
                        if let Some(first) = certs.first() {
                            self.compute_info(&first.clone());
                        }
                    }
                    Loaded::Pfx { .. } => {
                        self.info_note = Some("輸入密碼解鎖後即可顯示憑證內容。".to_string());
                    }
                }
                self.ok(format!("已載入：{}", loaded.type_label()));
                self.loaded = Some(loaded);
            }
            Err(e) => self.err(format!("{e}")),
        }
    }

    fn compute_info(&mut self, der: &[u8]) {
        match cert_info(der) {
            Ok(info) => {
                self.info = Some(info);
                self.info_note = None;
            }
            Err(e) => {
                self.info = None;
                self.info_note = Some(format!("無法解析憑證內容：{e}"));
            }
        }
    }

    /// 開啟儲存對話框並寫入位元組。
    fn save_bytes(&mut self, default_name: &str, filter: &str, exts: &[&str], data: &[u8]) {
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name(default_name)
            .add_filter(filter, exts)
            .save_file()
        {
            match std::fs::write(&path, data) {
                Ok(_) => self.ok(format!("已儲存：{}", path.display())),
                Err(e) => self.err(format!("寫入失敗：{e}")),
            }
        }
    }

    fn base_name(&self) -> String {
        self.file_name
            .as_ref()
            .and_then(|f| Path::new(f).file_stem())
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "output".to_string())
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

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.header(ui);
                ui.separator();
                self.drop_zone(ui);
                ui.add_space(8.0);
                self.info_panel(ui);
                self.actions_panel(ui);
                ui.add_space(8.0);
                self.status_panel(ui);
            });
        });
    }
}

// ---- UI 區塊 ----
impl App {
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("🔐 憑證格式轉換工具");
        });
        ui.label(
            egui::RichText::new("純離線運作 · 私鑰僅存於記憶體、不寫暫存檔 · 免安裝單一執行檔")
                .small()
                .color(egui::Color32::from_rgb(120, 120, 120)),
        );
    }

    fn drop_zone(&mut self, ui: &mut egui::Ui) {
        let (rect, _resp) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 92.0), egui::Sense::hover());
        let painter = ui.painter();
        painter.rect_stroke(
            rect,
            8.0,
            egui::Stroke::new(1.5, egui::Color32::from_rgb(150, 160, 200)),
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
            "支援 .pfx .p12 .pem .crt .cer .der .key",
            egui::FontId::proportional(12.0),
            egui::Color32::from_rgb(140, 140, 140),
        );

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("📂 選擇檔案…").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter(
                        "憑證/金鑰",
                        &["pfx", "p12", "pem", "crt", "cer", "der", "key"],
                    )
                    .add_filter("所有檔案", &["*"])
                    .pick_file()
                {
                    self.load_file(&path);
                }
            }
            if self.loaded.is_some() && ui.button("🗑 清除").clicked() {
                self.file_name = None;
                self.reset();
                self.status.clear();
            }
            if let Some(name) = &self.file_name {
                ui.label(
                    egui::RichText::new(format!("目前檔案：{name}"))
                        .color(egui::Color32::from_rgb(80, 80, 80)),
                );
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
    }

    fn info_panel(&mut self, ui: &mut egui::Ui) {
        if let Some(note) = &self.info_note {
            ui.label(egui::RichText::new(note).italics());
        }
        let Some(info) = &self.info else {
            return;
        };

        egui::CollapsingHeader::new("📄 憑證內容")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("cert_info_grid")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .striped(true)
                    .show(ui, |ui| {
                        row(ui, "主體 (Subject)", &info.subject);
                        row(ui, "簽發者 (Issuer)", &info.issuer);
                        row(ui, "生效時間", &info.not_before);
                        row(ui, "到期時間", &info.not_after);
                        row(ui, "序號", &info.serial);
                        row(ui, "金鑰類型", &info.key_type);
                        row(ui, "SHA-256 指紋", &info.sha256);
                        let sans = if info.sans.is_empty() {
                            "（無）".to_string()
                        } else {
                            info.sans.join("\n")
                        };
                        row(ui, "主體別名 (SAN)", &sans);
                    });
            });
    }

    fn actions_panel(&mut self, ui: &mut egui::Ui) {
        // 先把整個輸入內容 clone 成本地變數，避免在呼叫 &mut self 方法時仍借用 self.loaded
        let Some(loaded) = self.loaded.clone() else {
            return;
        };

        ui.add_space(6.0);
        ui.separator();
        ui.heading("轉換");

        match &loaded {
            Loaded::DerCert { der } => {
                let der = der.clone();
                if ui.button("DER → PEM 憑證（.pem）").clicked() {
                    let pem = cert_der_to_pem(&der);
                    let name = format!("{}.pem", self.base_name());
                    self.save_bytes(&name, "PEM 憑證", &["pem", "crt"], pem.as_bytes());
                }
            }

            Loaded::Pfx { data } => {
                let data = data.clone();
                ui.horizontal(|ui| {
                    ui.label("PFX 密碼：");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.open_password)
                            .password(true)
                            .desired_width(240.0),
                    );
                });
                if ui.button("🔓 解鎖並輸出 PEM（私鑰＋憑證鏈）").clicked() {
                    match pfx_to_pem_bundle(&data, &self.open_password) {
                        Ok((pem, leaf)) => {
                            if let Some(leaf) = leaf {
                                self.compute_info(&leaf);
                            }
                            let name = format!("{}.pem", self.base_name());
                            self.save_bytes(&name, "PEM", &["pem"], pem.as_bytes());
                        }
                        Err(e) => self.err(format!("{e}")),
                    }
                }
            }

            Loaded::Pem {
                certs,
                key,
                encrypted_key,
            } => {
                let certs = certs.clone();
                let key = key.clone();
                let encrypted_key = *encrypted_key;

                // 單張憑證 -> DER
                if certs.len() == 1 {
                    let der = certs[0].clone();
                    if ui.button("PEM → DER 憑證（.der）").clicked() {
                        let name = format!("{}.der", self.base_name());
                        self.save_bytes(&name, "DER 憑證", &["der", "cer"], &der);
                    }
                }

                // 私鑰格式互轉
                if let Some(k) = &key {
                    let kind = k.kind;
                    let k = k.clone();
                    if ui.button(key_convert_button_label(kind)).clicked() {
                        match convert_key_to_other_pem(&k) {
                            Ok((label, pem)) => {
                                let name = format!(
                                    "{}-{}.key",
                                    self.base_name(),
                                    match kind {
                                        KeyKind::Pkcs8 => "pkcs1",
                                        _ => "pkcs8",
                                    }
                                );
                                self.ok(format!("已轉為 {label}"));
                                self.save_bytes(
                                    &name,
                                    "私鑰 (PEM)",
                                    &["key", "pem"],
                                    pem.as_bytes(),
                                );
                            }
                            Err(e) => self.err(format!("{e}")),
                        }
                    }
                }

                // 憑證 + 私鑰 -> PFX
                if !certs.is_empty() && key.is_some() {
                    ui.add_space(6.0);
                    ui.group(|ui| {
                        ui.label(egui::RichText::new("打包成 PFX / PKCS#12").strong());
                        ui.horizontal(|ui| {
                            ui.label("設定密碼：");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.out_password)
                                    .password(true)
                                    .desired_width(240.0),
                            );
                        });
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
                            .color(egui::Color32::from_rgb(140, 140, 140)),
                        );

                        if ui.button("📦 產生 PFX（.pfx）").clicked() {
                            if self.out_password.is_empty() {
                                self.err("請先設定 PFX 密碼");
                            } else {
                                let k = key.as_ref().unwrap().clone();
                                match build_pfx(&certs, &k, &self.out_password, self.legacy) {
                                    Ok(bytes) => {
                                        let name = format!("{}.pfx", self.base_name());
                                        self.save_bytes(&name, "PFX", &["pfx", "p12"], &bytes);
                                    }
                                    Err(e) => self.err(format!("{e}")),
                                }
                            }
                        }
                    });
                }

                if encrypted_key {
                    ui.label(
                        egui::RichText::new(
                            "⚠ 偵測到「加密的」PEM 私鑰（ENCRYPTED PRIVATE KEY）。請先用 openssl 解密後再載入。",
                        )
                        .color(egui::Color32::from_rgb(170, 90, 40)),
                    );
                }

                if certs.is_empty() && key.is_none() {
                    ui.label("這個 PEM 沒有可轉換的內容。");
                }
            }
        }
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
            let color = if *is_err {
                egui::Color32::from_rgb(190, 60, 60)
            } else {
                egui::Color32::from_rgb(40, 130, 70)
            };
            let prefix = if *is_err { "✖ " } else { "✔ " };
            ui.colored_label(color, format!("{prefix}{msg}"));
        }
    }
}

fn row(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.label(egui::RichText::new(key).strong());
    ui.add(egui::Label::new(value).wrap());
    ui.end_row();
}
