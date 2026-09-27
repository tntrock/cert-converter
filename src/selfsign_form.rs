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
                                        .hint_text(
                                            "一行一個，例如：\nwww.example.local\n192.168.1.10",
                                        )
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
