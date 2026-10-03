use std::path::PathBuf;

use crossterm::event::{KeyEvent, MouseEvent};
use ratatui::{Frame, layout::Rect};

use crate::{screen::safe_text, shortcuts::Bindings, theme::Palette, vault::Secret};
use super::{form::{Action, Field, Form, FormHitRegion}, security::{recovery_file_form, recovery_file_request}};

pub enum SetupEntry { Created, Settings }

pub enum SetupAction {
    None,
    Back,
    Close,
    SaveRecoveryFile { current: Secret, destination: PathBuf },
}

enum Page { Mode, Protection, RecoveryFile, Ready }
enum RecoveryReceipt { NotExported, Saved, Warning(String) }

pub struct SetupWizard {
    entry: SetupEntry,
    local_only: bool,
    page: Page,
    form: Form,
    hits: Vec<FormHitRegion>,
    receipt: RecoveryReceipt,
}

/// The first setup step only explains storage: every vault starts on this device.
pub(crate) fn storage_mode_form(title: &str) -> Form {
    let mut form = Form::new(title, Vec::new());
    form.description = "Local storage: Vyx keeps your encrypted vault on this device. To share it with other devices later, add a self-hosted synchronization server in Settings / Vault synchronization.".into();
    form.submit = "Continue".into();
    form.cancel = "Back".into();
    form
}

impl SetupWizard {
    pub fn new(entry: SetupEntry, local_only: bool) -> Self {
        let page = if matches!(entry, SetupEntry::Created) { Page::Protection } else { Page::Mode };
        let mut wizard = Self {
            entry, local_only, page: Page::Mode, form: Form::new("", vec![]),
            hits: Vec::new(), receipt: RecoveryReceipt::NotExported,
        };
        wizard.show(page);
        wizard
    }

    fn title(&self, page: &Page) -> String {
        let (step, total) = match (&self.entry, self.local_only, page) {
            (SetupEntry::Created, _, Page::Mode) => (1, 4),
            (SetupEntry::Created, _, Page::Protection | Page::RecoveryFile) => (3, 4),
            (SetupEntry::Created, _, Page::Ready) => (4, 4),
            (_, true, Page::Mode) => (1, 3),
            (_, true, Page::Protection | Page::RecoveryFile) => (2, 3),
            (_, true, Page::Ready) => (3, 3),
            (_, false, Page::Ready) => (2, 2),
            (_, false, _) => (1, 2),
        };
        let name = match page {
            Page::Mode => "Storage",
            Page::Protection => "Recovery options",
            Page::RecoveryFile => "Save recovery file",
            Page::Ready => "Ready",
        };
        // Post-create setup stands alone; inside Settings it is one more settings page.
        let root = match self.entry { SetupEntry::Created => "Setup", SetupEntry::Settings => "Settings / Setup wizard" };
        format!("{root} / {step} of {total}: {name}")
    }

    fn show(&mut self, page: Page) {
        // Every page takes this title below, including the shared recovery file form.
        let title = self.title(&page);
        let mut form = match page {
            Page::Mode if self.local_only => {
                let mut form = storage_mode_form("");
                form.description.push_str(" Your vault already exists. This guide will not recreate or reset it.");
                form
            }
            Page::Mode => {
                let mut form = Form::new("", vec![]);
                form.description = "This vault is stored on this device and synchronized through your configured server. This guide will not change synchronization.".into();
                form
            }
            Page::Protection => {
                let mut form = Form::new("", vec![Field::select("Recovery file", vec![
                    "Save a recovery file (recommended)".into(), "Skip for now".into(),
                ], 0)]);
                form.description = "Without a matching recovery file, a forgotten vault passphrase cannot be reset. The file is not a vault backup; keep it separate. You can export later in Settings / Security / Save recovery file.".into();
                form
            }
            Page::RecoveryFile => recovery_file_form(),
            Page::Ready => {
                let mut form = Form::new("", vec![]);
                form.description = if !self.local_only {
                    "Your sync settings are unchanged. Local recovery export is unavailable.".into()
                } else {
                    match &self.receipt {
                        RecoveryReceipt::NotExported => "Recovery export was skipped in this run. A forgotten passphrase cannot be reset without an existing matching recovery file.".into(),
                        RecoveryReceipt::Saved => "Recovery file saved and verified. Keep it separate from the vault.".into(),
                        RecoveryReceipt::Warning(warning) => format!("Warning: {warning}\nThe recovery file was installed. Keep it separate from the vault."),
                    }
                };
                form.description.push_str("\n\nAdd connections from Servers.\nOpen Settings or Shortcuts from the command bar.\nRerun this guide in Settings / Setup wizard.");
                form
            }
        };
        form.title = title;
        if !matches!(page, Page::RecoveryFile) {
            form.submit = if matches!(page, Page::Ready) { "Finish" } else { "Continue" }.into();
        }
        form.cancel = if matches!(page, Page::Protection) && matches!(self.entry, SetupEntry::Created) {
            "Finish later"
        } else { "Back" }.into();
        self.form = form;
        self.page = page;
        self.hits.clear();
    }

    fn action(&mut self, action: Action) -> SetupAction {
        match action {
            Action::Cancel => match self.page {
                Page::Mode => return SetupAction::Back,
                Page::Protection if matches!(self.entry, SetupEntry::Created) => return SetupAction::Close,
                Page::Protection => self.show(Page::Mode),
                Page::RecoveryFile => self.show(Page::Protection),
                Page::Ready => self.show(if self.local_only { Page::Protection } else { Page::Mode }),
            },
            Action::Submit => match self.page {
                Page::Mode if !self.local_only => self.show(Page::Ready),
                Page::Mode => self.show(Page::Protection),
                Page::Protection => self.show(if self.form.fields[0].choice == 0 { Page::RecoveryFile } else { Page::Ready }),
                Page::RecoveryFile => if let Some((current, destination)) = recovery_file_request(&mut self.form) {
                    return SetupAction::SaveRecoveryFile { current, destination };
                },
                Page::Ready => return SetupAction::Close,
            },
            Action::Continue => {}
        }
        SetupAction::None
    }

    pub fn key(&mut self, key: KeyEvent, bindings: &Bindings) -> SetupAction {
        let action = self.form.key(key, bindings);
        self.action(action)
    }

    pub fn mouse(&mut self, mouse: MouseEvent) -> SetupAction {
        let action = self.form.mouse(mouse, &self.hits);
        self.action(action)
    }

    pub fn paste(&mut self, text: &str) { self.form.paste(text); }

    /// Inside Settings, `active` is false while section navigation owns the keyboard.
    pub fn draw(&mut self, frame: &mut Frame, area: Rect, bindings: &Bindings, palette: &Palette, active: bool) {
        self.hits.clear();
        match self.entry {
            SetupEntry::Settings => self.form.draw_settings(frame, area, bindings, &mut self.hits, palette, active),
            SetupEntry::Created if area.height < self.form.preferred_dialog_height(area.width).saturating_add(2) => {
                self.form.draw_panel(frame, area, bindings, &mut self.hits, palette);
            }
            SetupEntry::Created => self.form.draw(frame, area, bindings, &mut self.hits, palette),
        }
    }

    pub fn saved(&mut self, warning: Option<String>) {
        self.receipt = warning.map_or(RecoveryReceipt::Saved, |warning| RecoveryReceipt::Warning(safe_text(&warning)));
        self.show(Page::Ready);
    }

    pub fn set_error(&mut self, error: String) { self.form.error = safe_text(&error); }
}
