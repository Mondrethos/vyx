const ESC: u8 = 0x1b;
const ESC_BYTE: &[u8] = &[ESC];
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum FilterState {
    #[default]
    Ground,
    Escape,
    Osc,
    OscEscape,
}

/// Incrementally removes OSC strings before either terminal parser sees them.
///
/// OSC payload is never retained. The only cross-call byte state represented
/// here is a pending ESC, encoded by `Escape` or `OscEscape`.
pub(super) struct OscFilter {
    state: FilterState,
}

impl OscFilter {
    pub(super) fn new() -> Self {
        Self {
            state: FilterState::Ground,
        }
    }

    pub(super) fn process(&mut self, bytes: &[u8], mut output: impl FnMut(&[u8])) {
        let mut offset = 0;
        while offset < bytes.len() {
            match self.state {
                FilterState::Ground => {
                    let run = bytes[offset..]
                        .iter()
                        .position(|&byte| byte == ESC)
                        .unwrap_or(bytes.len() - offset);
                    if run != 0 {
                        output(&bytes[offset..offset + run]);
                        offset += run;
                    }
                    if offset < bytes.len() {
                        self.state = FilterState::Escape;
                        offset += 1;
                    }
                }
                FilterState::Escape => {
                    let byte = bytes[offset];
                    offset += 1;
                    match byte {
                        b']' => {
                            // The OSC introducer cancels a preceding partial
                            // CSI/DCS even though its payload never reaches VTE.
                            output(&[CAN]);
                            self.state = FilterState::Osc;
                        }
                        ESC => output(ESC_BYTE),
                        _ => {
                            self.state = FilterState::Ground;
                            output(ESC_BYTE);
                            output(&bytes[offset - 1..offset]);
                        }
                    }
                }
                FilterState::Osc => {
                    let byte = bytes[offset];
                    offset += 1;
                    match byte {
                        BEL | CAN | SUB => self.state = FilterState::Ground,
                        ESC => self.state = FilterState::OscEscape,
                        _ => {}
                    }
                }
                FilterState::OscEscape => {
                    let byte = bytes[offset];
                    offset += 1;
                    match byte {
                        b'\\' => self.state = FilterState::Ground,
                        b']' => self.state = FilterState::Osc,
                        ESC => {
                            // The first ESC canceled the OSC; this second ESC
                            // is the only byte that remains pending.
                            self.state = FilterState::Escape;
                        }
                        _ => {
                            // An ESC also cancels an OSC. Reintroduce it so a
                            // following CSI, RIS, or other escape is parsed.
                            self.state = FilterState::Ground;
                            output(ESC_BYTE);
                            output(&bytes[offset - 1..offset]);
                        }
                    }
                }
            }
        }
    }
}
