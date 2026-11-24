//! AES key plumbing: load a 32-byte key from the environment.
//!
//! Mirrors `gta6/rpf9/keys.py`. The key may be given as hex in `GTA6_AES_KEY_HEX` or
//! as a path to a 32-byte file in `GTA6_AES_KEY_FILE`. Returns `None` when neither is
//! set (the caller then leaves encrypted archives undecrypted).

/// Load a 32-byte AES-256 key from the environment, or `None` if unset.
pub fn load_aes_key() -> Option<Vec<u8>> {
    if let Ok(hex) = std::env::var("GTA6_AES_KEY_HEX") {
        let hex: String = hex
            .trim()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '_')
            .collect();
        if !hex.is_empty()
            && let Some(k) = parse_hex(&hex)
            && k.len() == 32
        {
            return Some(k);
        }
    }
    if let Ok(path) = std::env::var("GTA6_AES_KEY_FILE")
        && let Ok(bytes) = std::fs::read(&path)
        && bytes.len() == 32
    {
        return Some(bytes);
    }
    None
}

/// Parse a hex string into bytes; `None` on any non-hex character or odd length.
fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
