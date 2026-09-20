use crate::kdf_config::KdfLimits;

/// Resource ceilings for importing untrusted keystores.
///
/// The input limit counts UTF-8 bytes, including whitespace and ignored fields.
/// It is checked before JSON parsing; file reads consume at most one extra byte
/// to detect oversized input. KDF budgets apply after parsing.
///
/// These limits apply to the keystore import methods, not direct Serde use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportLimits {
    /// Maximum serialized input size in bytes. Defaults to 64 KiB.
    pub max_input_bytes: usize,
    /// CPU and memory ceilings for key derivation.
    pub kdf: KdfLimits,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            kdf: KdfLimits::default(),
        }
    }
}
