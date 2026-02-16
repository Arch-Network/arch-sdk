// This is the native loader.
// Used for invoking native programs; it doesn't have an account of its own,
// but native programs use this address in their owner's field.
crate::declare_id!("NativeLoader1111111111111111111111111111111");

/// Backwards-compatible alias for the native loader program ID.
pub const NATIVE_LOADER_ID: crate::pubkey::Pubkey = ID;
