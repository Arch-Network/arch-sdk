crate::declare_id!("VoteProgram11111111111111111111111111111111");

/// Backwards-compatible alias for the vote program ID.
pub const VOTE_PROGRAM_ID: crate::pubkey::Pubkey = ID;

/// Seed of a validator's vote account address, see [`vote_account_address`].
pub const VOTE_ACCOUNT_SEED: &str = "vote";

/// Address of the vote account of the validator whose identity is
/// `node_pubkey`: `Pubkey::create_with_seed(node_pubkey, "vote", vote program)`,
/// as Solana's derived vote accounts. The identity is a system account that
/// pays the validator's fees. The vote program does not check this
/// derivation; `CreateAccountWithSeed` does, when the account is created.
pub fn vote_account_address(node_pubkey: &crate::pubkey::Pubkey) -> crate::pubkey::Pubkey {
    crate::pubkey::Pubkey::create_with_seed(node_pubkey, VOTE_ACCOUNT_SEED, &ID)
        .expect("VOTE_ACCOUNT_SEED is shorter than MAX_SEED_LEN")
}
