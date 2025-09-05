use arch_program::{
    account::AccountInfo, entrypoint::ProgramResult, program::invoke_signed, pubkey::Pubkey,
    rent::minimum_rent, system_instruction,
};

/// Creates associated token account using Program Derived Address for the given
/// seeds
pub fn create_pda_account<'a>(
    payer: &AccountInfo<'a>,
    space: usize,
    owner: &Pubkey,
    system_program: &AccountInfo<'a>,
    new_pda_account: &AccountInfo<'a>,
    new_pda_signer_seeds: &[&[u8]],
) -> ProgramResult {
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            new_pda_account.key,
            minimum_rent(space),
            space as u64,
            owner,
        ),
        &[
            payer.clone(),
            new_pda_account.clone(),
            system_program.clone(),
        ],
        &[new_pda_signer_seeds],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_pda_account_with_anchor<'a>(
    payer: &AccountInfo<'a>,
    space: usize,
    owner: &Pubkey,
    txid: [u8; 32],
    vout: u32,
    system_program: &AccountInfo<'a>,
    new_pda_account: &AccountInfo<'a>,
    new_pda_signer_seeds: &[&[u8]],
) -> ProgramResult {
    invoke_signed(
        &system_instruction::create_account_with_anchor(
            payer.key,
            new_pda_account.key,
            arch_program::rent::minimum_rent(space),
            space as u64,
            owner,
            txid,
            vout,
        ),
        &[
            payer.clone(),
            new_pda_account.clone(),
            system_program.clone(),
        ],
        &[new_pda_signer_seeds],
    )
}
