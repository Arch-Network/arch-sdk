use arch_program::{
    account::AccountInfo,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    pubkey::Pubkey,
    rent::minimum_rent,
    system_instruction,
};

/// Tops `new_pda_account` up to the rent-exempt minimum for `space`.
fn top_up_to_rent_exempt<'a>(
    payer: &AccountInfo<'a>,
    space: usize,
    system_program: &AccountInfo<'a>,
    new_pda_account: &AccountInfo<'a>,
) -> ProgramResult {
    let required_lamports = minimum_rent(space).saturating_sub(new_pda_account.lamports());
    if required_lamports > 0 {
        invoke(
            &system_instruction::transfer(payer.key, new_pda_account.key, required_lamports),
            &[
                payer.clone(),
                new_pda_account.clone(),
                system_program.clone(),
            ],
        )?;
    }
    Ok(())
}

/// Sizes the PDA and hands it to `owner`.
fn allocate_and_assign<'a>(
    space: usize,
    owner: &Pubkey,
    system_program: &AccountInfo<'a>,
    new_pda_account: &AccountInfo<'a>,
    new_pda_signer_seeds: &[&[u8]],
) -> ProgramResult {
    invoke_signed(
        &system_instruction::allocate(new_pda_account.key, space as u64),
        &[new_pda_account.clone(), system_program.clone()],
        &[new_pda_signer_seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(new_pda_account.key, owner),
        &[new_pda_account.clone(), system_program.clone()],
        &[new_pda_signer_seeds],
    )
}

/// Creates associated token account using Program Derived Address for the given
/// seeds
///
/// If the account already exists, it will be topped up to rent-exempt and assigned to the given owner.
pub fn create_pda_account<'a>(
    payer: &AccountInfo<'a>,
    space: usize,
    owner: &Pubkey,
    system_program: &AccountInfo<'a>,
    new_pda_account: &AccountInfo<'a>,
    new_pda_signer_seeds: &[&[u8]],
) -> ProgramResult {
    if new_pda_account.lamports() > 0 {
        top_up_to_rent_exempt(payer, space, system_program, new_pda_account)?;
        allocate_and_assign(
            space,
            owner,
            system_program,
            new_pda_account,
            new_pda_signer_seeds,
        )
    } else {
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
    if new_pda_account.lamports() > 0 {
        top_up_to_rent_exempt(payer, space, system_program, new_pda_account)?;
        // The system program can only set the UTXO of an account it still owns,
        // so anchoring has to happen before the account is assigned away.
        invoke_signed(
            &system_instruction::anchor(new_pda_account.key, txid, vout),
            &[new_pda_account.clone(), system_program.clone()],
            &[new_pda_signer_seeds],
        )?;
        allocate_and_assign(
            space,
            owner,
            system_program,
            new_pda_account,
            new_pda_signer_seeds,
        )
    } else {
        invoke_signed(
            &system_instruction::create_account_with_anchor(
                payer.key,
                new_pda_account.key,
                minimum_rent(space),
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
}
