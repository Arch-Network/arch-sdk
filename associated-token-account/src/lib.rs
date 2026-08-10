//! Program state processor

mod tools;

use arch_program::{
    account::{next_account_info, AccountInfo, AccountMeta},
    entrypoint::ProgramResult,
    instruction::Instruction,
    msg,
    program::invoke,
    program_error::ProgramError,
    program_pack::Pack,
    pubkey::Pubkey,
};
use tools::{create_pda_account, create_pda_account_with_anchor};

#[cfg(not(feature = "no-entrypoint"))]
use arch_program::entrypoint;

arch_program::declare_id!("ATok9pxLsNzM5zJJ3UQpXBrMriHpZiY5Yio3GKYU4we3");

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreateMode {
    Always,
    Idempotent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreateInstruction {
    mode: CreateMode,
    anchor: Option<([u8; 32], u32)>,
}

fn parse_anchor(input: &[u8]) -> ([u8; 32], u32) {
    let txid = input[..32].try_into().expect("anchor txid is 32 bytes");
    let vout = u32::from_le_bytes(input[32..36].try_into().expect("anchor vout is 4 bytes"));
    (txid, vout)
}

fn parse_create_instruction(input: &[u8]) -> Result<CreateInstruction, ProgramError> {
    match input {
        [] => Ok(CreateInstruction {
            mode: CreateMode::Always,
            anchor: None,
        }),
        [1] => Ok(CreateInstruction {
            mode: CreateMode::Idempotent,
            anchor: None,
        }),
        bytes if bytes.len() == 36 => Ok(CreateInstruction {
            mode: CreateMode::Always,
            anchor: Some(parse_anchor(bytes)),
        }),
        [2, bytes @ ..] if bytes.len() == 36 => Ok(CreateInstruction {
            mode: CreateMode::Idempotent,
            anchor: Some(parse_anchor(bytes)),
        }),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn validate_idempotent_account(
    associated_token_account: &AccountInfo,
    wallet: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Result<bool, ProgramError> {
    if associated_token_account.owner == token_program {
        let data = associated_token_account.data.borrow();
        let token_account =
            apl_token::state::Account::unpack(&data).map_err(|_| ProgramError::IllegalOwner)?;

        if token_account.owner != *wallet {
            return Err(ProgramError::IllegalOwner);
        }
        if token_account.mint != *mint {
            return Err(ProgramError::InvalidAccountData);
        }
        return Ok(true);
    }

    if *associated_token_account.owner != Pubkey::system_program() {
        return Err(ProgramError::IllegalOwner);
    }

    Ok(false)
}

/// Instruction processor
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let instruction = parse_create_instruction(input)?;
    let account_info_iter = &mut accounts.iter();

    let funder_info = next_account_info(account_info_iter)?;
    let associated_token_account_info = next_account_info(account_info_iter)?;
    let wallet_account_info = next_account_info(account_info_iter)?;
    let spl_token_mint_info = next_account_info(account_info_iter)?;
    let system_program_info = next_account_info(account_info_iter)?;
    let spl_token_program_info = next_account_info(account_info_iter)?;
    let spl_token_program_id = spl_token_program_info.key;

    if *spl_token_program_id != apl_token::id() {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (associated_token_address, bump_seed) = get_associated_token_address_and_bump_seed(
        wallet_account_info.key,
        spl_token_mint_info.key,
        program_id,
    );
    if associated_token_address != *associated_token_account_info.key {
        msg!("Error: Associated address does not match seed derivation");
        return Err(ProgramError::InvalidSeeds);
    }

    if instruction.mode == CreateMode::Idempotent
        && validate_idempotent_account(
            associated_token_account_info,
            wallet_account_info.key,
            spl_token_mint_info.key,
            spl_token_program_id,
        )?
    {
        return Ok(());
    }

    let associated_token_account_signer_seeds: &[&[_]] = &[
        &wallet_account_info.key.serialize(),
        &apl_token::id().serialize(),
        &spl_token_mint_info.key.serialize(),
        &[bump_seed],
    ];

    if let Some((txid, vout)) = instruction.anchor {
        create_pda_account_with_anchor(
            funder_info,
            apl_token::state::Account::LEN,
            spl_token_program_info.key,
            txid,
            vout,
            system_program_info,
            associated_token_account_info,
            associated_token_account_signer_seeds,
        )?;
    } else {
        create_pda_account(
            funder_info,
            apl_token::state::Account::LEN,
            spl_token_program_info.key,
            system_program_info,
            associated_token_account_info,
            associated_token_account_signer_seeds,
        )?;
    }

    msg!("Initialize the associated token account");
    invoke(
        &apl_token::instruction::initialize_account3(
            spl_token_program_id,
            associated_token_account_info.key,
            spl_token_mint_info.key,
            wallet_account_info.key,
        )?,
        &[
            associated_token_account_info.clone(),
            spl_token_mint_info.clone(),
            wallet_account_info.clone(),
            spl_token_program_info.clone(),
        ],
    )
}

pub fn get_associated_token_address_and_bump_seed(
    wallet_address: &Pubkey,
    spl_token_mint_address: &Pubkey,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            &wallet_address.serialize(),
            &apl_token::id().serialize(),
            &spl_token_mint_address.serialize(),
        ],
        program_id,
    )
}

pub fn create_associated_token_account(
    funder: &Pubkey,
    associated_token_account: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    spl_token_program: &Pubkey,
    system_program: &Pubkey,
) -> Instruction {
    create_associated_token_account_instruction(
        funder,
        associated_token_account,
        wallet,
        mint,
        spl_token_program,
        system_program,
        vec![],
    )
}

pub fn create_associated_token_account_idempotent(
    funder: &Pubkey,
    associated_token_account: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    spl_token_program: &Pubkey,
    system_program: &Pubkey,
) -> Instruction {
    create_associated_token_account_instruction(
        funder,
        associated_token_account,
        wallet,
        mint,
        spl_token_program,
        system_program,
        vec![1],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_associated_token_account_with_anchor(
    funder: &Pubkey,
    associated_token_account: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    spl_token_program: &Pubkey,
    system_program: &Pubkey,
    txid: [u8; 32],
    vout: u32,
) -> Instruction {
    let mut data = txid.to_vec();
    data.extend_from_slice(&vout.to_le_bytes());

    create_associated_token_account_instruction(
        funder,
        associated_token_account,
        wallet,
        mint,
        spl_token_program,
        system_program,
        data,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_associated_token_account_idempotent_with_anchor(
    funder: &Pubkey,
    associated_token_account: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    spl_token_program: &Pubkey,
    system_program: &Pubkey,
    txid: [u8; 32],
    vout: u32,
) -> Instruction {
    let mut data = vec![2];
    data.extend_from_slice(&txid);
    data.extend_from_slice(&vout.to_le_bytes());

    create_associated_token_account_instruction(
        funder,
        associated_token_account,
        wallet,
        mint,
        spl_token_program,
        system_program,
        data,
    )
}

#[allow(clippy::too_many_arguments)]
fn create_associated_token_account_instruction(
    funder: &Pubkey,
    associated_token_account: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    spl_token_program: &Pubkey,
    system_program: &Pubkey,
    data: Vec<u8>,
) -> Instruction {
    Instruction::new(
        id(),
        data,
        vec![
            AccountMeta::new(*funder, true),
            AccountMeta::new(*associated_token_account, false),
            AccountMeta::new_readonly(*wallet, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*system_program, false),
            AccountMeta::new_readonly(*spl_token_program, false),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use apl_token::state::{Account as TokenAccount, AccountState};
    use arch_program::{program_option::COption, utxo::UtxoMeta};

    fn token_account_data(mint: Pubkey, wallet: Pubkey) -> Vec<u8> {
        let mut data = vec![0; TokenAccount::LEN];
        TokenAccount {
            mint,
            owner: wallet,
            amount: 0,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        }
        .pack_into_slice(&mut data);
        data
    }

    fn test_account_info<'a>(
        key: &'a Pubkey,
        lamports: &'a mut u64,
        data: &'a mut [u8],
        owner: &'a Pubkey,
        utxo: &'a UtxoMeta,
    ) -> AccountInfo<'a> {
        AccountInfo::new(key, lamports, data, owner, utxo, false, true, false)
    }

    #[test]
    fn parses_legacy_and_idempotent_create_instructions() {
        assert_eq!(
            parse_create_instruction(&[]),
            Ok(CreateInstruction {
                mode: CreateMode::Always,
                anchor: None,
            })
        );
        assert_eq!(
            parse_create_instruction(&[1]),
            Ok(CreateInstruction {
                mode: CreateMode::Idempotent,
                anchor: None,
            })
        );

        let txid = [7; 32];
        let vout: u32 = 42;
        let mut anchored = txid.to_vec();
        anchored.extend_from_slice(&vout.to_le_bytes());
        assert_eq!(
            parse_create_instruction(&anchored),
            Ok(CreateInstruction {
                mode: CreateMode::Always,
                anchor: Some((txid, vout)),
            })
        );

        let mut idempotent_anchored = vec![2];
        idempotent_anchored.extend_from_slice(&anchored);
        assert_eq!(
            parse_create_instruction(&idempotent_anchored),
            Ok(CreateInstruction {
                mode: CreateMode::Idempotent,
                anchor: Some((txid, vout)),
            })
        );
    }

    #[test]
    fn rejects_unknown_or_malformed_create_instructions() {
        for input in [
            vec![0],
            vec![2],
            vec![3],
            vec![1, 0],
            vec![0; 35],
            vec![0; 37],
        ] {
            assert_eq!(
                parse_create_instruction(&input),
                Err(ProgramError::InvalidInstructionData)
            );
        }
    }

    #[test]
    fn idempotent_builders_preserve_account_layout_and_encode_mode() {
        let funder = Pubkey::new_unique();
        let associated_token_account = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_program = Pubkey::new_unique();
        let system_program = Pubkey::new_unique();

        let ordinary = create_associated_token_account_idempotent(
            &funder,
            &associated_token_account,
            &wallet,
            &mint,
            &token_program,
            &system_program,
        );
        assert_eq!(ordinary.data, vec![1]);
        let legacy_ordinary = create_associated_token_account(
            &funder,
            &associated_token_account,
            &wallet,
            &mint,
            &token_program,
            &system_program,
        );
        assert_eq!(ordinary.accounts, legacy_ordinary.accounts);
        assert_eq!(
            ordinary.accounts,
            vec![
                AccountMeta::new(funder, true),
                AccountMeta::new(associated_token_account, false),
                AccountMeta::new_readonly(wallet, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(system_program, false),
                AccountMeta::new_readonly(token_program, false),
            ]
        );

        let txid = [9; 32];
        let vout: u32 = 17;
        let anchored = create_associated_token_account_idempotent_with_anchor(
            &funder,
            &associated_token_account,
            &wallet,
            &mint,
            &token_program,
            &system_program,
            txid,
            vout,
        );
        let mut expected_data = vec![2];
        expected_data.extend_from_slice(&txid);
        expected_data.extend_from_slice(&vout.to_le_bytes());
        assert_eq!(anchored.data, expected_data);
        assert_eq!(anchored.accounts, ordinary.accounts);
        let legacy_anchored = create_associated_token_account_with_anchor(
            &funder,
            &associated_token_account,
            &wallet,
            &mint,
            &token_program,
            &system_program,
            txid,
            vout,
        );
        assert_eq!(anchored.accounts, legacy_anchored.accounts);
    }

    #[test]
    fn legacy_builders_keep_their_existing_encodings() {
        let funder = Pubkey::new_unique();
        let associated_token_account = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_program = Pubkey::new_unique();
        let system_program = Pubkey::new_unique();

        let ordinary = create_associated_token_account(
            &funder,
            &associated_token_account,
            &wallet,
            &mint,
            &token_program,
            &system_program,
        );
        assert!(ordinary.data.is_empty());

        let txid = [5; 32];
        let vout: u32 = 23;
        let anchored = create_associated_token_account_with_anchor(
            &funder,
            &associated_token_account,
            &wallet,
            &mint,
            &token_program,
            &system_program,
            txid,
            vout,
        );
        let mut expected_data = txid.to_vec();
        expected_data.extend_from_slice(&vout.to_le_bytes());
        assert_eq!(anchored.data, expected_data);
        assert_eq!(anchored.accounts, ordinary.accounts);
    }

    #[test]
    fn validates_existing_idempotent_token_account() {
        let key = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_program = apl_token::id();
        let utxo = UtxoMeta::from([3; 32], 5);
        let mut lamports = 100;
        let mut data = token_account_data(mint, wallet);
        let account = test_account_info(&key, &mut lamports, &mut data, &token_program, &utxo);

        assert_eq!(
            validate_idempotent_account(&account, &wallet, &mint, &token_program),
            Ok(true)
        );
    }

    #[test]
    fn treats_system_owned_idempotent_account_as_missing() {
        let key = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_program = apl_token::id();
        let system_program = Pubkey::system_program();
        let utxo = UtxoMeta::from([0; 32], 0);
        let mut lamports = 0;
        let mut data = Vec::new();
        let account = test_account_info(&key, &mut lamports, &mut data, &system_program, &utxo);

        assert_eq!(
            validate_idempotent_account(&account, &wallet, &mint, &token_program),
            Ok(false)
        );
    }

    #[test]
    fn rejects_incompatible_existing_idempotent_accounts() {
        let key = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_program = apl_token::id();
        let utxo = UtxoMeta::from([4; 32], 2);

        let wrong_authority = Pubkey::new_unique();
        let mut authority_lamports = 1;
        let mut authority_data = token_account_data(mint, wrong_authority);
        let authority_account = test_account_info(
            &key,
            &mut authority_lamports,
            &mut authority_data,
            &token_program,
            &utxo,
        );
        assert_eq!(
            validate_idempotent_account(&authority_account, &wallet, &mint, &token_program),
            Err(ProgramError::IllegalOwner)
        );

        let wrong_mint = Pubkey::new_unique();
        let mut mint_lamports = 1;
        let mut mint_data = token_account_data(wrong_mint, wallet);
        let mint_account = test_account_info(
            &key,
            &mut mint_lamports,
            &mut mint_data,
            &token_program,
            &utxo,
        );
        assert_eq!(
            validate_idempotent_account(&mint_account, &wallet, &mint, &token_program),
            Err(ProgramError::InvalidAccountData)
        );

        let mut malformed_lamports = 1;
        let mut malformed_data = vec![0; 3];
        let malformed_account = test_account_info(
            &key,
            &mut malformed_lamports,
            &mut malformed_data,
            &token_program,
            &utxo,
        );
        assert_eq!(
            validate_idempotent_account(&malformed_account, &wallet, &mint, &token_program),
            Err(ProgramError::IllegalOwner)
        );

        let foreign_program = Pubkey::new_unique();
        let mut foreign_lamports = 1;
        let mut foreign_data = token_account_data(mint, wallet);
        let foreign_account = test_account_info(
            &key,
            &mut foreign_lamports,
            &mut foreign_data,
            &foreign_program,
            &utxo,
        );
        assert_eq!(
            validate_idempotent_account(&foreign_account, &wallet, &mint, &token_program),
            Err(ProgramError::IllegalOwner)
        );
    }

    #[test]
    fn process_instruction_noops_for_existing_idempotent_account() {
        let program_id = id();
        let funder_key = Pubkey::new_unique();
        let wallet_key = Pubkey::new_unique();
        let mint_key = Pubkey::new_unique();
        let system_program_key = Pubkey::system_program();
        let token_program_key = apl_token::id();
        let (associated_key, _) =
            get_associated_token_address_and_bump_seed(&wallet_key, &mint_key, &program_id);
        let utxo = UtxoMeta::from([8; 32], 11);

        let mut funder_lamports = 1_000;
        let mut funder_data = Vec::new();
        let funder = AccountInfo::new(
            &funder_key,
            &mut funder_lamports,
            &mut funder_data,
            &system_program_key,
            &utxo,
            true,
            true,
            false,
        );
        let mut associated_lamports = 700;
        let mut associated_data = token_account_data(mint_key, wallet_key);
        let associated = AccountInfo::new(
            &associated_key,
            &mut associated_lamports,
            &mut associated_data,
            &token_program_key,
            &utxo,
            false,
            true,
            false,
        );
        let mut wallet_lamports = 0;
        let mut wallet_data = Vec::new();
        let wallet = AccountInfo::new(
            &wallet_key,
            &mut wallet_lamports,
            &mut wallet_data,
            &system_program_key,
            &utxo,
            false,
            false,
            false,
        );
        let mut mint_lamports = 0;
        let mut mint_data = Vec::new();
        let mint = AccountInfo::new(
            &mint_key,
            &mut mint_lamports,
            &mut mint_data,
            &token_program_key,
            &utxo,
            false,
            false,
            false,
        );
        let mut system_lamports = 0;
        let mut system_data = Vec::new();
        let system_program = AccountInfo::new(
            &system_program_key,
            &mut system_lamports,
            &mut system_data,
            &system_program_key,
            &utxo,
            false,
            false,
            true,
        );
        let mut token_program_lamports = 0;
        let mut token_program_data = Vec::new();
        let token_program = AccountInfo::new(
            &token_program_key,
            &mut token_program_lamports,
            &mut token_program_data,
            &system_program_key,
            &utxo,
            false,
            false,
            true,
        );
        let accounts = vec![
            funder,
            associated.clone(),
            wallet,
            mint,
            system_program,
            token_program,
        ];
        let original_data = associated.data.borrow().to_vec();
        let original_lamports = **associated.lamports.borrow();
        let original_utxo = associated.utxo;

        assert_eq!(process_instruction(&program_id, &accounts, &[1]), Ok(()));

        let mut anchored_input = vec![2];
        anchored_input.extend_from_slice(&[12; 32]);
        anchored_input.extend_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            process_instruction(&program_id, &accounts, &anchored_input),
            Ok(())
        );
        assert_eq!(associated.data.borrow().to_vec(), original_data);
        assert_eq!(**associated.lamports.borrow(), original_lamports);
        assert_eq!(associated.owner, &token_program_key);
        assert_eq!(associated.utxo, original_utxo);

        let incompatible_data = token_account_data(mint_key, Pubkey::new_unique());
        associated
            .data
            .borrow_mut()
            .copy_from_slice(&incompatible_data);
        assert_eq!(
            process_instruction(&program_id, &accounts, &[1]),
            Err(ProgramError::IllegalOwner)
        );
    }

    #[test]
    fn process_instruction_rejects_unsupported_token_program() {
        let program_id = id();
        let funder_key = Pubkey::new_unique();
        let wallet_key = Pubkey::new_unique();
        let mint_key = Pubkey::new_unique();
        let system_program_key = Pubkey::system_program();
        let unsupported_token_program_key = Pubkey::new_unique();
        let (associated_key, _) =
            get_associated_token_address_and_bump_seed(&wallet_key, &mint_key, &program_id);
        let utxo = UtxoMeta::from([0; 32], 0);

        let mut funder_lamports = 0;
        let mut associated_lamports = 0;
        let mut wallet_lamports = 0;
        let mut mint_lamports = 0;
        let mut system_lamports = 0;
        let mut token_program_lamports = 0;
        let mut funder_data = Vec::new();
        let mut associated_data = Vec::new();
        let mut wallet_data = Vec::new();
        let mut mint_data = Vec::new();
        let mut system_data = Vec::new();
        let mut token_program_data = Vec::new();
        let accounts = vec![
            AccountInfo::new(
                &funder_key,
                &mut funder_lamports,
                &mut funder_data,
                &system_program_key,
                &utxo,
                true,
                true,
                false,
            ),
            AccountInfo::new(
                &associated_key,
                &mut associated_lamports,
                &mut associated_data,
                &system_program_key,
                &utxo,
                false,
                true,
                false,
            ),
            AccountInfo::new(
                &wallet_key,
                &mut wallet_lamports,
                &mut wallet_data,
                &system_program_key,
                &utxo,
                false,
                false,
                false,
            ),
            AccountInfo::new(
                &mint_key,
                &mut mint_lamports,
                &mut mint_data,
                &unsupported_token_program_key,
                &utxo,
                false,
                false,
                false,
            ),
            AccountInfo::new(
                &system_program_key,
                &mut system_lamports,
                &mut system_data,
                &system_program_key,
                &utxo,
                false,
                false,
                true,
            ),
            AccountInfo::new(
                &unsupported_token_program_key,
                &mut token_program_lamports,
                &mut token_program_data,
                &system_program_key,
                &utxo,
                false,
                false,
                true,
            ),
        ];

        assert_eq!(
            process_instruction(&program_id, &accounts, &[1]),
            Err(ProgramError::IncorrectProgramId)
        );
    }

    #[test]
    fn process_instruction_rejects_malformed_data_before_reading_accounts() {
        assert_eq!(
            process_instruction(&id(), &[], &[9]),
            Err(ProgramError::InvalidInstructionData)
        );
    }
}
