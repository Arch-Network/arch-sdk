use crate::{
    constants::BITCOIN_NETWORK, helper::send_transactions_and_wait, logging::init_logging,
};
use arch_program::{
    program_pack::Pack, pubkey::Pubkey, rent::minimum_rent, sanitized::ArchMessage,
    system_instruction::create_account,
};
use arch_sdk::{build_and_sign_transaction, generate_new_keypair, ArchRpcClient, Status};
use bitcoin::key::Keypair;

pub fn initialize_mint_token(
    client: &ArchRpcClient,
    authority_pubkey: Pubkey,
    authority_keypair: Keypair,
    freeze_authority_pubkey: Option<&Pubkey>,
    size: u64,
    owner: &Pubkey,
) -> (Keypair, Pubkey) {
    init_logging();

    let (token_mint_keypair, token_mint_pubkey, _) = generate_new_keypair(BITCOIN_NETWORK);

    let create_account_instruction = create_account(
        &authority_pubkey,
        &token_mint_pubkey,
        minimum_rent(0),
        size,
        owner,
    );

    let initialize_mint_instruction = apl_token::instruction::initialize_mint(
        &apl_token::id(),
        &token_mint_pubkey,
        &authority_pubkey,
        freeze_authority_pubkey,
        9,
    )
    .unwrap();

    let transaction = build_and_sign_transaction(
        ArchMessage::new(
            &[create_account_instruction, initialize_mint_instruction],
            Some(authority_pubkey),
            client.get_best_finalized_block_hash().unwrap(),
        ),
        vec![authority_keypair, token_mint_keypair],
        BITCOIN_NETWORK,
    )
    .expect("Failed to build and sign transaction");

    let processed_transactions = send_transactions_and_wait(vec![transaction]);
    assert_eq!(processed_transactions[0].status, Status::Processed);

    (token_mint_keypair, token_mint_pubkey)
}

pub fn initialize_token_account(
    client: &ArchRpcClient,
    token_mint_pubkey: Pubkey,
    owner_keypair: Keypair,
) -> (Keypair, Pubkey) {
    init_logging();

    let owner_pubkey = Pubkey::from_slice(&owner_keypair.x_only_public_key().0.serialize());

    let (token_account_keypair, token_account_pubkey, _) = generate_new_keypair(BITCOIN_NETWORK);

    let create_account_instruction = create_account(
        &owner_pubkey,
        &token_account_pubkey,
        minimum_rent(apl_token::state::Account::LEN),
        apl_token::state::Account::LEN as u64,
        &apl_token::id(),
    );

    let initialize_token_account_instruction = apl_token::instruction::initialize_account(
        &apl_token::id(),
        &token_account_pubkey,
        &token_mint_pubkey,
        &owner_pubkey,
    )
    .unwrap();

    let transaction = build_and_sign_transaction(
        ArchMessage::new(
            &[
                create_account_instruction,
                initialize_token_account_instruction,
            ],
            Some(owner_pubkey),
            client.get_best_finalized_block_hash().unwrap(),
        ),
        vec![owner_keypair, token_account_keypair],
        BITCOIN_NETWORK,
    )
    .expect("Failed to build and sign transaction");

    let processed_transactions = send_transactions_and_wait(vec![transaction]);
    assert_eq!(processed_transactions[0].status, Status::Processed);

    (token_account_keypair, token_account_pubkey)
}

pub fn mint_tokens(
    client: &ArchRpcClient,
    mint_pubkey: &Pubkey,
    account_pubkey: &Pubkey,
    owner_pubkey: &Pubkey,
    owner_keypair: Keypair,
    amount: u64,
) {
    let instruction = apl_token::instruction::mint_to(
        &apl_token::id(),
        mint_pubkey,
        account_pubkey,
        owner_pubkey,
        &[],
        amount,
    )
    .unwrap();

    let transaction = build_and_sign_transaction(
        ArchMessage::new(
            &[instruction],
            Some(*owner_pubkey),
            client.get_best_finalized_block_hash().unwrap(),
        ),
        vec![owner_keypair],
        BITCOIN_NETWORK,
    )
    .expect("Failed to build and sign transaction");

    let processed_transactions = send_transactions_and_wait(vec![transaction]);
    assert_eq!(processed_transactions[0].status, Status::Processed);
}

pub fn approve(
    client: &ArchRpcClient,
    source_pubkey: &Pubkey,
    delegate_pubkey: &Pubkey,
    owner_pubkey: &Pubkey,
    owner_keypair: Keypair,
    amount: u64,
) {
    let instruction = apl_token::instruction::approve(
        &apl_token::id(),
        source_pubkey,
        delegate_pubkey,
        owner_pubkey,
        &[owner_pubkey],
        amount,
    )
    .unwrap();

    let transaction = build_and_sign_transaction(
        ArchMessage::new(
            &[instruction],
            Some(*owner_pubkey),
            client.get_best_finalized_block_hash().unwrap(),
        ),
        vec![owner_keypair],
        BITCOIN_NETWORK,
    )
    .expect("Failed to build and sign transaction");

    let processed_transactioins = send_transactions_and_wait(vec![transaction]);
    assert_eq!(processed_transactioins[0].status, Status::Processed);
}

pub fn revoke(
    client: &ArchRpcClient,
    source_pubkey: &Pubkey,
    owner_pubkey: &Pubkey,
    owner_keypair: Keypair,
) {
    let instruction = apl_token::instruction::revoke(
        &apl_token::id(),
        source_pubkey,
        owner_pubkey,
        &[owner_pubkey],
    )
    .unwrap();

    let transaction = build_and_sign_transaction(
        ArchMessage::new(
            &[instruction],
            Some(*owner_pubkey),
            client.get_best_finalized_block_hash().unwrap(),
        ),
        vec![owner_keypair],
        BITCOIN_NETWORK,
    )
    .expect("Failed to build and sign transaction");

    let processed_tx = send_transactions_and_wait(vec![transaction]);
    assert_eq!(processed_tx[0].status, Status::Processed);
}

pub fn create_account_helper(
    client: &ArchRpcClient,
    from_pubkey: &Pubkey,
    to_pubkey: &Pubkey,
    from_keypair: Keypair,
    to_keypair: Keypair,
    space: u64,
    owner: &Pubkey,
) {
    let create_account_instruction = create_account(
        from_pubkey,
        to_pubkey,
        minimum_rent(space as usize),
        space,
        owner,
    );

    let transaction = build_and_sign_transaction(
        ArchMessage::new(
            &[create_account_instruction],
            Some(*from_pubkey),
            client.get_best_finalized_block_hash().unwrap(),
        ),
        vec![from_keypair, to_keypair],
        BITCOIN_NETWORK,
    )
    .expect("Failed to build and sign transaction");

    let processed_tx = send_transactions_and_wait(vec![transaction]);
    assert_eq!(processed_tx[0].status, Status::Processed);
}

pub fn freeze_account(
    client: &ArchRpcClient,
    token_account_pubkey: &Pubkey,
    mint_pubkey: &Pubkey,
    owner_pubkey: &Pubkey,
    owner_keypair: Keypair,
) {
    let instruction = apl_token::instruction::freeze_account(
        &apl_token::id(),
        token_account_pubkey,
        mint_pubkey,
        owner_pubkey,
        &[owner_pubkey],
    )
    .unwrap();

    let transaction = build_and_sign_transaction(
        ArchMessage::new(
            &[instruction],
            Some(*owner_pubkey),
            client.get_best_finalized_block_hash().unwrap(),
        ),
        vec![owner_keypair],
        BITCOIN_NETWORK,
    )
    .expect("Failed to build and sign transaction");

    let processed_tx = send_transactions_and_wait(vec![transaction]);
    assert_eq!(processed_tx[0].status, Status::Processed);
}
