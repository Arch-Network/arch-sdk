use anyhow::Result;

use indicatif::{ProgressBar, ProgressStyle};

use std::fs;

use crate::helper::{get_processed_transaction, sign_and_send_instruction};

use crate::arch_program::message::Message;
use crate::arch_program::pubkey::Pubkey;
use crate::arch_program::system_instruction::SystemInstruction;
use crate::constants::{BITCOIN_NETWORK, NODE1_ADDRESS};
use crate::error::SDKError;
use crate::runtime_transaction::RuntimeTransaction;
use crate::signature::Signature;

use bitcoin::key::UntweakedKeypair;
use bitcoin::XOnlyPublicKey;

use super::{extend_bytes_max_len, post_data, process_result, sign_message_bip322};
use crate::helper::read_account_info;
/// Deploys the HelloWorld program using the compiled ELF
pub fn deploy_program_txs(
    program_keypair: UntweakedKeypair,
    elf_path: &str,
) -> Result<(), SDKError> {
    let program_pubkey =
        Pubkey::from_slice(&XOnlyPublicKey::from_keypair(&program_keypair).0.serialize());

    let account_info = read_account_info(NODE1_ADDRESS, program_pubkey)?;

    if account_info.is_executable {
        let (txid, _) = sign_and_send_instruction(
            SystemInstruction::new_retract_instruction(program_pubkey),
            vec![program_keypair],
        )
        .map_err(|_| SDKError::SignAndSendFailed)?;

        let processed_tx = get_processed_transaction(NODE1_ADDRESS, txid.clone())
            .map_err(|_| SDKError::GetProcessedTransactionFailed)?;

        println!("processed_tx {:?}", processed_tx);
    }

    let elf = fs::read(elf_path).map_err(|_| SDKError::ElfPathNotFound)?;

    if account_info.data.len() > elf.len() {
        let (txid, _) = sign_and_send_instruction(
            SystemInstruction::new_truncate_instruction(program_pubkey, elf.len() as u32),
            vec![program_keypair],
        )
        .map_err(|_| SDKError::SignAndSendFailed)?;

        let processed_tx = get_processed_transaction(NODE1_ADDRESS, txid.clone())
            .map_err(|_| SDKError::GetProcessedTransactionFailed)?;

        println!("processed_tx {:?}", processed_tx);
    }

    let txs = elf
        .chunks(extend_bytes_max_len())
        .enumerate()
        .map(|(i, chunk)| {
            let offset: u32 = (i * extend_bytes_max_len()) as u32;
            let len: u32 = chunk.len() as u32;

            let message = Message {
                signers: vec![program_pubkey],
                instructions: vec![SystemInstruction::new_write_bytes_instruction(
                    offset,
                    len,
                    chunk.to_vec(),
                    program_pubkey,
                )],
            };

            let digest_slice = message.hash();

            RuntimeTransaction {
                version: 0,
                signatures: vec![Signature(
                    sign_message_bip322(&program_keypair, &digest_slice, BITCOIN_NETWORK).to_vec(),
                )],
                message,
            }
        })
        .collect::<Vec<RuntimeTransaction>>();

    let post_result = post_data(NODE1_ADDRESS, "send_transactions", txs);
    let processed_data =
        process_result(post_result).map_err(|_| SDKError::SendTransactionFailed)?;
    let array_data = processed_data
        .as_array()
        .ok_or(SDKError::InvalidResponseType)?;
    let txids = array_data
        .iter()
        .map(|r| {
            r.as_str()
                .ok_or(SDKError::InvalidResponseType)
                .map(String::from)
        })
        .collect::<Result<Vec<String>, SDKError>>()?;

    let pb = ProgressBar::new(txids.len() as u64);

    pb.set_style(ProgressStyle::default_bar()
        .progress_chars("#>-")
        .template("{spinner:.green}[{elapsed_precise:.blue}] {msg:.blue} [{bar:100.green/blue}] {pos}/{len} ({eta})").unwrap());

    pb.set_message("Successfully Processed Deployment Transactions :");

    for txid in txids {
        let _processed_tx = get_processed_transaction(NODE1_ADDRESS, txid.clone())
            .map_err(|_| SDKError::GetProcessedTransactionFailed)?;
        pb.inc(1);
        pb.set_message("Successfully Processed Deployment Transactions :");
    }

    pb.finish();
    Ok(())
}
