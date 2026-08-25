use crate::arch_program::pubkey::Pubkey;
use crate::arch_program::system_instruction;
use crate::build_and_sign_transaction;
use crate::client::ArchRpcClient;
use crate::program_deployment::ProgramDeployerError;
use crate::sign_message_bip322;
use crate::Config;
use crate::MAX_TX_BATCH_SIZE;
use crate::RUNTIME_TX_SIZE_LIMIT;
use crate::{
    types::{RuntimeTransaction, Signature},
    Status,
};
use arch_program::bpf_loader::{LoaderState, BPF_LOADER_ID};
use arch_program::hash::Hash;
use arch_program::loader_instruction;
use arch_program::sanitized::ArchMessage;
use bitcoin::key::Keypair;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use tracing::{debug, info, warn};

pub struct ProgramDeployer {
    client: ArchRpcClient,
}

impl ProgramDeployer {
    pub fn new(config: &Config) -> Self {
        Self {
            client: ArchRpcClient::new(config),
        }
    }

    /// Deploy a program using an authority that has already been funded.
    ///
    /// The authority pays for program-account setup and every packet-sized ELF
    /// write. The caller must provision enough lamports before calling this
    /// method; deployment never invokes a network faucet.
    pub async fn try_deploy_program(
        &self,
        program_name: String,
        program_keypair: Keypair,
        authority_keypair: Keypair,
        elf_path: &String,
    ) -> Result<Pubkey, ProgramDeployerError> {
        info!("Starting program deployment: {}", program_name);

        let elf = fs::read(elf_path).map_err(|source| ProgramDeployerError::ElfReadError {
            path: elf_path.clone(),
            source,
        })?;

        let program_pubkey = Pubkey::from_slice(&program_keypair.x_only_public_key().0.serialize());
        let authority_pubkey =
            Pubkey::from_slice(&authority_keypair.x_only_public_key().0.serialize());

        if let Some(pubkey) = self
            .ensure_account_exists(
                program_pubkey,
                authority_pubkey,
                program_keypair,
                authority_keypair,
                &elf,
            )
            .await?
        {
            return Ok(pubkey);
        }
        self.write_program_elf(program_keypair, authority_keypair, &elf)
            .await?;

        self.verify_elf_deployed(program_pubkey, &elf).await?;

        info!(program = %program_pubkey, "Step 2/3: ELF file sent and verified");

        self.ensure_executable(program_pubkey, authority_pubkey, authority_keypair)
            .await?;

        self.verify_executable(program_pubkey).await?;

        info!(
            program = %program_pubkey,
            "Program deployment complete: {}",
            program_name
        );

        Ok(program_pubkey)
    }

    /// Step 1: Ensure the program account exists on-chain.
    ///
    /// Returns `Ok(Some(pubkey))` if the same ELF is already deployed (early return),
    /// or `Ok(None)` to continue with the deployment.
    async fn ensure_account_exists(
        &self,
        program_pubkey: Pubkey,
        authority_pubkey: Pubkey,
        program_keypair: Keypair,
        authority_keypair: Keypair,
        elf: &[u8],
    ) -> Result<Option<Pubkey>, ProgramDeployerError> {
        if let Ok(account_info) = self.client.read_account_info(program_pubkey).await {
            info!(program = %program_pubkey, "Step 1/3: Account already exists, skipping creation");

            if account_info.data.len() < LoaderState::program_data_offset() {
                warn!(program = %program_pubkey, "Account is not initialized, redeploying");
            } else if account_info.data[LoaderState::program_data_offset()..] == *elf {
                info!(program = %program_pubkey, "Same program already deployed, skipping");

                if !account_info.is_executable {
                    self.make_program_executable(
                        program_pubkey,
                        authority_pubkey,
                        authority_keypair,
                    )
                    .await?;
                }

                return Ok(Some(program_pubkey));
            } else {
                warn!(program = %program_pubkey, "ELF mismatch with on-chain content, redeploying");
            }
        } else {
            self.create_program_account(
                program_pubkey,
                authority_pubkey,
                program_keypair,
                authority_keypair,
                elf.len(),
            )
            .await?;
        }

        Ok(None)
    }

    async fn create_program_account(
        &self,
        program_pubkey: Pubkey,
        authority_pubkey: Pubkey,
        program_keypair: Keypair,
        authority_keypair: Keypair,
        elf_len: usize,
    ) -> Result<(), ProgramDeployerError> {
        let recent_blockhash = self.client.get_best_finalized_block_hash().await?;

        let create_account_tx = build_and_sign_transaction(
            ArchMessage::new(
                &[system_instruction::create_account(
                    &authority_pubkey,
                    &program_pubkey,
                    arch_program::rent::minimum_rent(LoaderState::program_data_offset() + elf_len),
                    0,
                    &BPF_LOADER_ID,
                )],
                Some(authority_pubkey),
                recent_blockhash,
            ),
            vec![authority_keypair, program_keypair],
            self.client.config.network,
        )?;

        let txid = self.client.send_transaction(create_account_tx).await?;
        let tx = self.client.wait_for_processed_transaction(&txid).await?;

        if let Status::Failed(reason) = tx.status {
            return Err(ProgramDeployerError::AccountCreationFailed { txid, reason });
        }

        info!(program = %program_pubkey, tx = %txid, "Step 1/3: Program account created");
        Ok(())
    }

    async fn verify_elf_deployed(
        &self,
        program_pubkey: Pubkey,
        elf: &[u8],
    ) -> Result<(), ProgramDeployerError> {
        let account_info = self.client.read_account_info(program_pubkey).await?;

        if account_info.data[LoaderState::program_data_offset()..] != *elf {
            return Err(ProgramDeployerError::ElfMismatch {
                program: program_pubkey,
            });
        }

        debug!(
            program = %program_pubkey,
            owner = %account_info.owner,
            data_len = account_info.data.len(),
            utxo = %account_info.utxo,
            executable = account_info.is_executable,
            "Program account state after ELF upload"
        );

        Ok(())
    }

    async fn ensure_executable(
        &self,
        program_pubkey: Pubkey,
        authority_pubkey: Pubkey,
        authority_keypair: Keypair,
    ) -> Result<(), ProgramDeployerError> {
        let account_info = self.client.read_account_info(program_pubkey).await?;

        if account_info.is_executable {
            info!(program = %program_pubkey, "Step 3/3: Program account is already executable");
        } else {
            self.make_program_executable(program_pubkey, authority_pubkey, authority_keypair)
                .await?;
        }

        Ok(())
    }

    async fn verify_executable(&self, program_pubkey: Pubkey) -> Result<(), ProgramDeployerError> {
        let account_info = self.client.read_account_info(program_pubkey).await?;

        if !account_info.is_executable {
            return Err(ProgramDeployerError::NotExecutable {
                program: program_pubkey,
            });
        }

        debug!(
            program = %program_pubkey,
            owner = %account_info.owner,
            data_len = account_info.data.len(),
            utxo = %account_info.utxo,
            executable = account_info.is_executable,
            "Final program account state"
        );

        Ok(())
    }

    async fn make_program_executable(
        &self,
        program_pubkey: Pubkey,
        authority_pubkey: Pubkey,
        authority_keypair: Keypair,
    ) -> Result<(), ProgramDeployerError> {
        let recent_blockhash = self.client.get_best_finalized_block_hash().await?;
        let executability_tx = build_and_sign_transaction(
            ArchMessage::new(
                &[loader_instruction::deploy(program_pubkey, authority_pubkey)],
                Some(authority_pubkey),
                recent_blockhash,
            ),
            vec![authority_keypair],
            self.client.config.network,
        )?;

        let txid = self.client.send_transaction(executability_tx).await?;
        let tx = self.client.wait_for_processed_transaction(&txid).await?;

        if let Status::Failed(reason) = tx.status {
            return Err(ProgramDeployerError::MakeExecutableFailed { txid, reason });
        }

        info!(program = %program_pubkey, tx = %txid, "Step 3/3: Made program account executable");
        Ok(())
    }

    async fn write_program_elf(
        &self,
        program_keypair: Keypair,
        authority_keypair: Keypair,
        elf: &[u8],
    ) -> Result<(), ProgramDeployerError> {
        let program_pubkey = Pubkey::from_slice(&program_keypair.x_only_public_key().0.serialize());
        let authority_pubkey =
            Pubkey::from_slice(&authority_keypair.x_only_public_key().0.serialize());

        let account_info = self.client.read_account_info(program_pubkey).await?;

        debug!(
            program = %program_pubkey,
            executable = account_info.is_executable,
            data_len = account_info.data.len(),
            utxo = %account_info.utxo,
            owner = %account_info.owner,
            "Account state before ELF write"
        );

        if account_info.is_executable {
            let recent_blockhash = self.client.get_best_finalized_block_hash().await?;
            let retract_tx = build_and_sign_transaction(
                ArchMessage::new(
                    &[loader_instruction::retract(
                        program_pubkey,
                        authority_pubkey,
                    )],
                    Some(authority_pubkey),
                    recent_blockhash,
                ),
                vec![authority_keypair],
                self.client.config.network,
            )?;

            let retract_txid = self.client.send_transaction(retract_tx).await?;
            self.client
                .wait_for_processed_transaction(&retract_txid)
                .await?;
        }

        if account_info.data.len() != LoaderState::program_data_offset() + elf.len() {
            self.resize_program_account(
                program_pubkey,
                authority_pubkey,
                program_keypair,
                authority_keypair,
                &account_info,
                elf.len(),
            )
            .await?;
        }

        self.send_elf_chunks(program_pubkey, authority_pubkey, authority_keypair, elf)
            .await
    }

    async fn resize_program_account(
        &self,
        program_pubkey: Pubkey,
        authority_pubkey: Pubkey,
        program_keypair: Keypair,
        authority_keypair: Keypair,
        account_info: &crate::types::AccountInfo,
        elf_len: usize,
    ) -> Result<(), ProgramDeployerError> {
        debug!(program = %program_pubkey, "Truncating program account to match ELF size");

        let minimum_rent =
            arch_program::rent::minimum_rent(LoaderState::program_data_offset() + elf_len);
        let missing_lamports = minimum_rent.saturating_sub(account_info.lamports);

        if missing_lamports > 0 {
            let recent_blockhash = self.client.get_best_finalized_block_hash().await?;
            let transfer_tx = build_and_sign_transaction(
                ArchMessage::new(
                    &[system_instruction::transfer(
                        &authority_pubkey,
                        &program_pubkey,
                        missing_lamports,
                    )],
                    Some(authority_pubkey),
                    recent_blockhash,
                ),
                vec![authority_keypair],
                self.client.config.network,
            )?;

            let transfer_txid = self.client.send_transaction(transfer_tx).await?;
            self.client
                .wait_for_processed_transaction(&transfer_txid)
                .await?;
        }

        let recent_blockhash = self.client.get_best_finalized_block_hash().await?;
        let truncate_tx = build_and_sign_transaction(
            ArchMessage::new(
                &[loader_instruction::truncate(
                    program_pubkey,
                    authority_pubkey,
                    elf_len as u32,
                )],
                Some(authority_pubkey),
                recent_blockhash,
            ),
            vec![program_keypair, authority_keypair],
            self.client.config.network,
        )?;

        let truncate_txid = self.client.send_transaction(truncate_tx).await?;
        self.client
            .wait_for_processed_transaction(&truncate_txid)
            .await?;

        Ok(())
    }

    async fn send_elf_chunks(
        &self,
        program_pubkey: Pubkey,
        authority_pubkey: Pubkey,
        authority_keypair: Keypair,
        elf: &[u8],
    ) -> Result<(), ProgramDeployerError> {
        let chunk_size = extend_bytes_max_len();
        let num_chunks = elf.chunks(chunk_size).len();
        let num_batches = num_chunks.div_ceil(MAX_TX_BATCH_SIZE);

        debug!(
            program = %program_pubkey,
            chunks = num_chunks,
            batches = num_batches,
            "Preparing ELF write transactions"
        );

        let pb = ProgressBar::new(num_chunks as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] Sending ELF [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )
                .expect("Failed to set progress bar style")
                .progress_chars("#>-"),
        );

        for (batch_index, batch_bytes) in elf.chunks(chunk_size * MAX_TX_BATCH_SIZE).enumerate() {
            // A large program upload can span several blocks. Fetch the hash only
            // when its batch is ready to send so later transactions do not use the
            // hash captured at the beginning of the deployment.
            let recent_blockhash = self.client.get_best_finalized_block_hash().await?;
            let batch_start = batch_index * chunk_size * MAX_TX_BATCH_SIZE;
            let txs = batch_bytes
                .chunks(chunk_size)
                .enumerate()
                .map(|(i, chunk)| {
                    let offset = (batch_start + i * chunk_size) as u32;
                    let message = ArchMessage::new(
                        &[loader_instruction::write(
                            program_pubkey,
                            authority_pubkey,
                            offset,
                            chunk.to_vec(),
                        )],
                        Some(authority_pubkey),
                        recent_blockhash,
                    );
                    let digest_slice = message.hash();

                    Ok(RuntimeTransaction {
                        version: 0,
                        signatures: vec![Signature(sign_message_bip322(
                            &authority_keypair,
                            &digest_slice,
                            self.client.config.network,
                        )?)],
                        message,
                    })
                })
                .collect::<Result<Vec<RuntimeTransaction>, ProgramDeployerError>>()?;

            debug!(
                program = %program_pubkey,
                batch = batch_index + 1,
                batches = num_batches,
                transactions = txs.len(),
                blockhash = %recent_blockhash,
                "Sending ELF write batch"
            );
            println!(
                "Sending ELF batch {}/{} ({} transactions)",
                batch_index + 1,
                num_batches,
                txs.len()
            );

            let tx_ids = self.client.send_transactions(txs).await?;
            for (i, tx_id) in tx_ids.iter().enumerate() {
                let processed_tx = self.client.wait_for_processed_transaction(tx_id).await?;
                if let Status::Failed(reason) = processed_tx.status {
                    let offset = (batch_start + i * chunk_size) as u32;
                    return Err(ProgramDeployerError::ElfWriteFailed {
                        txid: *tx_id,
                        offset,
                        reason,
                    });
                }
                pb.inc(1);
            }
            println!(
                "Confirmed ELF batch {}/{} ({}/{} transactions)",
                batch_index + 1,
                num_batches,
                pb.position(),
                num_chunks
            );
        }

        pb.finish_with_message("ELF write transactions confirmed");
        Ok(())
    }
}

/// Returns the largest loader write payload that fits in a runtime transaction.
pub fn extend_bytes_max_len() -> usize {
    let program_pubkey = Pubkey::from([1_u8; 32]);
    let authority_pubkey = Pubkey::from([2_u8; 32]);
    let message = ArchMessage::new(
        &[loader_instruction::write(
            program_pubkey,
            authority_pubkey,
            0,
            Vec::new(),
        )],
        None,
        Hash::from([0; 32]),
    );

    RUNTIME_TX_SIZE_LIMIT
        - RuntimeTransaction {
            version: 0,
            signatures: vec![Signature([0_u8; 64])],
            message,
        }
        .serialize()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProcessedTransaction, RollbackStatus};
    use mockito::Matcher;
    use serde_json::json;

    #[test]
    fn extend_bytes_max_len_fills_runtime_transaction() {
        let max_len = extend_bytes_max_len();
        let program_pubkey = Pubkey::from([1_u8; 32]);
        let authority_pubkey = Pubkey::from([2_u8; 32]);
        let message = ArchMessage::new(
            &[loader_instruction::write(
                program_pubkey,
                authority_pubkey,
                0,
                vec![0_u8; max_len],
            )],
            None,
            Hash::from([0; 32]),
        );
        let transaction = RuntimeTransaction {
            version: 0,
            signatures: vec![Signature([0_u8; 64])],
            message,
        };

        assert_eq!(transaction.serialize().len(), RUNTIME_TX_SIZE_LIMIT);
    }

    #[tokio::test]
    async fn refreshes_blockhash_for_each_elf_batch() {
        let mut server = mockito::Server::new_async().await;
        let blockhash = Hash::from([7; 32]);
        let transaction_id = Hash::from([8; 32]);

        let blockhash_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "get_best_finalized_block_hash"
            })))
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": "test",
                    "result": blockhash.to_string()
                })
                .to_string(),
            )
            .expect(2)
            .create_async()
            .await;

        let send_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "send_transactions"
            })))
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": "test",
                    "result": [transaction_id.to_string()]
                })
                .to_string(),
            )
            .expect(2)
            .create_async()
            .await;

        let processed = ProcessedTransaction {
            runtime_transaction: RuntimeTransaction {
                version: 0,
                signatures: Vec::new(),
                message: ArchMessage::new(&[], None, Hash::from([0; 32])),
            },
            status: Status::Processed,
            bitcoin_txid: None,
            logs: Vec::new(),
            rollback_status: RollbackStatus::NotRolledback,
            inner_instructions_list: Vec::new(),
        };
        let processed_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "get_processed_transaction"
            })))
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": "test",
                    "result": processed
                })
                .to_string(),
            )
            .expect(2)
            .create_async()
            .await;

        let mut config = Config::localnet();
        config.arch_node_url = server.url();
        let deployer = ProgramDeployer::new(&config);
        let (program_keypair, _, _) = crate::generate_new_keypair(config.network);
        let (authority_keypair, _, _) = crate::generate_new_keypair(config.network);
        let program_pubkey = Pubkey::from_slice(&program_keypair.x_only_public_key().0.serialize());
        let authority_pubkey =
            Pubkey::from_slice(&authority_keypair.x_only_public_key().0.serialize());
        let elf = vec![42; extend_bytes_max_len() * MAX_TX_BATCH_SIZE + 1];

        deployer
            .send_elf_chunks(program_pubkey, authority_pubkey, authority_keypair, &elf)
            .await
            .unwrap();

        blockhash_mock.assert_async().await;
        send_mock.assert_async().await;
        processed_mock.assert_async().await;
    }
}
