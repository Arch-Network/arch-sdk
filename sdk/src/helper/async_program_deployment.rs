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
        let recent_blockhash = self.client.get_best_finalized_block_hash().await?;
        let chunk_size = extend_bytes_max_len();
        let num_chunks = elf.chunks(chunk_size).len();

        debug!(
            program = %program_pubkey,
            chunks = num_chunks,
            blockhash = %recent_blockhash,
            "Building ELF write transactions"
        );

        let txs = elf
            .chunks(chunk_size)
            .enumerate()
            .map(|(i, chunk)| {
                let offset: u32 = (i * chunk_size) as u32;
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

        let pb = ProgressBar::new(txs.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] Sending ELF [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )
                .expect("Failed to set progress bar style")
                .progress_chars("#>-"),
        );

        let batches = txs
            .chunks(MAX_TX_BATCH_SIZE)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<Vec<RuntimeTransaction>>>();

        let mut tx_ids = Vec::new();
        for batch in batches {
            let ids = self.client.send_transactions(batch).await?;
            tx_ids.extend(ids);
        }

        debug!(
            program = %program_pubkey,
            sent = tx_ids.len(),
            "Waiting for ELF write confirmations"
        );

        for (i, tx_id) in tx_ids.iter().enumerate() {
            let processed_tx = self.client.wait_for_processed_transaction(tx_id).await?;
            if let Status::Failed(reason) = processed_tx.status {
                let offset = (i * chunk_size) as u32;
                return Err(ProgramDeployerError::ElfWriteFailed {
                    txid: *tx_id,
                    offset,
                    reason,
                });
            }
            pb.inc(1);
        }

        pb.finish_with_message("ELF write transactions confirmed");
        Ok(())
    }
}

/// Returns the remaining space in an account's data storage
pub fn extend_bytes_max_len() -> usize {
    let message = ArchMessage::new(
        &[loader_instruction::write(
            Pubkey::system_program(),
            Pubkey::system_program(),
            0,
            vec![0_u8; 256],
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
