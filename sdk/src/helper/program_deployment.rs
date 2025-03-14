use arch_program::{instruction::Instruction, message::Message};
use bitcoin::{key::Keypair, Network};
use indicatif::{ProgressBar, ProgressStyle};
use tracing::debug;

use std::fs;

use crate::{
    helper::{utxo::BitcoinHelper, with_secret_key_file},
    types::{RuntimeTransaction, Signature, RUNTIME_TX_SIZE_LIMIT},
    Status,
};

use crate::arch_program::pubkey::Pubkey;
use crate::arch_program::system_instruction;

use crate::client::ArchError;
use crate::client::ArchRpcClient;
use crate::helper::transaction_building::build_transaction;

/* -------------------------------------------------------------------------- */
/*                               ERROR HANDLING                               */
/* -------------------------------------------------------------------------- */
/// Error type for program deployment operations
#[derive(Debug, thiserror::Error)]
pub enum ProgramDeployerError {
    /// Error reading or processing the ELF file
    #[error("ELF file error: {0}")]
    ElfFileError(String),
    /// Error with the program keypair file
    #[error("Keypair error: {0}")]
    KeypairError(String),
    /// Error sending UTXO to create program account
    #[error("UTXO error: {0}")]
    UtxoError(String),
    /// Error interacting with the Arch blockchain
    #[error("Arch blockchain error: {0}")]
    ArchError(#[from] ArchError),
    /// Error when verifying deployed program
    #[error("Verification error: {0}")]
    VerificationError(String),
    /// Error when deploying program chunks
    #[error("Deployment error: {0}")]
    DeploymentError(String),
    /// Error when building or sending transactions
    #[error("Transaction error: {0}")]
    TransactionError(String),
    /// Generic error that doesn't fit other categories
    #[error("Error: {0}")]
    Other(String),
}

impl From<std::io::Error> for ProgramDeployerError {
    fn from(err: std::io::Error) -> Self {
        ProgramDeployerError::ElfFileError(format!("I/O error: {}", err))
    }
}

/* -------------------------------------------------------------------------- */
/*                             PROGRAM DEPLOYMENT                             */
/* -------------------------------------------------------------------------- */
/// Configuration for program deployment
#[derive(Debug)]
pub struct DeploymentConfig {
    /// URL of the Arch node
    pub node_url: String,
    /// Bitcoin network to use (Mainnet, Testnet, Regtest)
    pub bitcoin_network: Network,
    /// Path to the program's secret key file
    pub program_file_path: String,
    /// Path to the ELF file
    pub elf_path: String,
    /// Name of the program (for display purposes)
    pub program_name: String,
    /// Bitcoin node endpoint URL
    pub bitcoin_node_endpoint: String,
    /// Bitcoin node username
    pub bitcoin_node_username: String,
    /// Bitcoin node password
    pub bitcoin_node_password: String,
}

impl DeploymentConfig {
    /// Create a new deployment configuration
    pub fn new(
        node_url: String,
        bitcoin_network: Network,
        program_file_path: String,
        elf_path: String,
        program_name: String,
        bitcoin_node_endpoint: String,
        bitcoin_node_username: String,
        bitcoin_node_password: String,
    ) -> Self {
        Self {
            node_url,
            bitcoin_network,
            program_file_path,
            elf_path,
            program_name,
            bitcoin_node_endpoint,
            bitcoin_node_username,
            bitcoin_node_password,
        }
    }
}

/// Program deployment service
pub struct ProgramDeployer {
    config: DeploymentConfig,
    client: ArchRpcClient,
    bitcoin_helper: BitcoinHelper,
}

impl ProgramDeployer {
    /// Create a new program deployer
    pub fn new(config: DeploymentConfig) -> Self {
        let client = ArchRpcClient::new(&config.node_url);
        let bitcoin_helper = BitcoinHelper::new(
            config.bitcoin_node_endpoint.clone(),
            config.bitcoin_node_username.clone(),
            config.bitcoin_node_password.clone(),
            config.bitcoin_network,
            config.node_url.clone(),
        );

        Self {
            config,
            client,
            bitcoin_helper,
        }
    }

    /// Try to deploy a program
    pub fn try_deploy_program(&self) -> Result<Pubkey, ProgramDeployerError> {
        print_title(
            &format!("PROGRAM DEPLOYMENT {}", self.config.program_name),
            5,
        );

        let (program_keypair, program_pubkey) =
            with_secret_key_file(&self.config.program_file_path)
                .map_err(|e| ProgramDeployerError::KeypairError(e.to_string()))?;

        let elf = fs::read(&self.config.elf_path).map_err(|e| {
            ProgramDeployerError::ElfFileError(format!("Failed to read ELF file: {}", e))
        })?;

        // Check if the program is already deployed with the same code
        if let Ok(account_info) = self.client.read_account_info(program_pubkey) {
            if account_info.data == elf {
                println!("\x1b[33m Same program already deployed! Skipping deployment. \x1b[0m");
                print_title(
                    &format!(
                        "PROGRAM DEPLOYMENT : OK Program account : {:?} !",
                        program_pubkey.0
                    ),
                    5,
                );
                return Ok(program_pubkey);
            }
            println!("\x1b[33m ELF mismatch with account content! Redeploying \x1b[0m");
        }

        // Step 1: Send UTXO to create program account
        let (deploy_utxo_btc_txid, deploy_utxo_vout) = self
            .send_utxo(program_pubkey)
            .map_err(|e| ProgramDeployerError::UtxoError(e.to_string()))?;

        println!(
            "\x1b[32m Step 1/4 Successful :\x1b[0m BTC Transaction for program account UTXO successfully sent : {} -- vout : {}",
            deploy_utxo_btc_txid, deploy_utxo_vout
        );

        // Step 2: Create account
        let create_account_tx = self.sign_and_send_instruction(
            system_instruction::create_account(
                hex::decode(&deploy_utxo_btc_txid)
                    .map_err(|e| {
                        ProgramDeployerError::TransactionError(format!(
                            "Failed to decode hex: {}",
                            e
                        ))
                    })?
                    .try_into()
                    .map_err(|_| {
                        ProgramDeployerError::TransactionError(format!(
                            "Failed to convert to array: {}",
                            deploy_utxo_btc_txid.to_string()
                        ))
                    })?,
                deploy_utxo_vout,
                program_pubkey,
            ),
            vec![program_keypair.clone()],
        )?;

        let tx = self
            .client
            .wait_for_processed_transaction(&create_account_tx)?;

        match tx.status {
            Status::Failed(e) => {
                return Err(ProgramDeployerError::TransactionError(format!(
                    "Program account creation transaction failed: {}",
                    e.to_string()
                )));
            }
            _ => {}
        }

        println!(
            "\x1b[32m Step 2/4 Successful :\x1b[0m Program account creation transaction successfully processed! Tx Id: {}",
            create_account_tx
        );

        // Step 3: Deploy program ELF
        self.deploy_program_elf(program_keypair.clone(), program_pubkey, &elf)?;

        // Step 4: Make program executable
        let executability_txid = self.sign_and_send_instruction(
            system_instruction::deploy(program_pubkey),
            vec![program_keypair],
        )?;

        self.client
            .wait_for_processed_transaction(&executability_txid)?;

        let program_info_after_making_executable = self.client.read_account_info(program_pubkey)?;

        assert!(
            program_info_after_making_executable.data == elf,
            "ELF content verification failed: deployed program data doesn't match local ELF file"
        );

        debug!(
            "Current Program Account {:x}: \n   Owner : {:x}, \n   Data length : {} Bytes,\n   Anchoring UTXO : {}, \n   Executable? : {}",
            program_pubkey,
            program_info_after_making_executable.owner,
            program_info_after_making_executable.data.len(),
            program_info_after_making_executable.utxo,
            program_info_after_making_executable.is_executable
        );

        println!("\x1b[32m Step 4/4 Successful :\x1b[0m Made program account executable!");

        print_title(
            &format!(
                "PROGRAM DEPLOYMENT : OK Program account : {:?} !",
                program_pubkey.0
            ),
            5,
        );

        Ok(program_pubkey)
    }

    /// Send a UTXO to create a program account
    fn send_utxo(&self, program_pubkey: Pubkey) -> Result<(String, u32), ProgramDeployerError> {
        // Use the BitcoinHelper to send the UTXO
        self.bitcoin_helper
            .send_utxo(program_pubkey)
            .map_err(|e| ProgramDeployerError::UtxoError(format!("Failed to send UTXO: {}", e)))
    }

    /// Sign and send an instruction
    fn sign_and_send_instruction(
        &self,
        instruction: Instruction,
        signers: Vec<Keypair>,
    ) -> Result<String, ProgramDeployerError> {
        // Build the transaction
        let transaction =
            build_transaction(signers, vec![instruction], self.config.bitcoin_network);

        // Send the transaction
        let tx_id = self.client.send_transaction(transaction).map_err(|e| {
            ProgramDeployerError::TransactionError(format!("Failed to send transaction: {}", e))
        })?;

        // Wait for the transaction to be processed
        self.client
            .wait_for_processed_transaction(&tx_id)
            .map_err(|e| {
                ProgramDeployerError::TransactionError(format!(
                    "Failed to process transaction: {}",
                    e
                ))
            })?;

        Ok(tx_id)
    }

    /// Deploy a program ELF
    fn deploy_program_elf(
        &self,
        program_keypair: Keypair,
        program_pubkey: Pubkey,
        elf: &[u8],
    ) -> Result<(), ProgramDeployerError> {
        let account_info = self.client.read_account_info(program_pubkey)?;

        println!("Account info : {:?}", account_info);

        if account_info.is_executable {
            let instruction = system_instruction::retract(program_pubkey);
            let tx_id = self.sign_and_send_instruction(instruction, vec![program_keypair])?;
            self.client.wait_for_processed_transaction(&tx_id)?;
        }

        if account_info.data.len() > elf.len() {
            let instruction = system_instruction::truncate(program_pubkey, elf.len() as u32);
            let tx_id = self.sign_and_send_instruction(instruction, vec![program_keypair])?;
            self.client.wait_for_processed_transaction(&tx_id)?;
        }

        let txs: Vec<RuntimeTransaction> = elf
            .chunks(extend_bytes_max_len())
            .enumerate()
            .map(|(i, chunk)| {
                let offset: u32 = (i * extend_bytes_max_len()) as u32;
                let len: u32 = chunk.len() as u32;

                let instruction =
                    system_instruction::write_bytes(offset, len, chunk.to_vec(), program_pubkey);

                build_transaction(
                    vec![program_keypair.clone()],
                    vec![instruction],
                    self.config.bitcoin_network,
                )
            })
            .collect();

        let pb = ProgressBar::new(txs.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )
                .expect("Failed to set progress bar style")
                .progress_chars("#>-"),
        );

        pb.set_message("Successfully Processed Deployment Transactions :");

        let tx_ids = self.client.send_transactions(txs)?;

        for tx_id in tx_ids.iter() {
            self.client.wait_for_processed_transaction(tx_id)?;
            pb.inc(1);
        }

        pb.finish_with_message("Successfully Processed Deployment Transactions");

        Ok(())
    }
}

/// Print a title with decorative formatting
fn print_title(title: &str, length: usize) {
    let dec = "=".repeat(length);
    println!("\n{} {} {}\n", dec, title, dec);
}

/// Returns the remaining space in an account's data storage
fn extend_bytes_max_len() -> usize {
    let message = Message {
        signers: vec![Pubkey::system_program()],
        instructions: vec![system_instruction::write_bytes(
            0,
            0,
            vec![0_u8; 8],
            Pubkey::system_program(),
        )],
    };

    RUNTIME_TX_SIZE_LIMIT
        - RuntimeTransaction {
            version: 0,
            signatures: vec![Signature([0_u8; 64].to_vec())],
            message,
        }
        .serialize()
        .len()
}
