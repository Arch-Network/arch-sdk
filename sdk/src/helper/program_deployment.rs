use crate::arch_program::pubkey::Pubkey;
use crate::client::runtime::block_on;
use crate::client::ArchError;
use crate::helper::async_program_deployment::ProgramDeployer;
use crate::Config;
use arch_program::bpf_loader::LoaderState;
use arch_program::hash::Hash;
use arch_program::hash::HashError;
use arch_program::instruction::InstructionError;
use bitcoin::key::Keypair;

/// Error type for program deployment operations
#[derive(Debug, thiserror::Error)]
pub enum ProgramDeployerError {
    #[error("failed to read ELF file '{path}'")]
    ElfReadError {
        path: String,
        source: std::io::Error,
    },

    #[error("account creation transaction failed (tx {txid}): {reason}")]
    AccountCreationFailed { txid: Hash, reason: String },

    #[error("ELF write transaction failed at offset {offset} (tx {txid}): {reason}")]
    ElfWriteFailed {
        txid: Hash,
        offset: u32,
        reason: String,
    },

    #[error("make-executable transaction failed (tx {txid}): {reason}")]
    MakeExecutableFailed { txid: Hash, reason: String },

    #[error("deployed ELF content does not match local file for program {program}")]
    ElfMismatch { program: Pubkey },

    #[error("program {program} is not executable after deployment")]
    NotExecutable { program: Pubkey },

    #[error(transparent)]
    Arch(#[from] ArchError),

    #[error(transparent)]
    Hash(#[from] HashError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn get_state(data: &[u8]) -> Result<&LoaderState, InstructionError> {
    unsafe {
        let data = data
            .get(0..LoaderState::program_data_offset())
            .ok_or(InstructionError::AccountDataTooSmall)?
            .try_into()
            .map_err(|_| InstructionError::AccountDataTooSmall)?;
        Ok(std::mem::transmute::<
            &[u8; LoaderState::program_data_offset()],
            &LoaderState,
        >(data))
    }
}

/// Blocking program deployment service.
///
/// Thin wrapper around the async [`ProgramDeployer`] using [`block_on`],
/// following the same pattern as [`crate::client::rpc::BlockingArchRpcClient`].
pub struct BlockingProgramDeployer {
    inner: ProgramDeployer,
}

impl BlockingProgramDeployer {
    /// Create a new blocking program deployer
    pub fn new(config: &Config) -> Self {
        Self {
            inner: ProgramDeployer::new(config),
        }
    }

    /// Try to deploy a program
    pub fn try_deploy_program(
        &self,
        program_name: String,
        program_keypair: Keypair,
        authority_keypair: Keypair,
        elf_path: &String,
    ) -> Result<Pubkey, ProgramDeployerError> {
        block_on(self.inner.try_deploy_program(
            program_name,
            program_keypair,
            authority_keypair,
            elf_path,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockingProgramDeployer, ProgramDeployerError};
    use crate::{generate_new_keypair, Config};

    #[tokio::test(flavor = "current_thread")]
    async fn try_deploy_program_returns_elf_error_inside_current_thread_runtime() {
        let config = Config::localnet();
        let deployer = BlockingProgramDeployer::new(&config);
        let (program_keypair, _, _) = generate_new_keypair(config.network);
        let (authority_keypair, _, _) = generate_new_keypair(config.network);
        let elf_path = "/tmp/does-not-exist-program.so".to_string();

        let result = deployer.try_deploy_program(
            "test".to_string(),
            program_keypair,
            authority_keypair,
            &elf_path,
        );

        match result {
            Err(ProgramDeployerError::ElfReadError { path, .. }) => assert_eq!(path, elf_path),
            other => panic!("expected ElfReadError, got {other:?}"),
        }
    }
}
