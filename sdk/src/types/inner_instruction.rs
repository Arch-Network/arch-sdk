use arch_program::sanitized::SanitizedInstruction;
use bitcode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Clone,
    PartialEq,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Encode,
    Decode,
    Eq,
)]
pub struct InnerInstruction {
    pub instruction: SanitizedInstruction,
    /// Invocation stack height of this instruction. Instruction stack height
    /// starts at 1 for transaction instructions.
    pub stack_height: u8,
}

/// An ordered list of compiled instructions that were invoked during a
/// transaction instruction
pub type InnerInstructions = Vec<InnerInstruction>;

/// A list of compiled instructions that were invoked during each instruction of
/// a transaction
pub type InnerInstructionsList = Vec<InnerInstructions>;
