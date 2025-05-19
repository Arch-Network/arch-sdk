use crate::pubkey::Pubkey;

/// A sanitized message that has been checked for validity and processed to improve
/// runtime performance.
///
/// This struct wraps an `ArchMessage` and provides additional caching of account
/// permissions for more efficient runtime access.
#[derive(Debug, Clone)]
pub struct SanitizedMessage {
    /// The underlying message containing instructions, account keys, and header information
    pub message: ArchMessage,
    /// List of boolean with same length as account_keys(), each boolean value indicates if
    /// corresponding account key is writable or not.
    pub is_writable_account_cache: Vec<bool>,
}

impl SanitizedMessage {
    /// Creates a new `SanitizedMessage` by processing the provided `ArchMessage`.
    ///
    /// This constructor will initialize the writable account cache for faster permission checks.
    ///
    /// # Arguments
    ///
    /// * `message` - The `ArchMessage` to wrap and process
    ///
    /// # Returns
    ///
    /// A new `SanitizedMessage` instance
    pub fn new(message: ArchMessage) -> Self {
        let is_writable_account_cache = message
            .account_keys
            .iter()
            .enumerate()
            .map(|(i, _key)| message.is_writable_index(i))
            .collect::<Vec<_>>();
        Self {
            message,
            is_writable_account_cache,
        }
    }

    /// Checks if the account at the given index is a signer.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the account in the account keys list
    ///
    /// # Returns
    ///
    /// `true` if the account is a signer, `false` otherwise
    pub fn is_signer(&self, index: usize) -> bool {
        self.message.is_signer(index)
    }

    /// Checks if the account at the given index is writable.
    ///
    /// This method uses the pre-computed writable account cache for efficiency.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the account in the account keys list
    ///
    /// # Returns
    ///
    /// `true` if the account is writable, `false` otherwise
    pub fn is_writable(&self, index: usize) -> bool {
        *self.is_writable_account_cache.get(index).unwrap_or(&false)
    }

    /// Returns a reference to the instructions in the message.
    ///
    /// # Returns
    ///
    /// A reference to the vector of `SanitizedInstruction`s
    pub fn instructions(&self) -> &Vec<SanitizedInstruction> {
        &self.message.instructions
    }
}

/// A message in the Arch Network that contains instructions to be executed,
/// account keys involved in the transaction, and metadata in the header.
#[derive(Debug, Clone)]
pub struct ArchMessage {
    /// Header containing metadata about the message
    pub header: MessageHeader,
    /// List of all account public keys used in this message
    pub account_keys: Vec<Pubkey>,
    /// List of instructions to execute
    pub instructions: Vec<SanitizedInstruction>,
}
impl ArchMessage {
    /// Returns true if the account at the specified index was requested to be
    /// writable. This method should not be used directly.
    ///
    /// # Arguments
    ///
    /// * `i` - The index of the account to check
    ///
    /// # Returns
    ///
    /// `true` if the account is writable, `false` otherwise
    pub(super) fn is_writable_index(&self, i: usize) -> bool {
        i < (self.header.num_required_signatures - self.header.num_readonly_signed_accounts)
            as usize
            || (i >= self.header.num_required_signatures as usize
                && i < self.account_keys.len()
                    - self.header.num_readonly_unsigned_accounts as usize)
    }

    /// Returns a reference to the message header.
    ///
    /// # Returns
    ///
    /// A reference to the `MessageHeader`
    pub fn header(&self) -> &MessageHeader {
        &self.header
    }

    /// Checks if the account at the given index is a signer.
    ///
    /// An account is a signer if its index is less than the number of required signatures
    /// specified in the message header.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the account in the account keys list
    ///
    /// # Returns
    ///
    /// `true` if the account is a signer, `false` otherwise
    pub fn is_signer(&self, index: usize) -> bool {
        index < usize::from(self.header().num_required_signatures)
    }
}

/// A sanitized instruction included in an `ArchMessage`.
///
/// This struct contains information about a single instruction including
/// the program to execute, the accounts to operate on, and the instruction data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SanitizedInstruction {
    /// The public key of the program that will process this instruction
    pub program_id: Pubkey,
    /// Ordered indices into the message's account keys, indicating which accounts
    /// this instruction will operate on
    pub accounts: Vec<u16>,
    /// The program-specific instruction data
    pub data: Vec<u8>,
}

/// The header of an `ArchMessage` that contains metadata about the message
/// and its authorization requirements.
#[derive(Debug, Clone)]
pub struct MessageHeader {
    /// The number of signatures required for this message to be considered
    /// valid
    pub num_required_signatures: u8,

    /// The last `num_readonly_signed_accounts` of the signed keys are read-only
    /// accounts.
    pub num_readonly_signed_accounts: u8,

    /// The last `num_readonly_unsigned_accounts` of the unsigned keys are
    /// read-only accounts.
    pub num_readonly_unsigned_accounts: u8,
}
