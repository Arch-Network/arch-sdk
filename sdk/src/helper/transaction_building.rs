use crate::{
    arch_program::pubkey::Pubkey,
    types::{RuntimeTransaction, Signature},
};
use arch_program::{instruction::Instruction, message::Message};
use bitcoin::{key::Keypair, XOnlyPublicKey};

use super::sign_message_bip322;

/* -------------------------------------------------------------------------- */
/*                   BUILDS A TRANSACTION FROM INSTRUCTIONS                   */
/* -------------------------------------------------------------------------- */
/// Builds a runtime transaction given a set of instructions.
pub fn build_transaction(
    signer_key_pairs: Vec<Keypair>,
    instructions: Vec<Instruction>,
    network: bitcoin::Network,
) -> RuntimeTransaction {
    let pubkeys = signer_key_pairs
        .iter()
        .map(|signer| Pubkey::from_slice(&XOnlyPublicKey::from_keypair(signer).0.serialize()))
        .collect::<Vec<Pubkey>>();

    let message = Message {
        signers: pubkeys,
        instructions,
    };

    let digest_slice = message.hash();

    let signatures = signer_key_pairs
        .iter()
        .map(|signer| {
            let signature = sign_message_bip322(signer, &digest_slice, network).to_vec();
            Signature(signature)
        })
        .collect::<Vec<Signature>>();

    RuntimeTransaction {
        version: 0,
        signatures,
        message,
    }
}
