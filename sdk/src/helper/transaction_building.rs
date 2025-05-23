use crate::{RuntimeTransaction, Signature};

use super::sign_message_bip322;
use arch_program::sanitized::ArchMessage;
use bitcoin::{key::Keypair, Network};

/// Sign and send a transaction
pub fn build_and_sign_transaction(
    message: ArchMessage,
    signers: Vec<Keypair>,
    bitcoin_network: Network,
) -> RuntimeTransaction {
    let digest_slice = message.hash();
    let signatures = message
        .account_keys
        .iter()
        .take(message.header.num_required_signatures as usize)
        .map(|key| {
            let signature = sign_message_bip322(
                signers
                    .iter()
                    .find(|signer| signer.x_only_public_key().0.serialize() == key.serialize())
                    .unwrap(),
                &digest_slice,
                bitcoin_network,
            )
            .to_vec();
            Signature(signature)
        })
        .collect::<Vec<Signature>>();

    RuntimeTransaction {
        version: 0,
        signatures,
        message,
    }
}
