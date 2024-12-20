use crate::account::AccountMeta;
use crate::instruction::Instruction;
use crate::pubkey::Pubkey;
use crate::utxo::UtxoMeta;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SystemInstruction;

impl SystemInstruction {
    pub fn new_create_account_instruction(
        txid: [u8; 32],
        vout: u32,
        pubkey: Pubkey,
    ) -> Instruction {
        Instruction {
            program_id: Pubkey::system_program(),
            accounts: vec![AccountMeta {
                pubkey,
                is_signer: true,
                is_writable: true,
            }],
            data: [&[0][..], &UtxoMeta::from(txid, vout).serialize()].concat(),
        }
    }

    pub fn new_write_bytes_instruction(
        offset: u32,
        len: u32,
        data: Vec<u8>,
        pubkey: Pubkey,
    ) -> Instruction {
        Instruction {
            program_id: Pubkey::system_program(),
            accounts: vec![AccountMeta {
                pubkey,
                is_signer: true,
                is_writable: true,
            }],
            data: [
                &[1][..],
                offset.to_le_bytes().as_slice(),
                len.to_le_bytes().as_slice(),
                data.as_slice(),
            ]
            .concat(),
        }
    }

    pub fn new_deploy_instruction(pubkey: Pubkey) -> Instruction {
        Instruction {
            program_id: Pubkey::system_program(),
            accounts: vec![AccountMeta {
                pubkey,
                is_signer: true,
                is_writable: true,
            }],
            data: vec![2],
        }
    }

    pub fn new_assign_ownership_instruction(pubkey: Pubkey, owner: Pubkey) -> Instruction {
        Instruction {
            program_id: Pubkey::system_program(),
            accounts: vec![AccountMeta {
                pubkey,
                is_signer: true,
                is_writable: true,
            }],
            data: [&[3][..], owner.serialize().as_slice()].concat(),
        }
    }

    pub fn new_retract_instruction(pubkey: Pubkey) -> Instruction {
        Instruction {
            program_id: Pubkey::system_program(),
            accounts: vec![AccountMeta {
                pubkey,
                is_signer: true,
                is_writable: true,
            }],
            data: vec![4],
        }
    }

    pub fn new_truncate_instruction(pubkey: Pubkey, new_size: u32) -> Instruction {
        Instruction {
            program_id: Pubkey::system_program(),
            accounts: vec![AccountMeta {
                pubkey,
                is_signer: true,
                is_writable: true,
            }],
            data: [&[5][..], new_size.to_le_bytes().as_slice()].concat(),
        }
    }
}
