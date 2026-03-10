use arch_program::pubkey::Pubkey;

use crate::helper::async_utxo::prepare_fees;
use crate::runtime::block_on;
use crate::ArchError;
use crate::Config;

use super::async_utxo::BitcoinHelper;

/// Blocking helper for Bitcoin operations.
///
/// Thin wrapper around the async [`BitcoinHelper`] using [`block_on`],
/// following the same pattern as [`crate::client::rpc::BlockingArchRpcClient`].
#[derive(Clone)]
pub struct BlockingBitcoinHelper {
    inner: BitcoinHelper,
}

impl BlockingBitcoinHelper {
    /// Create a new BlockingBitcoinHelper
    pub fn new(config: &Config) -> Result<Self, ArchError> {
        Ok(Self {
            inner: BitcoinHelper::new(config)?,
        })
    }

    /// Used to send a utxo to the taptweaked account address corresponding to the
    /// network's joint pubkey
    pub fn send_utxo(&self, pubkey: Pubkey) -> Result<(String, u32), String> {
        block_on(self.inner.send_utxo(pubkey))
    }

    pub fn wait_until_titan_indexes_transaction(&self, txid: &bitcoin::Txid) -> Result<(), String> {
        block_on(self.inner.wait_until_titan_indexes_transaction(txid))
    }
}

/// Blocking wrapper around the async [`prepare_fees`](super::async_utxo::prepare_fees).
pub fn blocking_prepare_fees() -> Result<String, ArchError> {
    block_on(prepare_fees())
}

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "current_thread")]
    async fn block_on_bridge_works_inside_current_thread_runtime() {
        let result = super::block_on(async { Ok::<_, String>(()) });
        assert_eq!(result, Ok(()));
    }
}
