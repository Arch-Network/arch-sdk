use thiserror::Error;

#[derive(Error, Debug)]
pub enum SDKError {
    #[error("signing and sending transaction failed")]
    SignAndSendFailed,

    #[error("get processed transaction failed")]
    GetProcessedTransactionFailed,

    #[error("elf path cannot be found")]
    ElfPathNotFound,

    #[error("send transaction failed")]
    SendTransactionFailed,

    #[error("returned invalid response type")]
    InvalidResponseType,

    #[error(transparent)]
    Other(#[from] anyhow::Error), // source and Display delegate to anyhow::Error
}
