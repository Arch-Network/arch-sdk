use std::future::Future;
use std::sync::OnceLock;
use tokio::runtime::{Handle, Runtime, RuntimeFlavor};

/// Shared fallback runtime for sync callers outside a tokio context.
/// Lazily initialized on first use, lives for the process lifetime.
fn fallback_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().expect("Failed to create tokio runtime"))
}

/// Block on an async future from a sync context.
///
/// Outside Tokio, this uses a shared fallback runtime. Inside a multi-threaded
/// Tokio runtime it re-enters via `block_in_place`, and inside a current-thread
/// runtime it uses a dedicated worker thread with its own runtime to avoid the
/// `block_in_place` panic.
pub(crate) fn block_on<F, R>(f: F) -> R
where
    F: Future<Output = R> + Send,
    R: Send,
{
    if let Ok(handle) = Handle::try_current() {
        match handle.runtime_flavor() {
            RuntimeFlavor::CurrentThread => std::thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()
                        .expect("Failed to create tokio runtime")
                        .block_on(f)
                });

                match worker.join() {
                    Ok(result) => result,
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            }),
            _ => tokio::task::block_in_place(|| handle.block_on(f)),
        }
    } else {
        fallback_runtime().block_on(f)
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "current_thread")]
    async fn block_on_from_current_thread_runtime_does_not_panic() {
        let result = super::block_on(async { 42 });
        assert_eq!(result, 42);
    }
}
