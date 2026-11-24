//! Driver abstraction (`SandboxDriver`) and live `WorldHandle`.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::time::Duration;

use aos_guest::ErrorCode;

use crate::config::{
    ExecOutputChunk, ExecReply, ExecRequest, FreezeOptions, FreezeReply, PingReply, SpawnWorldSpec,
    WorldInfo,
};
use crate::error::SandboxError;

/// Driver-specific backend for a running `World` held inside [`WorldHandle`].
pub trait WorldBackend: Send {
    fn info(&self) -> &WorldInfo;

    fn ping(&mut self, nonce: u64) -> Result<PingReply, SandboxError>;

    fn exec_streaming(
        &mut self,
        req: ExecRequest,
        on_chunk: &mut dyn FnMut(ExecOutputChunk),
    ) -> Result<ExecReply, SandboxError>;

    fn freeze_and_sync(&mut self, opts: FreezeOptions) -> Result<FreezeReply, SandboxError>;

    /// Unfreeze a previously frozen `World` (e.g. after `TreeStore::snapshot_readonly`
    /// during `agentd`'s `Checkpoint` flow) so execution can resume cleanly.
    ///
    /// Returns [`SandboxError::GuestError`] with [`ErrorCode::InvalidStateTransition`]
    /// if the world is not currently frozen.
    fn unfreeze(&mut self, timeout: Duration) -> Result<(), SandboxError>;

    /// Deterministically terminate all sandbox processes (`cgroup.kill`), reap child,
    /// and clean up cgroup/netns resources. Must be idempotent.
    fn destroy(&mut self) -> Result<(), SandboxError>;
}

/// Trait implemented by sandbox runtime drivers (`NamespaceDriver` in Phase 1;
/// `FirecrackerDriver` in Phase 2).
pub trait SandboxDriver {
    fn driver_name(&self) -> &'static str;

    /// Spawn a hardened `World`, verify the initial `aos-guest` `Ping -> Pong` handshake,
    /// and return a live [`WorldHandle`].
    fn spawn_world(&self, spec: SpawnWorldSpec) -> Result<WorldHandle, SandboxError>;
}

/// Owning handle to a running sandboxed `World`.
///
/// Guarantees deterministic teardown on [`WorldHandle::destroy`] or `Drop`.
pub struct WorldHandle {
    backend: Box<dyn WorldBackend>,
    destroyed: bool,
}

impl WorldHandle {
    pub fn from_backend(backend: Box<dyn WorldBackend>) -> Self {
        Self {
            backend,
            destroyed: false,
        }
    }

    pub fn info(&self) -> &WorldInfo {
        self.backend.info()
    }

    pub fn is_destroyed(&self) -> bool {
        self.destroyed
    }

    fn ensure_alive(&self) -> Result<(), SandboxError> {
        if self.destroyed {
            Err(SandboxError::WorldDestroyed)
        } else {
            Ok(())
        }
    }

    pub fn ping(&mut self, nonce: u64) -> Result<PingReply, SandboxError> {
        self.ensure_alive()?;
        self.backend.ping(nonce)
    }

    pub fn exec(&mut self, mut req: ExecRequest) -> Result<ExecReply, SandboxError> {
        self.ensure_alive()?;
        req.stream = false;
        self.backend.exec_streaming(req, &mut |_| {})
    }

    pub fn exec_streaming<F>(
        &mut self,
        mut req: ExecRequest,
        mut on_chunk: F,
    ) -> Result<ExecReply, SandboxError>
    where
        F: FnMut(ExecOutputChunk),
    {
        self.ensure_alive()?;
        req.stream = true;
        self.backend.exec_streaming(req, &mut on_chunk)
    }

    pub fn freeze_and_sync(&mut self, opts: FreezeOptions) -> Result<FreezeReply, SandboxError> {
        self.ensure_alive()?;
        self.backend.freeze_and_sync(opts)
    }

    /// Unfreeze a frozen world so execution can resume after snapshot capture.
    pub fn unfreeze(&mut self, timeout: Duration) -> Result<(), SandboxError> {
        self.ensure_alive()?;
        self.backend.unfreeze(timeout)
    }

    /// Deterministically tear down the world (`cgroup.kill` + reap + cleanup).
    /// Idempotent if called more than once.
    pub fn destroy(&mut self) -> Result<(), SandboxError> {
        if self.destroyed {
            return Ok(());
        }
        self.destroyed = true;
        self.backend.destroy()
    }
}

impl Drop for WorldHandle {
    fn drop(&mut self) {
        if !self.destroyed {
            self.destroyed = true;
            let _ = self.backend.destroy();
        }
    }
}

type UnfreezeHook = Box<dyn FnMut(Duration) -> Result<(), SandboxError> + Send>;

/// Generic [`WorldBackend`] adapter wrapping a [`crate::client::GuestRpcClient`] plus a
/// teardown hook (used by cross-platform mock/in-memory transports).
pub struct RpcWorldBackend<R, W, D> {
    info: WorldInfo,
    client: crate::client::GuestRpcClient<R, W>,
    on_unfreeze: Option<UnfreezeHook>,
    on_destroy: Option<D>,
}

impl<R, W, D> RpcWorldBackend<R, W, D>
where
    R: Read + Send,
    W: Write + Send,
    D: FnOnce() -> Result<(), SandboxError> + Send,
{
    pub fn new(
        info: WorldInfo,
        client: crate::client::GuestRpcClient<R, W>,
        on_destroy: D,
    ) -> Self {
        Self {
            info,
            client,
            on_unfreeze: None,
            on_destroy: Some(on_destroy),
        }
    }

    /// Attach a custom `unfreeze` handler for testing or host-controlled backends.
    pub fn with_unfreeze_hook<F>(mut self, hook: F) -> Self
    where
        F: FnMut(Duration) -> Result<(), SandboxError> + Send + 'static,
    {
        self.on_unfreeze = Some(Box::new(hook));
        self
    }
}

impl<R, W, D> WorldBackend for RpcWorldBackend<R, W, D>
where
    R: Read + Send,
    W: Write + Send,
    D: FnOnce() -> Result<(), SandboxError> + Send,
{
    fn info(&self) -> &WorldInfo {
        &self.info
    }

    fn ping(&mut self, nonce: u64) -> Result<PingReply, SandboxError> {
        self.client.ping(nonce)
    }

    fn exec_streaming(
        &mut self,
        req: ExecRequest,
        on_chunk: &mut dyn FnMut(ExecOutputChunk),
    ) -> Result<ExecReply, SandboxError> {
        self.client.exec_streaming(req, on_chunk)
    }

    fn freeze_and_sync(&mut self, opts: FreezeOptions) -> Result<FreezeReply, SandboxError> {
        self.client.freeze_and_sync(opts)
    }

    fn unfreeze(&mut self, timeout: Duration) -> Result<(), SandboxError> {
        if let Some(hook) = &mut self.on_unfreeze {
            return hook(timeout);
        }
        Err(SandboxError::GuestError {
            code: ErrorCode::InvalidStateTransition,
            message: "unfreeze is not configured on RpcWorldBackend".to_owned(),
        })
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        if let Some(f) = self.on_destroy.take() {
            f()?;
        }
        Ok(())
    }
}
