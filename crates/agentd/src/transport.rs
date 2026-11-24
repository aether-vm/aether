//! Permission-hardened Unix Domain Socket (`0600`) gRPC transport for `agentd`.
//!
//! Security redline (`AGENTS.md` §5, `ARCHITECTURE_V2.md` §7.5):
//! `agentd` listens **exclusively** on a local Unix Domain Socket with `0600` permissions inside
//! a `0700` parent directory. TCP listening is intentionally omitted from `agentd`.

#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::Result;

use crate::service::AgentdService;

/// Default production UDS path for `agentd`.
pub const DEFAULT_SOCKET_PATH: &str = "/run/forkloom/agentd.sock";

/// Bind a permission-hardened (`0600`) Unix Domain Socket and serve `forkloom.v1` gRPC until
/// `shutdown` completes (Unix/Linux only).
#[cfg(unix)]
pub async fn serve_uds<F>(
    socket_path: &Path,
    service: AgentdService,
    shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    use anyhow::{bail, ensure, Context};
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::transport::Server;

    use crate::proto::frame_service_server::FrameServiceServer;
    use crate::proto::system_service_server::SystemServiceServer;
    use crate::proto::world_service_server::WorldServiceServer;

    let parent = socket_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .context("socket path must have a parent directory")?;
    if let Ok(md) = fs::symlink_metadata(parent) {
        ensure!(
            !md.file_type().is_symlink(),
            "refusing to use symlinked socket parent directory {}",
            parent.display()
        );
    }
    fs::create_dir_all(parent)
        .with_context(|| format!("create socket parent dir {}", parent.display()))?;
    let parent_md = fs::symlink_metadata(parent)
        .with_context(|| format!("stat socket parent dir {}", parent.display()))?;
    ensure!(
        !parent_md.file_type().is_symlink(),
        "refusing to use symlinked socket parent directory {}",
        parent.display()
    );
    ensure!(
        parent_md.file_type().is_dir(),
        "socket parent path {} is not a directory",
        parent.display()
    );
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", parent.display()))?;

    // Refuse symlink attacks and live-daemon socket clobbering.
    if let Ok(md) = fs::symlink_metadata(socket_path) {
        ensure!(
            !md.file_type().is_symlink(),
            "refusing to bind over symlink at {}",
            socket_path.display()
        );
        ensure!(
            md.file_type().is_socket(),
            "refusing to remove non-socket file at {}",
            socket_path.display()
        );
        if std::os::unix::net::UnixStream::connect(socket_path).is_ok() {
            bail!(
                "another agentd instance is already listening on {}",
                socket_path.display()
            );
        }
        fs::remove_file(socket_path)
            .with_context(|| format!("remove stale socket {}", socket_path.display()))?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind Unix socket {}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", socket_path.display()))?;

    // Verify exact 0600 permissions before accepting connections.
    let mode = fs::symlink_metadata(socket_path)?.permissions().mode() & 0o777;
    ensure!(
        mode == 0o600,
        "socket {} mode is {:04o}, expected 0600",
        socket_path.display(),
        mode
    );

    let incoming = UnixListenerStream::new(listener);
    let serve_res = Server::builder()
        .add_service(SystemServiceServer::new(service.clone()))
        .add_service(FrameServiceServer::new(service.clone()))
        .add_service(WorldServiceServer::new(service))
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await;

    let _ = fs::remove_file(socket_path);
    serve_res.context("tonic UDS server failed")
}

/// Non-Unix stub: `agentd` strictly refuses to open TCP sockets; run the daemon on Linux.
#[cfg(not(unix))]
pub async fn serve_uds<F>(
    socket_path: &Path,
    _service: AgentdService,
    _shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    anyhow::bail!(
        "agentd UDS transport ({}) requires Linux/Unix; TCP listening is intentionally disabled",
        socket_path.display()
    )
}
