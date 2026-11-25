//! `aos`: thin gRPC-over-UDS CLI client for Forkloom `agentd`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

use aos_cli::client::{connect_uds, format_status, parse_label_kv};
use aos_cli::proto::frame_service_client::FrameServiceClient;
use aos_cli::proto::system_service_client::SystemServiceClient;
use aos_cli::proto::world_service_client::WorldServiceClient;
use aos_cli::proto::{
    self, AdvanceTimelineRequest, CheckpointRequest, CreateWorldRequest, DeleteFrameRequest,
    DeleteTimelineRequest, DestroyWorldRequest, DriverKind, ExecRequest, ExportPatchRequest,
    FencingToken, FrameDurability, GetFrameRequest, GetWorldRequest, IdempotencyKey,
    ImportTarHeader, ImportTarRequest, ListFramesRequest, NegotiateVersionRequest,
    OutputStreamKind, PinFrameRequest, PinSpec, RenewPinRequest, RenewWorldLeaseRequest,
};
use aos_cli::{DEFAULT_SOCKET_PATH, SUPPORTED_API_MAJOR};

#[derive(Parser, Debug)]
#[command(
    name = "aos",
    version,
    about = "Forkloom CLI (gRPC over local 0600 Unix Domain Socket)"
)]
struct Cli {
    /// Path to agentd Unix Domain Socket.
    #[arg(long, global = true, env = "FORKLOOM_SOCKET", default_value = DEFAULT_SOCKET_PATH)]
    socket: PathBuf,
    /// Caller owner identity for ACL & idempotency keys.
    #[arg(long, global = true, env = "FORKLOOM_OWNER", default_value = "default")]
    owner: String,
    /// Emit JSON output instead of human-readable text.
    #[arg(long, global = true, default_value_t = false)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliDurability {
    Durable,
    Volatile,
}

impl From<CliDurability> for FrameDurability {
    fn from(v: CliDurability) -> Self {
        match v {
            CliDurability::Durable => Self::Durable,
            CliDurability::Volatile => Self::Volatile,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliDriver {
    Namespace,
    Firecracker,
}

impl From<CliDriver> for DriverKind {
    fn from(v: CliDriver) -> Self {
        match v {
            CliDriver::Namespace => Self::Namespace,
            CliDriver::Firecracker => Self::Firecracker,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Negotiate protocol version and display daemon epoch & enabled drivers.
    Version,
    /// Manage immutable Frames (import, list, get, pin, delete, patch).
    Frame {
        #[command(subcommand)]
        sub: FrameCmd,
    },
    /// Manage durable Timelines (advance, delete).
    Timeline {
        #[command(subcommand)]
        sub: TimelineCmd,
    },
    /// Manage stateful sandbox Worlds (create, get, fence, lease, exec, checkpoint, destroy).
    World {
        #[command(subcommand)]
        sub: WorldCmd,
    },
}

#[derive(Subcommand, Debug)]
enum FrameCmd {
    /// Stream a USTAR tar archive into a new immutable Frame.
    Import {
        /// Path to the `.tar` archive to stream.
        tar_path: PathBuf,
        #[arg(long, value_enum, default_value_t = CliDurability::Durable)]
        durability: CliDurability,
        #[arg(long, default_value = "")]
        parent: String,
        #[arg(long = "label", value_parser = parse_label_kv)]
        labels: Vec<(String, String)>,
        #[arg(long)]
        pin_id: Option<String>,
        #[arg(long, default_value_t = 3_600_000)]
        pin_ttl_ms: u64,
        #[arg(long, default_value = "")]
        timeline: String,
        #[arg(long, default_value = "")]
        expected_old: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    /// List frames owned by `--owner` (or all if `--all-owners`).
    List {
        #[arg(long, default_value_t = false)]
        all_owners: bool,
        #[arg(long = "label", value_parser = parse_label_kv)]
        labels: Vec<(String, String)>,
        #[arg(long, default_value_t = false)]
        include_non_committed: bool,
    },
    /// Inspect one frame by ID.
    Get { frame_id: String },
    /// Attach a leased pin hold to a frame.
    Pin {
        frame_id: String,
        #[arg(long)]
        pin_id: String,
        #[arg(long, default_value_t = 3_600_000)]
        ttl_ms: u64,
    },
    /// Renew an existing pin lease.
    RenewPin {
        frame_id: String,
        #[arg(long)]
        pin_id: String,
    },
    /// Delete a frame (or defer reclaim while holds remain).
    Delete {
        frame_id: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Export a zero-trust validated unified diff patch between frames.
    Patch {
        target_frame_id: String,
        #[arg(long, default_value = "")]
        base: String,
    },
}

#[derive(Subcommand, Debug)]
enum TimelineCmd {
    /// Atomically CAS-advance a durable timeline head.
    Advance {
        name: String,
        #[arg(long)]
        head: String,
        #[arg(long, default_value = "")]
        expected_old: String,
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Delete a timeline and release its head hold.
    Delete {
        name: String,
        #[arg(long)]
        request_id: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum WorldCmd {
    /// Spawn a new stateful World from a committed base Frame.
    Create {
        #[arg(long)]
        base: String,
        #[arg(long, value_enum, default_value_t = CliDriver::Namespace)]
        driver: CliDriver,
        #[arg(long, default_value_t = 600_000)]
        lease_ttl_ms: u64,
        #[arg(long = "label", value_parser = parse_label_kv)]
        labels: Vec<(String, String)>,
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Inspect a World (active or Destroyed/Lost tombstone).
    Get { world_id: String },
    /// Take over ownership of a World, receiving a bumped monotonic fencing token.
    AcquireFence { world_id: String },
    /// Renew a World's in-memory monotonic lease.
    RenewLease {
        world_id: String,
        #[arg(long)]
        fence: u64,
    },
    /// Execute a command inside a World via `aos-guest`, streaming stdout/stderr live.
    Exec {
        world_id: String,
        #[arg(long)]
        fence: u64,
        #[arg(long, default_value = "")]
        cwd: String,
        #[arg(long, default_value_t = 60_000)]
        timeout_ms: u64,
        #[arg(long, default_value_t = 65_536)]
        max_output_bytes: u32,
        #[arg(long, default_value_t = false)]
        no_stream: bool,
        /// Start the command in the background; it runs until the World is destroyed.
        #[arg(long, default_value_t = false, conflicts_with = "timeout_ms")]
        detach: bool,
        #[arg(long)]
        request_id: Option<String>,
        /// Command and arguments (after `--`).
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    /// Capture a live World into a new immutable Frame.
    Checkpoint {
        world_id: String,
        #[arg(long)]
        fence: u64,
        #[arg(long, value_enum, default_value_t = CliDurability::Durable)]
        durability: CliDurability,
        #[arg(long = "label", value_parser = parse_label_kv)]
        labels: Vec<(String, String)>,
        #[arg(long)]
        pin_id: Option<String>,
        #[arg(long, default_value_t = 3_600_000)]
        pin_ttl_ms: u64,
        #[arg(long, default_value = "")]
        timeline: String,
        #[arg(long, default_value = "")]
        expected_old: String,
        #[arg(long, default_value_t = false)]
        no_syncfs: bool,
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Destroy a World and release its base-frame hold.
    Destroy {
        world_id: String,
        #[arg(long)]
        fence: u64,
        #[arg(long)]
        request_id: Option<String>,
    },
}

fn make_idem(owner: &str, request_id: Option<String>) -> Option<IdempotencyKey> {
    request_id.map(|id| IdempotencyKey {
        owner: owner.to_owned(),
        request_id: id,
    })
}

fn make_pin(owner: &str, pin_id: Option<String>, ttl_ms: u64) -> Option<PinSpec> {
    pin_id.map(|id| PinSpec {
        pin_id: id,
        owner: owner.to_owned(),
        lease_ttl_ms: ttl_ms,
    })
}

fn labels_map(pairs: Vec<(String, String)>) -> HashMap<String, String> {
    pairs.into_iter().collect()
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let channel = connect_uds(&cli.socket).await?;

    match cli.cmd {
        Cmd::Version => {
            let mut c = SystemServiceClient::new(channel);
            let resp = c
                .negotiate_version(NegotiateVersionRequest {
                    client_name: "aos-cli".into(),
                    client_version: env!("CARGO_PKG_VERSION").into(),
                    supported_api_major: SUPPORTED_API_MAJOR,
                })
                .await
                .map_err(|s| anyhow!("{}", format_status(&s)))?
                .into_inner();
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "daemon_version": resp.daemon_version,
                        "api_major": resp.api_major,
                        "api_minor": resp.api_minor,
                        "daemon_epoch": resp.daemon_epoch,
                        "enabled_drivers": resp.enabled_drivers,
                    }))?
                );
            } else {
                println!(
                    "agentd {} (api v{}.{}, epoch {}, drivers: [{}])",
                    resp.daemon_version,
                    resp.api_major,
                    resp.api_minor,
                    resp.daemon_epoch,
                    resp.enabled_drivers.join(", ")
                );
            }
        }
        Cmd::Frame { sub } => {
            let mut c = FrameServiceClient::new(channel);
            match sub {
                FrameCmd::Import {
                    tar_path,
                    durability,
                    parent,
                    labels,
                    pin_id,
                    pin_ttl_ms,
                    timeline,
                    expected_old,
                    request_id,
                } => {
                    let mut file = File::open(&tar_path)
                        .await
                        .with_context(|| format!("open {}", tar_path.display()))?;
                    let (tx, rx) = tokio::sync::mpsc::channel(8);
                    let header = ImportTarHeader {
                        owner: cli.owner.clone(),
                        durability: FrameDurability::from(durability) as i32,
                        parent_frame_id: parent,
                        labels: labels_map(labels),
                        pin: make_pin(&cli.owner, pin_id, pin_ttl_ms),
                        timeline_name: timeline,
                        expected_old_timeline_head: expected_old,
                        idempotency_key: make_idem(&cli.owner, request_id),
                    };
                    tx.send(ImportTarRequest {
                        chunk: Some(proto::import_tar_request::Chunk::Header(header)),
                    })
                    .await
                    .map_err(|_| anyhow!("import stream closed"))?;

                    let reader_task = tokio::spawn(async move {
                        let mut buf = vec![0u8; 64 * 1024];
                        loop {
                            let n = file.read(&mut buf).await?;
                            if n == 0 {
                                break;
                            }
                            if tx
                                .send(ImportTarRequest {
                                    chunk: Some(proto::import_tar_request::Chunk::Data(
                                        buf[..n].to_vec(),
                                    )),
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok::<(), std::io::Error>(())
                    });

                    let resp = c
                        .import_tar(ReceiverStream::new(rx))
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    reader_task.await??;
                    let f = resp.frame.context("missing frame in ImportTarResponse")?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "frame_id": f.frame_id,
                                "owner": f.owner,
                                "disk_clean": f.disk_clean,
                                "bytes_received": resp.bytes_received,
                                "timeline": resp.timeline.map(|t| t.name),
                            }))?
                        );
                    } else {
                        println!(
                            "imported frame {} ({} bytes, disk_clean={})",
                            f.frame_id, resp.bytes_received, f.disk_clean
                        );
                    }
                }
                FrameCmd::List {
                    all_owners,
                    labels,
                    include_non_committed,
                } => {
                    let resp = c
                        .list_frames(ListFramesRequest {
                            owner: if all_owners { String::new() } else { cli.owner },
                            label_selector: labels_map(labels),
                            include_non_committed,
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    if cli.json {
                        let items: Vec<_> = resp
                            .frames
                            .iter()
                            .map(|f| {
                                json!({
                                    "frame_id": f.frame_id,
                                    "owner": f.owner,
                                    "parent": f.parent_frame_id,
                                    "disk_clean": f.disk_clean,
                                    "holds": f.holds.len(),
                                })
                            })
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&items)?);
                    } else {
                        for f in resp.frames {
                            println!(
                                "{}  owner={}  clean={}  holds={}",
                                f.frame_id,
                                f.owner,
                                f.disk_clean,
                                f.holds.len()
                            );
                        }
                    }
                }
                FrameCmd::Get { frame_id } => {
                    let resp = c
                        .get_frame(GetFrameRequest { frame_id })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    let f = resp.frame.context("missing frame")?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "frame_id": f.frame_id,
                                "owner": f.owner,
                                "parent_frame_id": f.parent_frame_id,
                                "disk_clean": f.disk_clean,
                                "objects": f.objects,
                                "holds": f.holds.len(),
                                "marked_for_reclaim": f.marked_for_reclaim,
                            }))?
                        );
                    } else {
                        println!(
                            "frame {} owner={} parent={} clean={} objects={:?} holds={}",
                            f.frame_id,
                            f.owner,
                            f.parent_frame_id,
                            f.disk_clean,
                            f.objects,
                            f.holds.len()
                        );
                    }
                }
                FrameCmd::Pin {
                    frame_id,
                    pin_id,
                    ttl_ms,
                } => {
                    let resp = c
                        .pin_frame(PinFrameRequest {
                            frame_id: frame_id.clone(),
                            pin: Some(PinSpec {
                                pin_id: pin_id.clone(),
                                owner: cli.owner,
                                lease_ttl_ms: ttl_ms,
                            }),
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    let h = resp.hold.context("missing hold")?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "frame_id": frame_id,
                                "hold": {
                                    "kind": h.kind,
                                    "detail": h.detail,
                                    "expires_at_ms": h.expires_at_ms,
                                }
                            }))?
                        );
                    } else {
                        println!(
                            "pinned {} ({}, expires_at_ms={})",
                            frame_id, h.detail, h.expires_at_ms
                        );
                    }
                }
                FrameCmd::RenewPin { frame_id, pin_id } => {
                    let resp = c
                        .renew_pin(RenewPinRequest {
                            frame_id: frame_id.clone(),
                            pin_id: pin_id.clone(),
                            owner: cli.owner,
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "frame_id": frame_id,
                                "pin_id": pin_id,
                                "expires_at_ms": resp.expires_at_ms,
                                "persisted_to_disk": resp.persisted_to_disk,
                            }))?
                        );
                    } else {
                        println!(
                            "renewed pin expires_at_ms={} persisted={}",
                            resp.expires_at_ms, resp.persisted_to_disk
                        );
                    }
                }
                FrameCmd::Delete {
                    frame_id,
                    request_id,
                } => {
                    let resp = c
                        .delete_frame(DeleteFrameRequest {
                            frame_id: frame_id.clone(),
                            owner: cli.owner.clone(),
                            idempotency_key: make_idem(&cli.owner, request_id),
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "frame_id": frame_id,
                                "deleted": resp.deleted,
                                "deferred": resp.deferred,
                                "remaining_holds": resp.remaining_holds,
                            }))?
                        );
                    } else if resp.deleted {
                        println!("deleted frame {frame_id}");
                    } else {
                        println!(
                            "deferred deletion of {frame_id} (remaining_holds={})",
                            resp.remaining_holds
                        );
                    }
                }
                FrameCmd::Patch {
                    target_frame_id,
                    base,
                } => {
                    let resp = c
                        .export_patch(ExportPatchRequest {
                            target_frame_id,
                            base_frame_id: base,
                            owner: cli.owner,
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "base_frame_id": resp.base_frame_id,
                                "target_frame_id": resp.target_frame_id,
                                "blake3_hex": resp.blake3_hex,
                                "entries": resp.entries.iter().map(|e| json!({
                                    "path": e.path, "kind": e.kind, "size_bytes": e.size_bytes
                                })).collect::<Vec<_>>(),
                                "unified_diff": String::from_utf8_lossy(&resp.unified_diff),
                            }))?
                        );
                    } else {
                        std::io::stdout().write_all(&resp.unified_diff)?;
                    }
                }
            }
        }
        Cmd::Timeline { sub } => {
            let mut c = FrameServiceClient::new(channel);
            match sub {
                TimelineCmd::Advance {
                    name,
                    head,
                    expected_old,
                    request_id,
                } => {
                    let resp = c
                        .advance_timeline(AdvanceTimelineRequest {
                            timeline: name,
                            owner: cli.owner.clone(),
                            expected_old_frame_id: expected_old,
                            new_head_frame_id: head,
                            idempotency_key: make_idem(&cli.owner, request_id),
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    let tl = resp.timeline.context("missing timeline")?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "timeline": tl.name,
                                "owner": tl.owner,
                                "head_frame_id": tl.head_frame_id,
                                "previous_head_frame_id": resp.previous_head_frame_id,
                            }))?
                        );
                    } else {
                        println!(
                            "timeline {} -> {} (previous: {})",
                            tl.name, tl.head_frame_id, resp.previous_head_frame_id
                        );
                    }
                }
                TimelineCmd::Delete { name, request_id } => {
                    let resp = c
                        .delete_timeline(DeleteTimelineRequest {
                            timeline: name.clone(),
                            owner: cli.owner.clone(),
                            idempotency_key: make_idem(&cli.owner, request_id),
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "timeline": name,
                                "released_head_frame_id": resp.released_head_frame_id,
                            }))?
                        );
                    } else {
                        println!(
                            "deleted timeline {name} (released head {})",
                            resp.released_head_frame_id
                        );
                    }
                }
            }
        }
        Cmd::World { sub } => {
            let mut c = WorldServiceClient::new(channel);
            match sub {
                WorldCmd::Create {
                    base,
                    driver,
                    lease_ttl_ms,
                    labels,
                    request_id,
                } => {
                    let resp = c
                        .create_world(CreateWorldRequest {
                            owner: cli.owner.clone(),
                            base_frame_id: base,
                            driver: DriverKind::from(driver) as i32,
                            labels: labels_map(labels),
                            lease_ttl_ms,
                            idempotency_key: make_idem(&cli.owner, request_id),
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    let w = resp.world.context("missing world")?;
                    let fence = w.fencing_token.map_or(0, |t| t.value);
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "world_id": w.world_id,
                                "base_frame_id": w.base_frame_id,
                                "fencing_token": fence,
                                "origin_epoch": w.origin_epoch,
                            }))?
                        );
                    } else {
                        println!("created world {} (fence={fence})", w.world_id);
                    }
                }
                WorldCmd::Get { world_id } => {
                    let resp = c
                        .get_world(GetWorldRequest { world_id })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    let w = resp.world.context("missing world")?;
                    let fence = w.fencing_token.map_or(0, |t| t.value);
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "world_id": w.world_id,
                                "state": w.state,
                                "owner": w.owner,
                                "base_frame_id": w.base_frame_id,
                                "fencing_token": fence,
                                "origin_epoch": w.origin_epoch,
                                "lost_in_epoch": w.lost_in_epoch,
                                "end_reason": w.end_reason,
                            }))?
                        );
                    } else {
                        println!(
                            "world {} state={} owner={} base={} fence={} epoch={}",
                            w.world_id, w.state, w.owner, w.base_frame_id, fence, w.origin_epoch
                        );
                    }
                }
                WorldCmd::AcquireFence { world_id } => {
                    let resp = c
                        .acquire_fence(proto::AcquireFenceRequest {
                            world_id: world_id.clone(),
                            owner: cli.owner,
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    let fence = resp.fencing_token.map_or(0, |t| t.value);
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "world_id": world_id,
                                "fencing_token": fence,
                            }))?
                        );
                    } else {
                        println!("world {world_id} new fence={fence}");
                    }
                }
                WorldCmd::RenewLease { world_id, fence } => {
                    let resp = c
                        .renew_world_lease(RenewWorldLeaseRequest {
                            world_id: world_id.clone(),
                            owner: cli.owner,
                            fencing_token: Some(FencingToken { value: fence }),
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "world_id": world_id,
                                "renewed_ttl_ms": resp.renewed_ttl_ms,
                            }))?
                        );
                    } else {
                        println!(
                            "world {world_id} lease renewed ({} ms)",
                            resp.renewed_ttl_ms
                        );
                    }
                }
                WorldCmd::Exec {
                    world_id,
                    fence,
                    cwd,
                    timeout_ms,
                    max_output_bytes,
                    no_stream,
                    detach,
                    request_id,
                    argv,
                } => {
                    let mut stream = c
                        .exec(ExecRequest {
                            world_id,
                            owner: cli.owner.clone(),
                            fencing_token: Some(FencingToken { value: fence }),
                            argv,
                            env: HashMap::new(),
                            cwd,
                            timeout_ms: if detach { 0 } else { timeout_ms },
                            max_output_bytes,
                            stream: !no_stream,
                            idempotency_key: make_idem(&cli.owner, request_id),
                            detached: detach,
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();

                    let mut streamed_any = false;
                    let mut final_exit = 0i32;
                    while let Some(ev) = stream.next().await {
                        let ev = ev.map_err(|s| anyhow!("{}", format_status(&s)))?;
                        match ev.event {
                            Some(proto::exec_event::Event::Chunk(chunk)) => {
                                if !cli.json {
                                    streamed_any = true;
                                    match OutputStreamKind::try_from(chunk.stream) {
                                        Ok(OutputStreamKind::OutputStreamStderr) => {
                                            std::io::stderr().write_all(&chunk.data)?;
                                        }
                                        _ => {
                                            std::io::stdout().write_all(&chunk.data)?;
                                        }
                                    }
                                }
                            }
                            Some(proto::exec_event::Event::Result(res)) => {
                                if cli.json {
                                    println!(
                                        "{}",
                                        serde_json::to_string_pretty(&json!({
                                            "exec_id": res.exec_id,
                                            "exit_code": res.exit_code,
                                            "has_exit_code": res.has_exit_code,
                                            "signal": res.signal,
                                            "timed_out": res.timed_out,
                                            "duration_ms": res.duration_ms,
                                            "replayed_from_cache": res.replayed_from_cache,
                                            "stdout": res.stdout.as_ref().map(|b| json!({
                                                "head": String::from_utf8_lossy(&b.head),
                                                "tail": String::from_utf8_lossy(&b.tail),
                                                "total_bytes": b.total_bytes,
                                                "omitted_bytes": b.omitted_bytes,
                                                "truncated": b.truncated,
                                            })),
                                            "stderr": res.stderr.as_ref().map(|b| json!({
                                                "head": String::from_utf8_lossy(&b.head),
                                                "tail": String::from_utf8_lossy(&b.tail),
                                                "total_bytes": b.total_bytes,
                                                "omitted_bytes": b.omitted_bytes,
                                                "truncated": b.truncated,
                                            })),
                                        }))?
                                    );
                                } else if !streamed_any {
                                    if let Some(out) = &res.stdout {
                                        std::io::stdout().write_all(&out.head)?;
                                        if out.truncated {
                                            write!(
                                                std::io::stdout(),
                                                "\n... [truncated {} bytes] ...\n",
                                                out.omitted_bytes
                                            )?;
                                            std::io::stdout().write_all(&out.tail)?;
                                        }
                                    }
                                    if let Some(err) = &res.stderr {
                                        std::io::stderr().write_all(&err.head)?;
                                        if err.truncated {
                                            write!(
                                                std::io::stderr(),
                                                "\n... [truncated {} bytes] ...\n",
                                                err.omitted_bytes
                                            )?;
                                            std::io::stderr().write_all(&err.tail)?;
                                        }
                                    }
                                }
                                final_exit = if res.has_exit_code {
                                    res.exit_code
                                } else {
                                    i32::from(!detach)
                                };
                            }
                            None => {}
                        }
                    }
                    return Ok(if final_exit == 0 {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(u8::try_from(final_exit.clamp(1, 255)).unwrap_or(1))
                    });
                }
                WorldCmd::Checkpoint {
                    world_id,
                    fence,
                    durability,
                    labels,
                    pin_id,
                    pin_ttl_ms,
                    timeline,
                    expected_old,
                    no_syncfs,
                    request_id,
                } => {
                    let resp = c
                        .checkpoint(CheckpointRequest {
                            world_id,
                            owner: cli.owner.clone(),
                            fencing_token: Some(FencingToken { value: fence }),
                            durability: FrameDurability::from(durability) as i32,
                            labels: labels_map(labels),
                            pin: make_pin(&cli.owner, pin_id, pin_ttl_ms),
                            timeline_name: timeline,
                            expected_old_timeline_head: expected_old,
                            perform_syncfs: !no_syncfs,
                            idempotency_key: make_idem(&cli.owner, request_id),
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    let f = resp.frame.context("missing frame in CheckpointResponse")?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "frame_id": f.frame_id,
                                "parent_frame_id": f.parent_frame_id,
                                "disk_clean": f.disk_clean,
                                "timeline": resp.timeline.map(|t| t.name),
                            }))?
                        );
                    } else {
                        println!(
                            "checkpoint frame {} (disk_clean={})",
                            f.frame_id, f.disk_clean
                        );
                    }
                }
                WorldCmd::Destroy {
                    world_id,
                    fence,
                    request_id,
                } => {
                    let resp = c
                        .destroy_world(DestroyWorldRequest {
                            world_id,
                            owner: cli.owner.clone(),
                            fencing_token: Some(FencingToken { value: fence }),
                            idempotency_key: make_idem(&cli.owner, request_id),
                        })
                        .await
                        .map_err(|s| anyhow!("{}", format_status(&s)))?
                        .into_inner();
                    let w = resp.world.context("missing world")?;
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "world_id": w.world_id,
                                "state": w.state,
                                "end_reason": w.end_reason,
                            }))?
                        );
                    } else {
                        println!("destroyed world {} (reason={})", w.world_id, w.end_reason);
                    }
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("aos: {err:#}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_phase1_cli_subcommands() {
        let cases: &[&[&str]] = &[
            &["aos", "version"],
            &["aos", "frame", "import", "repo.tar", "--timeline", "main", "--label", "env=dev"],
            &["aos", "frame", "list", "--label", "env=dev"],
            &["aos", "frame", "get", "00000000000000000000000000"],
            &["aos", "frame", "pin", "00000000000000000000000000", "--pin-id", "keep"],
            &["aos", "frame", "renew-pin", "00000000000000000000000000", "--pin-id", "keep"],
            &["aos", "frame", "delete", "00000000000000000000000000"],
            &["aos", "frame", "patch", "00000000000000000000000000"],
            &["aos", "timeline", "advance", "main", "--head", "00000000000000000000000000"],
            &["aos", "timeline", "delete", "main"],
            &["aos", "world", "create", "--base", "00000000000000000000000000"],
            &["aos", "world", "get", "00000000000000000000000000"],
            &["aos", "world", "acquire-fence", "00000000000000000000000000"],
            &["aos", "world", "renew-lease", "00000000000000000000000000", "--fence", "1"],
            &["aos", "world", "exec", "00000000000000000000000000", "--fence", "1", "--", "echo", "hi"],
            &["aos", "world", "checkpoint", "00000000000000000000000000", "--fence", "1", "--timeline", "main"],
            &["aos", "world", "destroy", "00000000000000000000000000", "--fence", "1"],
        ];
        for argv in cases {
            Cli::try_parse_from(*argv).unwrap_or_else(|e| panic!("failed to parse {argv:?}: {e}"));
        }
    }

    #[test]
    fn label_kv_parser_validates_format() {
        assert_eq!(parse_label_kv("a=b=c").unwrap(), ("a".into(), "b=c".into()));
        assert!(parse_label_kv("noequals").is_err());
        assert!(parse_label_kv("=val").is_err());
    }
}
