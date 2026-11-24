//! Unix Domain Socket gRPC channel connector and structured `ErrorDetail` decoder for `aos`.

#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::Result;
use prost::Message;
use tonic::transport::Channel;
use tonic::Status;

use crate::proto::{ErrorCode, ErrorDetail};
use crate::ERROR_DETAIL_BIN_KEY;

/// Decode structured `forkloom.v1.ErrorDetail` from a gRPC [`tonic::Status`], if present.
#[must_use]
pub fn decode_error_detail(status: &Status) -> Option<ErrorDetail> {
    let raw = status.metadata().get_bin(ERROR_DETAIL_BIN_KEY)?;
    let bytes = raw.to_bytes().ok()?;
    ErrorDetail::decode(bytes.as_ref()).ok()
}

/// Format a gRPC [`tonic::Status`] into a concise human-readable diagnostic preserving
/// `WorldLost`, `OutcomeUnknown`, and `FencedOut` fields.
#[must_use]
pub fn format_status(status: &Status) -> String {
    if let Some(d) = decode_error_detail(status) {
        let code_name = ErrorCode::try_from(d.code)
            .unwrap_or(ErrorCode::Unspecified)
            .as_str_name();
        let mut extra = Vec::new();
        if !d.resource_id.is_empty() {
            extra.push(format!("resource={}", d.resource_id));
        }
        if d.current_fencing_token > 0 {
            extra.push(format!(
                "presented_fence={} current_fence={}",
                d.presented_fencing_token, d.current_fencing_token
            ));
        }
        if d.lost_in_epoch > 0 {
            extra.push(format!(
                "origin_epoch={} lost_in_epoch={}",
                d.origin_epoch, d.lost_in_epoch
            ));
        }
        if extra.is_empty() {
            format!("[{code_name}] {}", d.message)
        } else {
            format!("[{code_name}] {} ({})", d.message, extra.join(", "))
        }
    } else {
        format!("[{:?}] {}", status.code(), status.message())
    }
}

/// Connect to `agentd` strictly over a Unix Domain Socket (Unix/Linux only).
#[cfg(unix)]
pub async fn connect_uds(socket_path: &Path) -> Result<Channel> {
    use anyhow::Context;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;
    use tonic::transport::{Endpoint, Uri};
    use tower::service_fn;

    let sock = socket_path.to_path_buf();
    let channel = Endpoint::try_from("http://[::]:50051")
        .context("create dummy UDS endpoint URI")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let p = sock.clone();
            async move {
                let stream = UnixStream::connect(&p).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .with_context(|| format!("connect to agentd at unix://{}", socket_path.display()))?;
    Ok(channel)
}

/// Non-Unix stub: `aos` connects strictly over UDS (no insecure default TCP fallback).
#[cfg(not(unix))]
pub async fn connect_uds(socket_path: &Path) -> Result<Channel> {
    anyhow::bail!(
        "connecting to unix://{} requires Linux/Unix (run inside WSL2/Linux; TCP is disabled)",
        socket_path.display()
    )
}

/// Parse `KEY=VALUE` label CLI flags into `(key, value)`.
pub fn parse_label_kv(raw: &str) -> Result<(String, String), String> {
    let (k, v) = raw
        .split_once('=')
        .ok_or_else(|| format!("label {raw:?} must have KEY=VALUE format"))?;
    if k.is_empty() {
        return Err("label key must not be empty".into());
    }
    Ok((k.to_owned(), v.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::{MetadataMap, MetadataValue};
    use tonic::Code;

    fn status_with_detail(code: Code, detail: &ErrorDetail) -> Status {
        let mut md = MetadataMap::new();
        md.insert_bin(
            ERROR_DETAIL_BIN_KEY,
            MetadataValue::from_bytes(&detail.encode_to_vec()),
        );
        Status::with_metadata(code, detail.message.clone(), md)
    }

    #[test]
    fn decodes_and_formats_world_lost_outcome_unknown_and_fenced_out() {
        let lost = ErrorDetail {
            code: ErrorCode::WorldLost as i32,
            message: "world died during daemon restart".into(),
            resource_id: "01JWORLD".into(),
            current_fencing_token: 0,
            presented_fencing_token: 0,
            origin_epoch: 1,
            lost_in_epoch: 2,
        };
        let s_lost = status_with_detail(Code::FailedPrecondition, &lost);
        assert_eq!(decode_error_detail(&s_lost).unwrap(), lost);
        let fmt_lost = format_status(&s_lost);
        assert!(fmt_lost.contains("ERROR_CODE_WORLD_LOST"));
        assert!(fmt_lost.contains("origin_epoch=1 lost_in_epoch=2"));

        let unknown = ErrorDetail {
            code: ErrorCode::OutcomeUnknown as i32,
            message: "exec outcome unknown across restart".into(),
            resource_id: "01JWORLD".into(),
            current_fencing_token: 0,
            presented_fencing_token: 0,
            origin_epoch: 1,
            lost_in_epoch: 2,
        };
        let s_unk = status_with_detail(Code::Unknown, &unknown);
        let fmt_unk = format_status(&s_unk);
        assert!(fmt_unk.contains("ERROR_CODE_OUTCOME_UNKNOWN"));
        assert!(fmt_unk.contains("resource=01JWORLD"));

        let fenced = ErrorDetail {
            code: ErrorCode::FencedOut as i32,
            message: "stale fencing token".into(),
            resource_id: "01JWORLD".into(),
            current_fencing_token: 2,
            presented_fencing_token: 1,
            origin_epoch: 0,
            lost_in_epoch: 0,
        };
        let s_fenced = status_with_detail(Code::Aborted, &fenced);
        let fmt_fenced = format_status(&s_fenced);
        assert!(fmt_fenced.contains("ERROR_CODE_FENCED_OUT"));
        assert!(fmt_fenced.contains("presented_fence=1 current_fence=2"));
    }
}
