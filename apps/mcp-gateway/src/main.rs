use std::path::{Path, PathBuf};

use anyhow::Context as _;
use briefcase_api::types::{CallToolRequest, CallToolResponse};
use briefcase_api::{BriefcaseClient, DaemonEndpoint};
use briefcase_core::{ToolCall, ToolCallContext};
use clap::Parser;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "briefcase-mcp-gateway",
    version,
    about = "Single MCP surface for tools"
)]
struct Args {
    /// Directory for runtime state (auth token, socket).
    #[arg(long, env = "BRIEFCASE_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Use a TCP daemon endpoint, e.g. `http://127.0.0.1:3000`.
    #[arg(long, env = "BRIEFCASE_DAEMON_BASE_URL")]
    daemon_base_url: Option<String>,

    /// Override the unix socket path (Unix only).
    #[arg(long, env = "BRIEFCASE_DAEMON_UNIX_SOCKET")]
    unix_socket: Option<PathBuf>,

    /// Override the daemon auth token (otherwise read from <data_dir>/auth_token).
    #[arg(long, env = "BRIEFCASE_AUTH_TOKEN")]
    auth_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    params: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    let args = Args::parse();
    let data_dir = resolve_data_dir(args.data_dir.as_deref())?;

    let auth_token = match args.auth_token {
        Some(t) => t,
        None => std::fs::read_to_string(data_dir.join("auth_token"))
            .context("read daemon auth_token")?
            .trim()
            .to_string(),
    };

    let endpoint = match args.daemon_base_url {
        Some(base_url) => DaemonEndpoint::Tcp { base_url },
        None => {
            #[cfg(unix)]
            {
                let socket_path = args
                    .unix_socket
                    .unwrap_or_else(|| data_dir.join("briefcased.sock"));
                DaemonEndpoint::Unix { socket_path }
            }
            #[cfg(not(unix))]
            {
                anyhow::bail!("unix sockets not supported; set --daemon-base-url");
            }
        }
    };

    let client = BriefcaseClient::new(endpoint, auth_token);
    client.health().await.context("connect to daemon")?;
    info!("connected to briefcased");

    run_rpc_loop(client).await?;
    Ok(())
}

async fn run_rpc_loop(client: BriefcaseClient) -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: RpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, "invalid json");
                continue;
            }
        };

        let resp = handle_rpc(&client, req).await;
        let out = serde_json::to_string(&resp)?;
        stdout.write_all(out.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }

    Ok(())
}

async fn handle_rpc(client: &BriefcaseClient, req: RpcRequest) -> RpcResponse {
    // Minimal MCP-like JSON-RPC surface:
    // - initialize
    // - tools/list
    // - tools/call
    if req.jsonrpc != "2.0" {
        return RpcResponse {
            jsonrpc: "2.0",
            id: req.id,
            result: None,
            error: Some(RpcError {
                code: -32600,
                message: "invalid jsonrpc version".to_string(),
                data: None,
            }),
        };
    }

    match req.method.as_str() {
        "initialize" => RpcResponse {
            jsonrpc: "2.0",
            id: req.id,
            result: Some(serde_json::json!({
                "serverInfo": { "name": "briefcase-mcp-gateway", "version": env!("CARGO_PKG_VERSION") },
                "capabilities": { "tools": {} },
            })),
            error: None,
        },
        "tools/list" => match client.list_tools().await {
            Ok(list) => {
                let tools = list
                    .tools
                    .into_iter()
                    .map(|t| {
                        serde_json::json!({
                            "name": t.id,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                        })
                    })
                    .collect::<Vec<_>>();

                RpcResponse {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(serde_json::json!({ "tools": tools })),
                    error: None,
                }
            }
            Err(e) => RpcResponse {
                jsonrpc: "2.0",
                id: req.id,
                result: None,
                error: Some(RpcError {
                    code: -32000,
                    message: "daemon_error".to_string(),
                    data: Some(serde_json::json!({ "detail": e.to_string() })),
                }),
            },
        },
        "tools/call" => {
            let Some(params) = req.params else {
                return RpcResponse {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: None,
                    error: Some(RpcError {
                        code: -32602,
                        message: "missing params".to_string(),
                        data: None,
                    }),
                };
            };

            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));

            let call = ToolCall {
                tool_id: name.to_string(),
                args: arguments,
                context: ToolCallContext {
                    request_id: Uuid::new_v4(),
                    agent_id: None,
                    session_id: None,
                },
                approval_token: None,
            };

            match client.call_tool(CallToolRequest { call }).await {
                Ok(CallToolResponse::Ok { result }) => RpcResponse {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(serde_json::json!({
                        "content": [
                            { "type": "text", "text": serde_json::to_string_pretty(&result.content).unwrap_or_else(|_| result.content.to_string()) }
                        ],
                        "meta": {
                            "provenance": result.provenance
                        }
                    })),
                    error: None,
                },
                Ok(CallToolResponse::ApprovalRequired { approval }) => RpcResponse {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(serde_json::json!({
                        "content": [
                            { "type": "text", "text": format!("Approval required for tool `{}`: {}. Approval ID: {}. Approve via `briefcase approvals approve {}`.", approval.tool_id, approval.reason, approval.id, approval.id) }
                        ]
                    })),
                    error: None,
                },
                Ok(CallToolResponse::Denied { reason }) => RpcResponse {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: None,
                    error: Some(RpcError {
                        code: -32001,
                        message: "denied".to_string(),
                        data: Some(serde_json::json!({ "reason": reason })),
                    }),
                },
                Ok(CallToolResponse::Error { message }) => RpcResponse {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: None,
                    error: Some(RpcError {
                        code: -32000,
                        message: "tool_error".to_string(),
                        data: Some(serde_json::json!({ "message": message })),
                    }),
                },
                Err(e) => RpcResponse {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: None,
                    error: Some(RpcError {
                        code: -32000,
                        message: "daemon_error".to_string(),
                        data: Some(serde_json::json!({ "detail": e.to_string() })),
                    }),
                },
            }
        }
        m => {
            warn!(method = %m, "unknown method");
            RpcResponse {
                jsonrpc: "2.0",
                id: req.id,
                result: None,
                error: Some(RpcError {
                    code: -32601,
                    message: "method not found".to_string(),
                    data: None,
                }),
            }
        }
    }
}

fn resolve_data_dir(cli: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(p) = cli {
        return Ok(p.to_path_buf());
    }

    let proj = ProjectDirs::from("com", "briefcase", "credential-briefcase")
        .context("resolve platform data dir")?;
    Ok(proj.data_local_dir().to_path_buf())
}
