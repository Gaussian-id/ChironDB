//! Local stdio transport bridge. The HTTP server owns all retrieval decisions.
use clap::Parser;
use rmcp::{
    ErrorData, Peer, RoleClient, RoleServer, ServerHandler, ServiceExt,
    model::*,
    service::RequestContext,
    transport::{
        StreamableHttpClientTransport, stdio,
        streamable_http_client::StreamableHttpClientTransportConfig,
    },
};

#[derive(Parser)]
#[command(
    name = "chironmcp",
    version,
    about = "ChironDB MCP stdio to HTTP bridge"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:7401/v1/mcp")]
    endpoint: String,
    #[arg(long, default_value = "CHIRONDB_API_KEY")]
    api_key_env: String,
}

struct Bridge(Peer<RoleClient>);
impl ServerHandler for Bridge {
    fn get_info(&self) -> ServerInfo {
        chirondb::mcp::server_info()
    }
    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        std::borrow::Cow::Owned(vec![
            ProtocolVersion::V_2026_07_28,
            ProtocolVersion::V_2025_11_25,
        ])
    }
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.0
            .list_tools(request)
            .await
            .map(|mut result| {
                result.result_type = Some(ResultType::COMPLETE);
                result.ttl_ms = Some(0);
                result.cache_scope = Some(CacheScope::Private);
                result
            })
            .map_err(|_| ErrorData::internal_error("upstream discovery failed", None))
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let mut handle = self
            .0
            .send_cancellable_request(
                ClientRequest::CallToolRequest(CallToolRequest::new(request)),
                rmcp::service::PeerRequestOptions::no_options(),
            )
            .await
            .map_err(|_| ErrorData::internal_error("upstream tool failed", None))?;
        tokio::select! {
            _ = context.ct.cancelled() => {
                let _ = handle.cancel(Some("stdio client cancelled".into())).await;
                Err(ErrorData::internal_error("cancelled", None))
            },
            result = &mut handle.rx => match result {
                Ok(Ok(ServerResult::CallToolResult(mut result))) => {
                    result.result_type = Some(ResultType::COMPLETE);
                    Ok(result.into())
                },
                _ => Err(ErrorData::internal_error("upstream tool failed", None)),
            },
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    chirondb::mcp::validate_endpoint(&args.endpoint)?;
    let key = std::env::var(&args.api_key_env)
        .map_err(|_| anyhow::anyhow!("ChironDB API key environment variable is missing"))?;
    anyhow::ensure!(!key.is_empty(), "ChironDB API key is empty");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(35))
        .build()?;
    let transport = StreamableHttpClientTransport::with_client(
        client,
        StreamableHttpClientTransportConfig::with_uri(args.endpoint).auth_header(key),
    );
    let upstream = ().serve(transport).await?;
    let server = Bridge(upstream.peer().clone()).serve(stdio()).await?;
    server.waiting().await?;
    upstream.cancel().await?;
    Ok(())
}
