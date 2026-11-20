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
    fn get_info(&self) -> ServerConfig {
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

#[cfg(test)]
mod tests {
    use rmcp::transport::streamable_http_client::{
        StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn reply(
        headers: &str,
        body: &[u8],
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<reqwest::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let headers = headers.to_owned();
        let body = body.to_vec();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let count = stream.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&chunk[..count]);
                assert!(request.len() <= 16 * 1024);
                if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..end]).unwrap();
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            stream.write_all(headers.as_bytes()).await.unwrap();
            // Oversized replies may be rejected before the peer finishes writing.
            let _ = stream.write_all(&body).await;
        });
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let message = serde_json::from_value(serde_json::json!({
            "jsonrpc":"2.0", "id":1, "method":"ping"
        }))
        .unwrap();
        let result = client
            .post_message(endpoint.into(), message, None, None, Default::default())
            .await;
        server.await.unwrap();
        result
    }

    #[tokio::test]
    async fn upstream_transport_bounds_json_and_streamed_error_bodies() {
        let small = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            small.len()
        );
        assert!(matches!(
            reply(&headers, small).await,
            Ok(StreamableHttpPostResponse::Json(..))
        ));
        let error = reply("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16777217\r\nConnection: close\r\n\r\n", &[]).await;
        assert!(matches!(
            error,
            Err(StreamableHttpError::ResponseBodyTooLarge { .. })
        ));
        // No Content-Length: the streaming limit must apply while reading.
        let error = reply("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n", &vec![b'x'; 64 * 1024 + 1]).await;
        assert!(matches!(
            error,
            Err(StreamableHttpError::ResponseBodyTooLarge { .. })
        ));
    }
}
