//! Shared test helpers for scenario tests.

use chirondb::{
    grpc::pb::{WireRequest, gauss_db_client::GaussDbClient, wire_request, wire_response},
    wire,
};
use tonic::Request;

pub async fn connect_grpc(addr: std::net::SocketAddr) -> GaussDbClient<tonic::transport::Channel> {
    GaussDbClient::new(connect_grpc_channel(addr).await)
}

pub async fn connect_grpc_channel(addr: std::net::SocketAddr) -> tonic::transport::Channel {
    let endpoint = format!("http://{addr}");
    for _ in 0..20 {
        match tonic::transport::Endpoint::from_shared(endpoint.clone())
            .unwrap()
            .connect()
            .await
        {
            Ok(channel) => return channel,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(25)).await,
        }
    }
    tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap()
}

pub fn grpc_auth_request<T>(message: T, api_key: &str) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {api_key}").parse().unwrap(),
    );
    request
}

pub async fn send_wire(
    endpoint: &str,
    request_id: u64,
    operation: wire_request::Operation,
) -> chirondb::grpc::pb::WireResponse {
    let response = send_wire_with_key(endpoint, request_id, "", operation).await;
    assert_eq!(response.error_code, "");
    response
}

pub async fn send_wire_with_key(
    endpoint: &str,
    request_id: u64,
    api_key: &str,
    operation: wire_request::Operation,
) -> chirondb::grpc::pb::WireResponse {
    let response = wire::send_request(
        endpoint,
        WireRequest {
            request_id,
            api_key: api_key.to_string(),
            operation: Some(operation),
        },
    )
    .await
    .unwrap();
    assert_eq!(response.request_id, request_id);
    response
}

pub fn wire_search_hit_id(response: chirondb::grpc::pb::WireResponse) -> String {
    let wire_response::Payload::Search(search) = response.payload.unwrap() else {
        panic!("expected search response");
    };
    search.hits.first().expect("expected search hit").id.clone()
}

pub async fn list_reflection_services(
    channel: tonic::transport::Channel,
    api_key: Option<&str>,
) -> Vec<String> {
    let response = reflection_request(channel, api_key)
        .await
        .unwrap()
        .into_inner()
        .message()
        .await
        .unwrap()
        .unwrap();
    let Some(
        tonic_reflection::pb::v1::server_reflection_response::MessageResponse::ListServicesResponse(
            services,
        ),
    ) = response.message_response
    else {
        panic!("expected reflection list services response");
    };
    services
        .service
        .into_iter()
        .map(|service| service.name)
        .collect()
}

pub async fn reflection_request(
    channel: tonic::transport::Channel,
    api_key: Option<&str>,
) -> Result<
    tonic::Response<tonic::Streaming<tonic_reflection::pb::v1::ServerReflectionResponse>>,
    tonic::Status,
> {
    let request = tonic_reflection::pb::v1::ServerReflectionRequest {
        host: String::new(),
        message_request: Some(
            tonic_reflection::pb::v1::server_reflection_request::MessageRequest::ListServices(
                String::new(),
            ),
        ),
    };
    let mut request = Request::new(tokio_stream::once(request));
    if let Some(api_key) = api_key {
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {api_key}").parse().unwrap(),
        );
    }
    let mut client =
        tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient::new(channel);
    client.server_reflection_info(request).await
}
