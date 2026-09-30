// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::error::Maintenance;
use lore_base::lore_warn;
use lore_proto::lore::environment::v1::EnvironmentGetRequest;
use lore_proto::lore::environment::v1::environment_service_client::EnvironmentServiceClient;

use super::Channel;
use super::CorrelationInterceptor;
use super::UnauthenticatedService;
use super::grpc_retry;
use super::handle_error;
use crate::error::ProtocolError;
use crate::types::Endpoint;
use crate::types::EnvironmentConfig;
use crate::types::EnvironmentServerConfig;
use crate::types::Oidc;
use crate::types::ServerCompressionMode;

impl From<lore_proto::lore::environment::v1::Environment> for EnvironmentConfig {
    fn from(value: lore_proto::lore::environment::v1::Environment) -> Self {
        EnvironmentConfig {
            endpoint: value.endpoint.map(|endpoint| Endpoint {
                auth_url: if !endpoint.auth_url.is_empty() {
                    Some(endpoint.auth_url.clone())
                } else {
                    None
                },
                repository_url: if !endpoint.repository_url.is_empty() {
                    Some(endpoint.repository_url.clone())
                } else {
                    None
                },
                storage_url: if !endpoint.storage_url.is_empty() {
                    Some(endpoint.storage_url.clone())
                } else {
                    None
                },
                revision_url: if !endpoint.revision_url.is_empty() {
                    Some(endpoint.revision_url.clone())
                } else {
                    None
                },
                lock_url: if !endpoint.lock_url.is_empty() {
                    Some(endpoint.lock_url.clone())
                } else {
                    None
                },
                notification_url: if !endpoint.notification_url.is_empty() {
                    Some(endpoint.notification_url.clone())
                } else {
                    None
                },
                user_url: if !endpoint.user_url.is_empty() {
                    Some(endpoint.user_url.clone())
                } else {
                    None
                },
            }),
            config: value.config.map(|config| EnvironmentServerConfig {
                max_query_batch: if config.max_query_batch > 0 {
                    Some(config.max_query_batch as usize)
                } else {
                    None
                },
                compression_mode: config
                    .compression_mode
                    .map(|mode| ServerCompressionMode::from_u32(mode as u32)),
            }),
            oidc: value.oidc.and_then(oidc_from_proto),
        }
    }
}

/// `None` for a message with no issuer: there is no provider to discover without one.
fn oidc_from_proto(oidc: lore_proto::lore::environment::v1::Oidc) -> Option<Oidc> {
    if oidc.issuer.is_empty() {
        return None;
    }
    let non_empty = |value: String| (!value.is_empty()).then_some(value);
    Some(Oidc {
        issuer: oidc.issuer,
        client_id: oidc.client_id,
        scopes: oidc.scopes,
        preferred: oidc.preferred,
        resource_template: non_empty(oidc.resource_template),
        scope_template: non_empty(oidc.scope_template),
        token_exchange_issuer: non_empty(oidc.token_exchange_issuer),
        identity_claim: non_empty(oidc.identity_claim),
    })
}

#[derive(Clone)]
pub struct EnvironmentService {
    client: EnvironmentServiceClient<UnauthenticatedService>,
}

impl EnvironmentService {
    pub fn new(channel: Channel) -> Self {
        let client = EnvironmentServiceClient::with_interceptor(channel, CorrelationInterceptor);

        Self { client }
    }

    /// Fetches the environment configuration from the remote server.
    ///
    /// Returns `ProtocolError::Maintenance` when the server signals maintenance mode,
    /// or `ProtocolError::Internal` when the response is missing environment data.
    pub async fn get(&self) -> Result<EnvironmentConfig, ProtocolError> {
        let mut retry = grpc_retry();
        let response = loop {
            let request = EnvironmentGetRequest {};

            let mut client = self.client.clone();

            match client.environment_get(request).await {
                Ok(response) => {
                    break response.into_inner();
                }
                Err(status)
                    if status.code() == tonic::Code::Unavailable
                        && status
                            .message()
                            .to_ascii_lowercase()
                            .contains("maintenance") =>
                {
                    lore_warn!("Server in maintenance mode: {}", status.message());
                    return Err(ProtocolError::from(Maintenance));
                }
                Err(status) => {
                    handle_error(&mut retry, status).await?;
                }
            }
        };

        if let Some(environment) = response.environment {
            Ok(environment.into())
        } else {
            Err(ProtocolError::internal(
                "get: No environment config data in response",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use lore_proto::lore::environment::v1 as proto;

    use super::*;

    fn environment_with(oidc: Option<proto::Oidc>) -> EnvironmentConfig {
        proto::Environment {
            endpoint: Some(proto::Endpoint {
                auth_url: "ucs-auth://auth.example.com".to_string(),
                ..Default::default()
            }),
            config: None,
            oidc,
        }
        .into()
    }

    /// What an old server sends: `auth_url` only, so the client stays on the legacy path.
    #[test]
    fn a_server_advertising_no_provider_maps_to_none() {
        let environment = environment_with(None);
        assert_eq!(environment.oidc, None);
        assert_eq!(
            environment
                .endpoint
                .and_then(|endpoint| endpoint.auth_url)
                .as_deref(),
            Some("ucs-auth://auth.example.com")
        );
    }

    #[test]
    fn a_provider_without_an_issuer_maps_to_none() {
        let environment = environment_with(Some(proto::Oidc {
            client_id: "lore-cli".to_string(),
            ..Default::default()
        }));
        assert_eq!(environment.oidc, None);
    }

    #[test]
    fn an_advertised_provider_maps_empty_strings_to_none() {
        let environment = environment_with(Some(proto::Oidc {
            issuer: "https://auth.example.com".to_string(),
            client_id: "lore-cli".to_string(),
            scopes: vec!["openid".to_string()],
            preferred: true,
            resource_template: "https://lore.example.com/partitions/{id}".to_string(),
            scope_template: String::new(),
            token_exchange_issuer: "https://auth.example.com".to_string(),
            identity_claim: String::new(),
        }));
        assert_eq!(
            environment.oidc,
            Some(Oidc {
                issuer: "https://auth.example.com".to_string(),
                client_id: "lore-cli".to_string(),
                scopes: vec!["openid".to_string()],
                preferred: true,
                resource_template: Some("https://lore.example.com/partitions/{id}".to_string()),
                scope_template: None,
                token_exchange_issuer: Some("https://auth.example.com".to_string()),
                identity_claim: None,
            })
        );
    }
}
