// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_proto::lore::repository::v1::RepositoryDeleteRequest;
use lore_revision::lore::RepositoryId;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::grpc::repository::v1::repository_delete::*;
use lore_telemetry::InstrumentProvider;
use rand::random;
use tonic::Request;

use crate::store::test_support::test_store_create;

struct TestInstrumentProvider;

impl InstrumentProvider for TestInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "test"
    }
}

async fn seed_repository(
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    id: RepositoryId,
    creator: &str,
) {
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        id,
    ));
    let metadata_hash = repository::metadata_store(
        repository.clone(),
        RepositoryMetadata {
            name: "the-repository".to_string(),
            creator: creator.to_string(),
            ..Default::default()
        },
    )
    .await
    .expect("Failed to store repository metadata");
    repository::metadata_store_hash(repository.clone(), metadata_hash)
        .await
        .expect("Failed to store repository metadata hash");
    repository::store_name_to_id(repository, "the-repository", id)
        .await
        .expect("Failed to store repository name to id mapping");
}

fn delete_request(id: RepositoryId, token: AuthorizationToken) -> Request<RepositoryDeleteRequest> {
    let id_bytes: Context = id.into();
    let mut request = Request::new(RepositoryDeleteRequest {
        id: id_bytes.into(),
    });
    request.extensions_mut().insert(token);
    request
        .extensions_mut()
        .insert(lore_server::authnz::repository_authorizer::RawToken(
            "verified-test".into(),
        ));
    request.extensions_mut().insert(
        lore_server::authnz::repository_authorizer::RequestAuthorizer(
            Arc::new(
                lore_server::authnz::resource_grants_authorizer::ResourceGrantsAuthorizer::new(
                    "resources".into(),
                    "resource_id".into(),
                    None,
                    "urc-{id}".into(),
                    "urc-*".into(),
                ),
            ),
            false,
        ),
    );
    request
}

/// Matching the creator, by subject or username, cannot replace the admin grant.
#[tokio::test]
async fn creator_identity_does_not_replace_the_required_admin_grant() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let id = random::<RepositoryId>();
        seed_repository(immutable_store.clone(), mutable_store.clone(), id, "alice").await;

        let by_subject = AuthorizationToken {
            user_id: "f7d3a1c2-0000-0000-0000-000000000000".to_string(),
            preferred_username: Some("alice".to_string()),
            ..Default::default()
        };
        let status = handler(
            delete_request(id, by_subject.clone()),
            None,
            immutable_store.clone(),
            mutable_store.clone(),
            &TestInstrumentProvider,
        )
        .await
        .expect_err("the subject is not the recorded creator");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);

        let by_username = AuthorizationToken {
            identity: Some("alice".to_string()),
            ..by_subject
        };
        handler(
            delete_request(id, by_username),
            None,
            immutable_store,
            mutable_store,
            &TestInstrumentProvider,
        )
        .await
        .expect_err("a matching creator identity alone does not grant admin");
    }))
    .await;
}
