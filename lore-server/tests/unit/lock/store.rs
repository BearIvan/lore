// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::lock::LockQuery;
use lore_revision::lock::LockStore;
use lore_revision::lock::util::assemble_resource_for_path;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_server::lock::store::*;

#[tokio::test]
async fn locking_a_resource_held_by_another_owner_states_the_reason() {
    let store = LocalLockStore::default();
    let repository = RepositoryId::default();
    let resource = assemble_resource_for_path("Map.umap", BranchId::default());

    store
        .lock_resources("user_A", repository, std::slice::from_ref(&resource))
        .await
        .expect("the first owner acquires the lock");

    let error = store
        .lock_resources("user_B", repository, &[resource])
        .await
        .expect_err("a second owner is refused");

    assert_eq!(error.to_string(), "resource already locked");
}

#[tokio::test]
async fn a_refused_batch_keeps_none_of_the_locks_it_took() {
    let store = LocalLockStore::default();
    let repository = RepositoryId::default();
    let branch = BranchId::default();
    let contended = assemble_resource_for_path("Contended.umap", branch);
    let free = assemble_resource_for_path("Free.umap", branch);

    store
        .lock_resources("user_A", repository, std::slice::from_ref(&contended))
        .await
        .expect("the first owner acquires the contended lock");

    store
        .lock_resources("user_B", repository, &[free, contended])
        .await
        .expect_err("the batch is refused");

    let held = store
        .query_locks(LockQuery::Repository(repository))
        .await
        .expect("the held locks can be queried");

    assert_eq!(held.len(), 1, "the refused batch left a lock behind");
    assert_eq!(held[0].owner, "user_A");
}

#[tokio::test]
async fn a_rejected_unlock_batch_preserves_every_lock() {
    let store = LocalLockStore::default();
    let repository = RepositoryId::default();
    let a = assemble_resource_for_path("A.umap", BranchId::default());
    let b = assemble_resource_for_path("B.umap", BranchId::default());
    store
        .lock_resources("A", repository, &[a.clone()])
        .await
        .unwrap();
    store
        .lock_resources("B", repository, &[b.clone()])
        .await
        .unwrap();
    assert!(
        store
            .unlock_resources("A", true, repository, &[a, b])
            .await
            .is_err()
    );
    assert_eq!(
        store
            .query_locks(LockQuery::Repository(repository))
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn locks_and_unlocks_survive_reopening_the_snapshot() {
    let path = std::env::temp_dir().join(format!("lore-lock-test-{}.json", uuid::Uuid::new_v4()));
    let repository = RepositoryId::default();
    let resource = assemble_resource_for_path("Persist.umap", BranchId::default());
    {
        let store = LocalLockStore::persistent(path.clone()).unwrap();
        store
            .lock_resources("A", repository, &[resource.clone()])
            .await
            .unwrap();
    }
    {
        let store = LocalLockStore::persistent(path.clone()).unwrap();
        let locks = store
            .query_locks(LockQuery::Repository(repository))
            .await
            .unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].owner, "A");
        store
            .unlock_resources("A", true, repository, &[resource])
            .await
            .unwrap();
    }
    let store = LocalLockStore::persistent(path.clone()).unwrap();
    assert!(
        store
            .query_locks(LockQuery::Repository(repository))
            .await
            .unwrap()
            .is_empty()
    );
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn duplicate_unlock_resources_do_not_partially_fail() {
    let store = LocalLockStore::default();
    let repository = RepositoryId::default();
    let resource = assemble_resource_for_path("A.umap", BranchId::default());
    store
        .lock_resources("A", repository, &[resource.clone()])
        .await
        .unwrap();
    store
        .unlock_resources("A", true, repository, &[resource.clone(), resource])
        .await
        .unwrap();
    assert!(
        store
            .query_locks(LockQuery::Repository(repository))
            .await
            .unwrap()
            .is_empty()
    );
}
