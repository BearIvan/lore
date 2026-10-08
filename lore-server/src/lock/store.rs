// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use async_trait::async_trait;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use lore_base::error::InvalidArguments;
use lore_base::error::LockNotFound;
use lore_base::error::LockNotOwned;
use lore_base::types::Hash;
use lore_base::types::LockData;
use lore_base::types::LockResource;
use lore_revision::lock::LockError;
use lore_revision::lock::LockQuery;
use lore_revision::lock::LockStore;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::util;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct LockKey {
    repository: RepositoryId,
    branch: BranchId,
    hash: Hash,
}

#[derive(Default)]
pub struct LocalLockStore {
    storage: DashMap<LockKey, LockData>,
    transaction: parking_lot::Mutex<()>,
    path: Option<std::path::PathBuf>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredLock {
    repository: RepositoryId,
    branch: BranchId,
    hash: Hash,
    description: String,
    owner: String,
    locked_at: u64,
}

impl LocalLockStore {
    pub fn persistent(path: std::path::PathBuf) -> anyhow::Result<Self> {
        let store = Self {
            path: Some(path.clone()),
            ..Self::default()
        };
        match std::fs::read(&path) {
            Ok(bytes) => {
                for lock in serde_json::from_slice::<Vec<StoredLock>>(&bytes)? {
                    store.storage.insert(
                        LockKey {
                            repository: lock.repository,
                            branch: lock.branch,
                            hash: lock.hash,
                        },
                        LockData {
                            resource: LockResource {
                                branch: lock.branch,
                                hash: lock.hash,
                                description: lock.description,
                            },
                            owner: lock.owner,
                            locked_at: lock.locked_at,
                        },
                    );
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        Ok(store)
    }

    fn snapshot(&self) -> Vec<(LockKey, LockData)> {
        self.storage
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// A failed durable write rolls memory back to the pre-transaction snapshot.
    fn persist_or_rollback(&self, before: Vec<(LockKey, LockData)>) -> Result<(), LockError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let save = || -> anyhow::Result<()> {
            let locks: Vec<_> = self
                .storage
                .iter()
                .map(|entry| StoredLock {
                    repository: entry.key().repository,
                    branch: entry.key().branch,
                    hash: entry.key().hash,
                    description: entry.resource.description.clone(),
                    owner: entry.owner.clone(),
                    locked_at: entry.locked_at,
                })
                .collect();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let temporary = path.with_extension("tmp");
            let mut file = std::fs::File::create(&temporary)?;
            serde_json::to_writer(&mut file, &locks)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)?;
            Ok(())
        };
        if let Err(err) = save() {
            self.storage.clear();
            for (key, data) in before {
                self.storage.insert(key, data);
            }
            return Err(LockError::internal(format!("Cannot persist locks: {err}")));
        }
        Ok(())
    }
}

#[async_trait]
impl LockStore for LocalLockStore {
    async fn lock_resources(
        &self,
        owner_id: &str,
        repository: RepositoryId,
        resources: &[LockResource],
    ) -> Result<Vec<LockData>, LockError> {
        let _transaction = self.transaction.lock();
        for resource in resources {
            let key = LockKey {
                repository,
                branch: resource.branch,
                hash: resource.hash,
            };
            if self
                .storage
                .get(&key)
                .is_some_and(|lock| lock.owner != owner_id)
            {
                return Err(LockError::internal("resource already locked"));
            }
        }
        let before = if self.path.is_some() {
            self.snapshot()
        } else {
            Vec::new()
        };
        let mut locks = Vec::<LockData>::with_capacity(resources.len());
        let timestamp = util::time::timestamp();
        for resource in resources {
            let key = LockKey {
                repository,
                branch: resource.branch,
                hash: resource.hash,
            };

            let lock = LockData {
                resource: resource.clone(),
                owner: owner_id.to_string(),
                locked_at: timestamp,
            };
            // `DashMap::entry` is safe here as it is not held across any awaits and no other locks are acquired while held
            #[allow(clippy::disallowed_methods)]
            match self.storage.entry(key) {
                Entry::Vacant(entry) => entry.insert(lock.clone()),
                Entry::Occupied(entry) => {
                    if entry.get().owner == lock.owner {
                        continue;
                    }
                    return Err(LockError::internal("resource already locked"));
                }
            };

            locks.push(lock);
        }

        self.persist_or_rollback(before)?;

        Ok(locks)
    }

    async fn query_locks(&self, query: LockQuery) -> Result<Vec<LockData>, LockError> {
        let _transaction = self.transaction.lock();
        let mut locks = Vec::new();

        match query {
            LockQuery::Repository(repository) => {
                for lock in self.storage.iter() {
                    if lock.key().repository == repository {
                        locks.push(lock.value().clone());
                    }
                }
            }
            LockQuery::RepositoryBranch(repository, branch) => {
                for lock in self.storage.iter() {
                    let key = lock.key();
                    let value = lock.value();
                    if key.repository == repository && key.branch == branch {
                        locks.push(value.clone());
                    }
                }
            }
            LockQuery::RepositoryBranchDescription(repository, branch, description) => {
                for lock in self.storage.iter() {
                    let key = lock.key();
                    let value = lock.value();
                    if key.repository == repository
                        && key.branch == branch
                        && value.resource.description == description
                    {
                        locks.push(value.clone());
                    }
                }
            }
            LockQuery::OwnerRepository(owner, repository) => {
                for lock in self.storage.iter() {
                    let key = lock.key();
                    let value = lock.value();
                    if key.repository == repository && value.owner == owner {
                        locks.push(value.clone());
                    }
                }
            }
            LockQuery::OwnerRepositoryBranch(owner, repository, branch) => {
                for lock in self.storage.iter() {
                    let key = lock.key();
                    let value = lock.value();
                    if key.repository == repository && key.branch == branch && value.owner == owner
                    {
                        locks.push(value.clone());
                    }
                }
            }
            LockQuery::HashRepositoryBranch(resource, repository, branch) => {
                let key = LockKey {
                    hash: resource,
                    repository,
                    branch,
                };

                if let Some(lock) = self.storage.get(&key) {
                    locks.push(lock.value().clone());
                }
            }
            _ => {
                return Err(InvalidArguments {
                    reason: "unsupported lock query".into(),
                }
                .into());
            }
        }

        Ok(locks)
    }

    async fn check_locks_status(
        &self,
        repository: RepositoryId,
        resources: &[LockResource],
    ) -> Result<Vec<LockData>, LockError> {
        let _transaction = self.transaction.lock();
        let mut locked = vec![];

        for resource in resources {
            let key = LockKey {
                repository,
                branch: resource.branch,
                hash: resource.hash,
            };

            if let Some(lock) = self.storage.get(&key) {
                locked.push(lock.value().clone());
            }
        }

        Ok(locked)
    }

    async fn unlock_resources(
        &self,
        owner_id: &str,
        validate_user: bool,
        repository: RepositoryId,
        resources: &[LockResource],
    ) -> Result<Vec<LockResource>, LockError> {
        let _transaction = self.transaction.lock();
        // Validate the complete batch before removing a single lock.
        for resource in resources {
            let key = LockKey {
                repository,
                branch: resource.branch,
                hash: resource.hash,
            };
            let lock = self.storage.get(&key).ok_or(LockNotFound)?;
            if validate_user && lock.owner != owner_id {
                return Err(LockNotOwned.into());
            }
        }
        let before = if self.path.is_some() {
            self.snapshot()
        } else {
            Vec::new()
        };
        for resource in resources {
            let key = LockKey {
                repository,
                branch: resource.branch,
                hash: resource.hash,
            };

            // Preflight covered the whole batch under the transaction guard.
            // Repeated resources in a request are released only once.
            self.storage.remove(&key);
        }

        self.persist_or_rollback(before)?;
        Ok(resources.to_vec())
    }
}
