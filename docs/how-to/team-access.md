# Team access and Unreal locking in the BearIvan fork

This fork enforces ordinary write access on the public gRPC, QUIC and HTTP
interfaces. A matching repository grant remains readable for compatibility;
`write`, `admin`, or `owner` is required for content upload, branch publication,
branch creation/deletion and lock mutations. Repository administration,
protection metadata and raw mutable-storage APIs require `admin`. Specific
privileged permissions such as `obliterate` remain explicit. A service-account
flag alone no longer bypasses branch protection.

For the VPN deployment, administrators manage per-repository grants on the server:

```sh
sudo lore-access repositories
sudo lore-access grant alice VirconWorlds --access read
sudo lore-access grant bob VirconWorlds --access write
sudo lore-access grant lead VirconWorlds --access admin
sudo lore-access revoke alice VirconWorlds
sudo lore-access grants bob
```

The helper source is in `contrib/keycloak/lore-access.py`. Its paths target this
deployment's existing root-only Keycloak management account and repository catalog.
Changing grants logs the affected user out. Signed access tokens may retain their
old rights until they expire; this deployment uses a 120-second access-token lifetime.
Legacy empty grant arrays must be migrated to `["read", "write"]` before deployment.
New users still start with no repository grants.

Use native Lore authentication rather than passing bearer tokens to each command.
For this deployment, the Keycloak adapter returns refresh credentials through a
backward-compatible extension of `UrcAuthApi.UserToken` (field 5) and accepts them
in `RefreshAuthSessionRequest` (field 1). The native client refreshes expired
stored credentials before selecting an identity or exchanging repository tokens.
Supplied `--identity-token` and `--access-token` values are never replaced by
cached credentials. Refresh responses must retain the identity and issuer and
pass the client's token-recipient check before they are saved.

To use local repository-administration grants without an external ReBAC API:

```toml
[server.grpc_public_services]
local_repository_administration = true
```

```powershell
lore auth login lore://10.8.0.1:41337
```

The user signs in through their browser once. Lore retains the refresh credential
in its token store and refreshes short-lived access tokens. The adapter forwards
device-login and refresh grants to Keycloak, which remains the identity provider
and token signer; the adapter has no token-signing key. Repository administration
in local mode uses role checks instead of requiring a legacy ReBAC service.
Use the Windows client provided with this fork, rather than the earlier 0.10.1
client or the old PowerShell token wrapper. A revoked or expired refresh session
still requires a new browser login.

The community Unreal plugin is included under `contrib/unreal/LoreSourceControl`,
with its original MIT license and upstream attribution. In its settings, enable
**Using Locking**, select the fork's `lore.exe`, and leave Identity blank so the
client selects the authenticated identity. **Check Out** acquires the lock and
makes an asset writable. The plugin resolves the current subject ID before
comparing lock owners and propagates lock-query failures; an unknown lock state
blocks submission.

Both branch-push APIs reject revisions touching a foreign locked path, including
deletion and moves. Lock mutations and the push's check/head update share a local
gate to prevent a concurrent checkout from racing publication. This gate assumes
a single server instance; a distributed lock backend needs distributed
coordination before this enforcement can span multiple writers.

Persist local locks across restarts with:

```toml
[lock_store]
mode = "local"
path = "/srv/lore/locks.json"
```

Snapshots are atomic on the Linux deployment. A failed persistence operation
rolls back the in-memory mutation. Batch lock/unlock operations validate the
entire batch before mutation. With no path configured, local locks remain
in-memory. Administrators may explicitly release another user's lock; the
plugin's upstream **Check In Over Lock** operation cannot bypass server checks.

Locks are per branch and prevent overwriting a locked path; this fork does not
require every file edit to acquire a lock first or implement Perforce path ACLs.
