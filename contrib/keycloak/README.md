# Lore Keycloak administration

Install `lore-access.py` as `/usr/local/sbin/lore-access` on the Lore server.
It uses the existing root-only files under `/etc/lore-auth/` and the trusted CA.
Repository administration uses the management service account. Session settings
use the realm administrator in `bootstrap.json`; credentials are never printed.

## Login lifetime

Show current values (seconds):

```sh
sudo lore-access session-settings
```

Allow a login to last one week, including periods with the Editor or computer
turned off:

```sh
sudo lore-access session-settings --duration 7d
```

Supported units: `s`, `m`, `h`, `d`, `w`. For example, use `8h`, `30d`, or `1w`.
The command sets both idle and absolute session limits to the same duration in
the dedicated `lore` realm, including client and Remember Me defaults. Activity
does not extend the absolute deadline. A shorter explicit `lore-cli` client
override is detected before any changes are made.

Access tokens retain their short lifetime (currently 120 seconds). The updated
Lore client saves refresh credentials and renews access tokens automatically on
the next operation. After the configured login lifetime, sign in again. Sign
out, account disabling, password resets, and administrator session revocation
can end a login earlier. The setting is stored in Keycloak's database and
survives service restarts. Log in again after changing the setting so credentials
issued under the previous limit are replaced.

## Repository permissions

```sh
sudo lore-access grant alice VirconWorlds --access read
sudo lore-access grant bob VirconWorlds --access write
sudo lore-access grant lead VirconWorlds --access admin
sudo lore-access revoke alice VirconWorlds
```

Grant changes revoke current sessions; affected users must sign in again.
