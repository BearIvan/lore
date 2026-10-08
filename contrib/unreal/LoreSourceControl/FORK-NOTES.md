# BearIvan integration

Source: https://github.com/BenVlodgi/UE-LoreSourceControl (MIT).

Use the Lore CLI built from this fork. Log in once using the plugin's **Log in**
button or `lore auth login lore://10.8.0.1:41337`. Leave Identity blank to use
the signed-in identity. The fork's client and Keycloak adapter refresh the session automatically; do not
paste access tokens into editor settings. A new login is needed after logout,
administrative session revocation, or expiration of the refresh session.

Enable **Using Locking**. Check Out acquires a lock and makes the asset writable.
Status compares owners to the authenticated subject ID, and failed lock queries
stay Unknown and block submission. The server rejects pushes touching another
user's locks. Administrators must release the foreign lock explicitly before
overriding it; the upstream Check In Over Lock menu cannot bypass server checks.

This source is prepared for Vircon. It does not initialize or import that project.
