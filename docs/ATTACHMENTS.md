# Encrypted attachment storage

This document describes the deployment-owned attachment gateway. For the independent broker with owner-configured storage per Space, see the [storage broker](../crates/elo-storage/README.md); its credential handling and authorization differ from this gateway.

## Product limits

| Limit | Value |
|---|---:|
| Plaintext file size | 5 MiB (`5 * 1024 * 1024` bytes) |
| Encrypted attachment storage per Space | 50 MB (`50_000_000` bytes) |
| Encryption chunk | 1 MiB |
| Upload reservation | 15 minutes |
| Upload/download authorization | short-lived bearer token; download tokens last 5 minutes |
| Unlinked uploaded object | removed after 24 hours |

The server accounts for actual encrypted bytes. Active upload reservations count against the same Space quota, so concurrent uploads cannot overbook it.

## Storage boundary

Message records contain a provider-neutral, end-to-end encrypted attachment descriptor. The binary body is never stored in a message or Replica object. A deployment-owned gateway streams ciphertext to an `AttachmentStorage` provider.

The initial hosted provider is MEGA through a loopback-only MEGAcmd WebDAV endpoint. S3-compatible storage and a local provider for self-hosting and tests use the same interface. Provider credentials and paths never appear in the application, attachment descriptor, Space record, or logs.

Provider objects use opaque Space and object IDs:

```text
spaces/<space_id>/<attachment_object_id>
```

Original filenames and MIME types remain inside the encrypted `file.shared`
record. While uploading, the filename is also carried in the signed, encrypted
ephemeral upload hint addressed to the same permitted chat audience; the
transport does not receive it as plaintext metadata.

## Cryptography

Each attachment gets an independent random 256-bit key and nonce prefix. The client encrypts the file in 1 MiB chunks with XChaCha20-Poly1305. A monotonically increasing chunk counter completes each nonce. The container authenticates its header, every chunk, the final size, and a whole-ciphertext SHA-256 digest.

The client streams both encryption and decryption. A storage provider receives only ciphertext. The attachment key is available only to the recipients of the signed, encrypted message metadata.

## Upload

1. The native picker copies at most 5 MiB into an app-private, mode `0600` staging file.
2. The client encrypts the staging file while calculating its encrypted size and digest.
3. The Space service atomically reserves encrypted quota and returns a short-lived upload token.
4. The gateway verifies membership, token, expected length and digest while streaming the ciphertext to the configured provider.
5. The client commits the upload, publishes a `file.shared` record carrying an attachment descriptor, and links the stored object to that message. The descriptor distinguishes external attachment storage from the legacy Replica object reference without changing the signed record protocol version.
6. App-private staging files are removed after success; a bounded, encrypted local copy is retained for reuse. Interrupted reservations expire. An uploaded object that never becomes linked to a message is removed after 24 hours.

No attachment message is published for an incomplete upload.

After the linked message commits locally, the transfer response includes the
current local view with a native revision. The UI applies it and clears the
attachment draft immediately; network synchronization and staging-file cleanup
do not gate chat visibility. The ordinary paged history reader supplies the
committed row, with the same profile/Space checks as text messages. A local-view
failure after commit must not report the upload as failed and invite a duplicate
send; normal synchronization can refresh that view later.

## Download

The client verifies the signed `file.shared` record and first checks its encrypted local cache. On a cache miss it asks the Space service for a short-lived download token. The gateway rechecks current Space membership, streams the provider object, and reports its expected encrypted length. The client verifies the ciphertext digest and authenticates and decrypts every chunk. A partial or damaged file is never presented as complete.

Downloaded images appear directly in the conversation without a save dialog.
On mobile, holding the image opens system sharing for the original file, including
the system's save actions. Other files use the native save dialog. Already cached
files are read locally, including offline, without another server download.

The cache contains ciphertext only, isolated by local profile and Space, with a
128 MiB budget per Space. Oldest unused entries are evicted first. Reading a cache
entry still verifies the selected profile, signed message, deletion state and
file integrity. Removing the local profile or Space also removes its cache.
Server expiry does not delete a previously downloaded local copy. This cache is
not a permanent backup, and files saved outside the app before this feature was
added are not imported automatically.

Chat previews are decoded natively from JPEG, PNG, GIF or WebP into a static image
of at most 640 × 640 pixels. Decoding is serialized and bounded by image dimensions
and memory limits; unsupported or oversized images retain the file presentation.
Sharing uses the complete original, not the preview. Explicit exports use private
temporary plaintext files; Android retains its receiver copy until later cleanup
because the receiving app may read it after the chooser closes.

## Transfer presentation and cancellation

The transferring device's upload and download rows show determinate byte
progress whenever the transport exposes a total size. The active row uses a
compact status caption and a small inline `Cancel` text action; cancellation is
not presented as a primary button. Cancelling aborts the network transfer and
does not show an error dialog. A cancelled upload remains selected so the user
can retry or remove it, while a cancelled download leaves no partial file for
the system save dialog.

Other currently connected, authorized chat participants can see an ephemeral
tile with the filename, size and **Uploading…**. Remote tiles have no percentage,
download action, unread marker or notification. Cancellation removes the tile;
a failed or expired upload becomes **Upload interrupted** for a bounded period.
The native uploader renews a 30-second activity lease about every ten seconds;
each terminal hint expires 60 seconds after publication. These hints are best-effort and require
the [live transport implementation](../crates/elo-core/src/realtime.rs).

A ready hint triggers ordinary verified message catch-up and retains the tile
until the actual `file.shared` descriptor arrives. Its attachment ID replaces
the transient tile; an already committed/deleted record suppresses late ready
hints. Only the complete ordinary attachment message can enter history,
unread counts or notification delivery. The uploading device keeps its existing
local progress row, without a duplicate remote tile. Ephemeral states are not
restored from a backup or replayed as attachment messages.

After reservation, cancellation makes a bounded best-effort request to revoke the
unlinked upload. The hosting cleanup worker removes its provider object and
releases the reservation. The reservation lease remains the fallback if that
request cannot reach the server. Local-provider staging files are also removed
when a transfer future is dropped. Linking is the send boundary: once linking
starts, the client finishes the local commit rather than reporting a cancellation
for a message that may already be linked. Cancellation cannot remove a linked file.

## Retention and cleanup

Server copies expire after **1 hour by default**. The primary owner can choose
**1, 12 or 24 hours** in Space Settings → Details. The deadline starts at the
upload reservation and is included in the signed attachment descriptor.
Changing the policy affects future uploads; existing descriptors keep their
original deadlines. Loading a legacy Never/days policy selects one hour for
future uploads without rewriting existing records.

The attachment tile and a cached image show **Expires: {date}**, using the
reader's local day, month and time without a year. At the signed deadline the
caption becomes **Expired**, and an uncached tile no longer offers a download.
A server-confirmed manual removal shows **Removed**; an unexplained missing
object shows **Unavailable**. Cached image previews remain usable and shareable.
No status polling is needed to display a known deadline.

Automatic expiry uses signed service metadata, never provider modification
times. Expired downloads are denied immediately. The background cleanup worker
deletes ciphertext from the storage provider, retrying failures; provider
outages can delay physical deletion. Manual cleanup first previews the number
of files and bytes, then requires confirmation.

Details separates retention, cleanup age and its full-width preview action by the shared content density. When no files qualify, show “No attachments are old enough to remove.” as persistent red status text immediately above Preview attachment cleanup, without a toast or confirmation. Changing the age or retention clears this result.

Deleting or expiring an object removes only its server copy and releases Space quota. The signed message and local copies already saved by members remain. Status values are `available`, `expired`, `deleted`, and `missing`.

Operational backups have their own retention. Attachment expiry does not
rewrite earlier backups or erase files already exported to another app.

Deleting a Space first removes every known provider object and then removes its provider namespace. Provider deletion is idempotent; an already missing object is a successful cleanup result.

## Backups and recovery

Profile backups keep signed attachment references and cryptographic metadata but exclude attachment bodies. After recovery, a user can download a body only while it is still available and the recovered identity remains a member of that Space.

## Deployment configuration

`elo-team` accepts one optional `attachment_storage` entry in its private host configuration:

```json
{
  "attachment_storage": {
    "provider": "mega_web_dav",
    "base_url": "http://127.0.0.1:18930/<private-path>"
  }
}
```

An S3-compatible deployment supplies its HTTPS endpoint, region, bucket and access credentials in the same private server configuration. Ordinary clients never receive this configuration.
