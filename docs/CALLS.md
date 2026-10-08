# Calls

## Product and deployment contract

The accepted scope is direct audio/video calls, group calls attached to a
conversation, screen sharing, live presence, reconnect and multi-device handling.
Use **Start session**, **Join session** and **Session active** in the interface. The protocol distinguishes `direct` and `group`.
Use these names consistently in source, documentation and deployment configuration.

Calls reuse the existing Identity, Credential and Authority model. The scope is
the signed `(hosting_space_id, space_id, stream_id)`, never a presentation group.
The hosting ID binds the user-facing Space; the other IDs identify the signed
conversation. This matters when personal conversation genesis is shared between
local compartments. Direct calls use
the existing contact/Direct conversation flow. Starting, joining and publishing
require the current device credential and the conversation's Post capability.

Application and media services are separate roles. They can run on one host or
on separate hosts; this reference layout is not a statement about the current
publisher deployment:

| Application server | Media server |
| --- | --- |
| Spaces, Replica, wake, call authorization and realtime call control | SFU and TURN |

The media server can serve rooms from many Spaces. Placement is by active call,
not by identity or Space. SFU and TURN can initially share one machine. Resource
limits, health checks and credentials remain separate for each service. This
two-server layout isolates media load; it does not provide high availability.

The configured deployment API returns the selected call-control, SFU and TURN
endpoints and short-lived authorization. Never compile individual media-server
IP addresses or static media credentials into the app. Keep the configured API
trust boundary: private installations must not fall back to official services.
The ordinary HTTPS gateway handles control traffic; media connects directly to
the selected SFU/TURN through the required UDP/TCP ports. Adding or replacing
media servers does not require a mobile release through the implemented discovery path.
Drain existing rooms before shutting down a node; moving an active room is not
seamless live migration.

Direct conversations support ringing calls with **Answer**, **Decline** and
**Cancel call**. Group sessions remain joinable from the conversation or the
**Calls** filter in Buzz. Starting a group does not ring its members. Members join from the conversation
or **Buzz → Calls**; there is no invitation picker in the call interface.
The signed conversation kind, not its current participant count or title,
determines the behavior.

The interface presents one compact, draggable floating call widget across the
unlocked app, including More and settings. It overlays the current screen without
changing the header or message-list layout. Other
available sessions belong in Calls rather than additional persistent control bars.
An incoming invitation uses this same widget, with its caller/conversation, Space,
**Answer** and **Decline**. It does not open a second, automatic incoming-call
dialog. A matching CallKit or Telecom presentation takes precedence over the
in-app invitation controls and ringtone; another ongoing call remains available.
System-presentation hints are matched to the exact invitation and local profile,
independently of the network admission check. They never authorize media.
Answering while another call is active requires an explicit **End & answer**
confirmation. Admission is validated before ending the current local call;
declining the incoming invitation leaves it running. Expanded video, participant
controls and desktop screen sharing remain available.

The initiating participant must acquire media permission and receive acceptance of
its signed Media command before a new session is advertised as ready. This sets
`ready` and the original `ready_at`; Subscribe, Start, Join and ConnectMedia alone
do not mark a session ready. Camera capture remains an explicit action.

Before notification, the sender checks `/calls/v1/state` with a signed Subscribe
command. Existing membership, hosted-Space admission, configuration and replay
checks apply; this endpoint cannot start or join a call. Ring targets bind the
hosting Space, conversation, call, recipient and a specific invitation ID, with a
60-second invitation deadline. The target is authenticated and encrypted with a
key derived from the recipient's wake scope capability. The relay never receives
that capability or a profile/media key.

Ring delivery requires an authorized, unmuted recipient scope and a separately
opted-in installation. The relay deduplicates each invitation, expires it, and
never queues a ring for later playback. iOS uses the installation's registered
APNs VoIP environment; ordinary notifications retain their own route. An accepted
provider request is not an answer, read receipt or guarantee of device delivery.
Session advertisements do not increase the unread-message badge. Cancellation,
answer on another device and expiry are reconciled against signed live state;
delayed push delivery must never revive a terminal invitation or start capture.

Deploy matching call-control, wake and client versions. Native signaling,
notification code and synthetic tests do not establish physical acceptance of an
installed release. Real lock-screen, cold-start and multi-device tests remain
separate gates.

## Media and privacy

Direct calls prefer authenticated WebRTC P2P with TURN fallback. Encrypted SDP
retries are idempotent: a repeated offer reuses its answer and an already applied
answer is ignored. Buffered and live signals are serialized; a new ICE negotiation
is still processed. Group calls use
an SFU; never build a full mesh. LiveKit is the first implemented provider, behind a
provider interface. Audio, camera and screen sharing are tracks in one call.

Replica never stores or transports media. It may carry bounded encrypted control
packets and key envelopes. Call control uses a persistent authenticated connection,
not message polling. SDP/ICE and media keys are signed and encrypted for approved
device credentials. Both the encrypted payload and the routing envelope bind the
current session epoch, so delayed signaling from before a Leave/rejoin is rejected. Do not log them or embed media keys in SFU tokens.

Group media requires additional end-to-end encryption above WebRTC's transport
encryption. Clients obtain keys through elo's authenticated encrypted channel;
the SFU and call-control service never receive those keys. Rotate keys on membership
changes. Stop publishing when fresh authorization/key distribution cannot be
established. Unsupported platform encryption must fail closed.

Servers still observe network addresses, timing, opaque conversation identifiers,
participant sessions and traffic volume. There is no recording, transcription,
PSTN, anonymous room or permanent media storage in this scope.

## Session semantics

- One active call per conversation; concurrent starts return the same call.
- Start and join are idempotent. One media session per identity within a call;
  the first credential to join owns that identity’s participation.
  A restored/linked profile is the same participant, not a second test person.
  A second credential for that identity is rejected with `already_joined` and the
  client explains the conflict instead of suggesting a network failure. Leave on
  the first device before joining on the second; simultaneous two-person tests
  require separate identities.
- Direct Start creates a bounded ringing attempt. The recipient's Join answers
  it; Decline ends that attempt for all devices, Cancel is restricted to its
  initiator while ringing, and End or Leave terminates an active direct call.
  A direct participant lease expiring also ends the call.
- Group Start is active without a ring. Invite creates a recipient-specific
  attempt; Decline consumes only that invitation and Leave removes only the
  leaving participant. Dismissing an available session locally does not end its
  room. A late Decline/Join carries the invitation ID and cannot act on a newer
  invitation for the same room.
- Presence counts identities. Client heartbeats run every 5–10 seconds;
  participant expiry is 30 seconds. The last explicit group Leave ends its room.
  The configurable 15-second empty-room grace applies to unexpected group expiry.
  Ringing expires after 60 seconds even if the caller keeps sending heartbeats.
- One device participates in one call at a time. Answering or joining another
  requires an explicit switch; rejecting that switch preserves the current call.
- Calls continue across navigation. A persistent compact control surface exposes
  microphone, speaker and leave; the full call view adds camera, participants and
  desktop screen share. Speaker mute silences all remote playback locally, remains
  in effect across navigation/reconnect and resets on a new call. It never changes
  the microphone grant or another participant’s media state.
- Camera/screen capture never starts implicitly. Cancel/failure/leave stops all
  local capture and releases tracks.
- Initial operational limits: 25 participants, 12 camera publishers, one screen
  share, camera up to 720p/30 fps and screen up to 1080p/15 fps. These are
  configuration limits, not measured capacity guarantees.
- Use adaptive subscriptions/simulcast and avoid high-resolution subscriptions
  for hidden tiles. Measure CPU, bandwidth, packet loss, reconnects and TURN ratio.

Desktop call controls expose Share screen in the expanded view,
with Stop sharing while active. Capture uses the system getDisplayMedia picker
(window/display choices depend on the OS webview), with no system-audio capture.
Cancelling the picker leaves the call connected; publishing errors release newly
acquired capture without ending microphone/camera communication. Stop releases
local tracks immediately, including the SFU publication clone before waiting for
network unpublication. Starting screen publication first obtains the signed
call-control media grant; the SFU rejects sources not yet allowed by that grant.
Because the grant and SFU permission update travel over separate connections,
group publication also waits for the SDK's local source permission before sending
the track. This wait is bounded to five seconds and is cancelled on leave or
disconnect. Existing grants do not add a delay. A failed publication rolls back
that grant. Group rekey/reconnect republishes the existing screen track.
Remote unsubscription refreshes tiles after the provider has cleared the old
publication; stopping a share must not leave its last frame in the participant view.
Speaker activity updates reuse the existing playback stream and provider bindings;
speaking alone must not detach/restart audio or video. A replaced provider track
or underlying media track gets a fresh binding, and unsubscribe/disconnect clears
obsolete bindings. A regression covers voice changes and track replacement.
The main group stage prefers an active screen presenter unless a participant is
pinned. While sharing, the local participant preview also shows the shared screen
instead of the camera, both in the two-person overlay and the group strip. Stopping
sharing restores the camera preview (or initials if the camera is off). Screen
previews fit the complete captured content without cropping.
Mobile native screen publication remains unsupported. macOS bundles include
camera/microphone purpose strings and release entitlement inputs. The current Mac
build passes controller/provider lifecycle tests. The user confirmed working
desktop screen sharing in the Mac1006/iPhone1050 test on September21.
Windows/Linux native acceptance remains open.

A transient control-connection loss stops the previous media adapter and enters
Reconnecting. A signed heartbeat retries after 1.5 seconds and revalidates the
current call before reconnecting media. A fixed 25-second recovery deadline
releases capture if it cannot recover; authorization denials and ended calls are
terminal immediately. Old-session results and unrelated deployment socket closures
must not interrupt the current call. Socket opening/closing always settles its
pending promise so later commands can reconnect. This bounded control recovery is
covered by automated tests. Physical Redmi8 group audio/video recovery after a
10-second Wi-Fi interruption passed on September21. iPhone1076 foreground direct
recovery after an approximately ten-second network interruption later passed.
Long outages and background network handover remain unverified.

The September 21 Mac/iPhone foreground audio/video, speaking stability and desktop
screen-sharing results describe those earlier tested binaries. They are historical
acceptance evidence, not acceptance of every later session lifecycle or platform.

## Authorization boundary

Signed commands bind deployment audience, hosted Space, conversation, exact configuration head,
device credential, nonce and expiry. A self-certified device proves identity but
does not establish membership. Verify the signed genesis/configuration chain
with elo-core before checking capabilities. Persist the highest accepted head,
reject rollback/forks and revalidate active sessions on configuration changes.
Only the opaque accepted head and sequence are persistent. Public membership
proofs are checked in memory and must be supplied again after a service restart.

Stream proofs alone cannot prove that the enclosing hosted Space still exists.
Production admission also needs the hosting service's current membership/deletion
decision. Deleted accounts and removed members must not reopen a call using an
old signed configuration. Keep this check in the service integration, not in UI.

Private conversation controllers now publish each signed configuration to hosting
before committing it locally. Hosting verifies the full authority chain and keeps
only its opaque head and sequence. Call admission requires that exact current
head, as well as current Space membership/device authorization. Unknown private
heads, rollback and forks fail closed. A new private chain must register its
controller-signed initial configuration before later updates; pre-registration
private conversations are not silently bootstrapped from a possibly stale proof.
General uses the host's authoritative current configuration directly.

Short-lived SFU tokens alone do not revoke a connected participant. Self-hosted
LiveKit can refresh connection tokens; revocation requires server-side participant
removal plus media-key rotation. Drain/restart must preserve authorization fences.

## Platform integration and acceptance

The shared controls preserve full-screen video, local preview, camera switching,
microphone mute, audio-output selection and desktop screen sharing. Mobile screen
publication is not implemented. System Answer may use an already enrolled
call-only delegation while the profile vault stays locked; a push alone never
starts capture or unlocks the profile.

After an authenticated profile refresh, eligible conversations receive a signed
call-only credential scoped to the hosting Space, exact conversation, current
configuration head, parent device credential and pinned call service. Protected
native storage contains this limited signing/decryption key and the incoming
ring target capability, not profile signing keys, history keys or the wake
notification-send key. Delegations expire after at most 24 hours and refresh
before expiry. Enrollment reevaluates membership, hidden conversations and
blocked direct contacts on every pass; matching valid keys are reused. Live
admission still checks the current hosted permissions. An expired or revoked
binding cannot answer until a fresh authorized enrollment is available.

Logout and disabling incoming calls remove protected enrollment and stop its
native ownership. Native callbacks and snapshots expose public state only. The
background worker verifies the restored proof, encrypted target, exact live
invitation and current participant state before signing Join or Decline. A
bounded Android Decline worker can execute directly from the notification
receiver without creating a WebView or opening the vault. Failed dispatch remains
pending for later reconciliation; it is not reported as a successful decline.

Android integrates a self-managed Telecom account, incoming-call notifications,
an incoming Activity and a phone-call foreground service. Full-screen presentation
depends on platform permission/settings and has a notification fallback. Explicit
answer validates the target and permissions before capture. Microphone and camera
foreground-service types are added only for the actual media use; boot and stale
intents cannot resurrect a call. The portrait orientation policy is unchanged.

iOS uses CallKit/PushKit for real incoming invitations. Verified outgoing sessions
also register with CallKit before media starts, so the system can offer End & answer
when another invitation arrives. System end/mute actions bind the exact capture
UUID and local activation; an old callback cannot stop a replacement call. Media
epoch resets preserve that system call, while terminal cleanup ends it. CallKit
owns audio-session activation for system calls; direct WebRTC and encrypted LiveKit group adapters
respect that activation. Native signaling, participant state and encrypted group
key exchange run independently of WebView timers. Media keys stay at the endpoints;
frames and protected credentials do not cross WebView IPC. The admitted delegate
remains pinned for signaling; the original device key may update its capture state
or invite a group member without replacing that transport. A second device of
the same identity cannot take over the admitted participant.

The native group worker keeps the same key during a reconnect within the same
epoch. Membership changes advance the epoch, dispose the old room/key, and require
fresh recipient-encrypted key distribution. An unexpected same-epoch member or key
change, revoked authorization or unavailable encryption stops capture. Native
permission, compilation and local WebSocket tests are not physical audio acceptance.

An active audio session alone does not prove indefinite background execution while
waiting alone. If the OS suspends an idle session, its server lease may expire;
no silent playback or extra recording is used solely to keep the app awake.
Apple's [audio-session guidance](https://developer.apple.com/library/archive/documentation/Audio/Conceptual/AudioSessionProgrammingGuide/AudioGuidelinesByAppType/AudioGuidelinesByAppType.html)
still applies. Acceptance must cover ongoing media, waiting alone, a locked vault,
process restart, system audio activation and network handover for the exact build.

Private hosting admission waits up to two seconds for the Space client instead
of treating a momentary lock collision as lost membership. After acquiring it,
the endpoint checks pending deletion and current membership/device/scope again;
timeout and failed authorization still fail closed. This stays within the call
service's three-second admission deadline. The [hosting admission code and tests](../crates/elo-team/src/hosting/calls.rs)
cover the concurrency boundary; native acceptance remains separate.

Screen publication is currently desktop-only. Future mobile implementation would
need ReplayKit on iOS and MediaProjection on Android; those adapters are not implemented. Keep unsupported actions hidden
or clearly unavailable. Reuse existing type, spacing, safe-area, dialog and
translation conventions. Load RTC code only when needed.

The full acceptance matrix must cover real two-client direct audio/video and forced TURN; a group of
at least three; active-call discovery; concurrent starts; multiple recipient
devices; background ongoing sessions; network loss/reconnect; capture cleanup;
revocation/key rotation; and cross-Space isolation. Load-test a 25-person call and
parallel rooms before making capacity claims. A server health check or simulated
UI does not count as successful media delivery.

## Implemented control foundation

`elo-core::calls` signs deployment-bound commands and encrypts signed media-key,
SDP and ICE payloads for a selected device. Local app operations
`call_authorization`, `call_encrypt_signal` and `call_open_signal` use the current
profile, conversation permissions and blocked-user state. A target Space must
match its joined catalog entry; signing does not rebuild the messaging view.

`elo-call-service` supplies an executable WebSocket service. It implements atomic
start-or-join, first-device admission, participant/media limits,
heartbeat expiry, unexpected-disconnect grace and targeted encrypted signals. New members,
leaving members and expired participants advance the media-key epoch. The client distributes a fresh signed, recipient-encrypted media key for every new epoch. Each epoch uses a separate SFU room; the previous room is deleted.
Conflicting signed configuration branches block that conversation; a valid newer
configuration ends the current room until safe in-place rekeying is available.

SQLite retains opaque head fences and 60-second replay receipts, with a separate
exclusive process lock. Active calls do not survive a control-service restart.
The public-proof cache is bounded to 64 MiB of encoded proof material (actual
in-memory structures add overhead), and idle proofs are evicted. There is a
4096-scope fence cap; it is an initial implementation bound, not a platform
capacity claim. Durable fences must not be discarded to reset that limit.

The hosting operator listener optionally exposes `/internal/calls/admission`
behind a dedicated 256-bit bearer key. It is absent from the public router and
disabled without configuration. Each WebSocket operation checks live hosted
membership. Subscribed sessions are checked again every five seconds and fail
closed when admission is unavailable. Credential binding, bounded frames,
connection/command limits and slow-consumer disconnects constrain the transport.
After an idle proof is evicted, a client must supply a fresh proof to subscribe.

## App and service integration

The app obtains call control from the trusted joined hosting profile's pinned
`call_url`; the built-in service defaults to `/calls/v1` on its hosting origin. The signed `connect_media` operation returns an expiring room-scoped
provider token and temporary TURN credentials. These endpoints are configuration,
not embedded IP addresses or a fallback to official infrastructure. A future
multi-node deployment can change the provider endpoint behind the same API.

The shared app includes conversation call actions, the Calls filter in Buzz,
one persistent compact floating widget and an expanded participant/video view. Calls continue
across navigation; answering another call uses the explicit switch flow. Direct
calls authenticate SDP/ICE through elo's signed encrypted signals. Group calls use
LiveKit with a fresh 256-bit key per membership epoch: the desktop adapter uses its
encryption worker, while mobile adapters and signaling are native. No plaintext
fallback is offered when the runtime lacks the required encryption API.

The server provider uses short-lived join-only tokens, a private loopback admin
API, per-participant publishing permissions and authenticated temporary TURN.
Host admission validates the current Space member and device on every command
and again every five seconds. General additionally uses the hosting service's
current signed head and, for witnessed General, the independently pinned witness
freshness gate. This does not make the witness a validator of every private-chat
configuration. Removal/invalid admission ends or rekeys the room and removes
the old provider room. Signing keys and media-provider credentials never enter
application bundles. The provider receives opaque session identifiers and media
traffic; it does not receive media encryption keys.

Call control, LiveKit and coturn run as separate services. Recorded synthetic
browser tests exercised direct audio/video, forced TURN, three-person encrypted
group media and membership rekey. Those results do not establish acceptance of
every native build, and server health is not media acceptance.

## Synthetic transport load — 2026-09-21

LiveKit CLI 2.18.7 exercised the QA SFU with H.264 synthetic video, simulated
speakers and the speaker subscription layout. The large case had 25 publishing
sessions (25 audio tracks, 12 video tracks) and 25 separate receiving sessions.
Audio/video publishers share identities; this is 50 sessions, not 62 users. It ran
for 3 minutes and then 30 minutes. Five parallel rooms ran for 10 minutes, each with
five publishers (five audio/three video tracks) and five receivers.

All seven runs had zero connection errors. The 30-minute receiver summary reported
53.6 Mbps aggregate, 221/925 subscribed tracks and 326 lost packets (0.001%). The
five parallel rooms reported 9.6–11.3 Mbps each. The 4-vCPU/8-GiB server averaged
14.12% total CPU, peaked at 16.2%, retained at least 6.617 GiB available RAM and had
no service restarts. Peak sampled network egress was 64.19 Mbps. No source
compilation or service restart ran during measurement.

The first oversized attempt was invalid: the normal 25-session room limit rejected
extra generator sessions even though the CLI exited 0. Corrected isolated rooms
used explicit test caps; elo's normal limit was unchanged. Speaker layout receives
a subset of large-room tracks. These are synthetic SFU transport results, not full
elo E2EE, forced TURN, mobile battery, native background lifecycle or a general
concurrent-user capacity guarantee. These historical measurements must not be
used as acceptance of a later app build or a different deployment.

## Platform acceptance boundaries

Historical phone results are summarized above. The following areas need acceptance
for the exact release being distributed; source compilation alone does not resolve
them:

- Windows/Linux native calls, screen capture and installation acceptance.
- iOS CallKit/PushKit and Android Telecom incoming calls while locked,
  backgrounded and cold-started, including provider environment and opt-in state.
- Answer/reject during another call, cancellation on multiple devices, stale
  invitation expiry, audio routing and interrupted direct/group sessions.
- Long network outages, Wi-Fi/cellular handover and reconnect while the iOS
  WebView is suspended. Native lease renewal alone does not prove these paths.
- Final store-installed notification/media smoke tests on supported runtimes.
  Redmi testing used Android10 with WebView Dev156, not its obsolete WebView87.
- Extended group block/rekey, background/network and native capacity acceptance.
  The synthetic SFU load result does not establish full elo/E2EE/device capacity.

The current source client subscribes in bounded batches of 16, with pauses and resumption
after transient failures, instead of silently stopping at 32 conversations.
The matching service admits up to 4096 scopes per socket. Regression checks cover
70 client conversations and 66 WebSocket scopes, including permission withdrawal.
Previously published clients retain the old cutoff until the coordinated update.
Mobile screen publication remains unimplemented.

Protocol/service tests, synthetic media, package checks and physical acceptance
remain distinct evidence. See [call-service tests](../crates/elo-call-service/tests)
and [native session code](../apps/desktop/src-tauri/src/native_session.rs) for
reproducible implementation checks; those do not replace physical acceptance.

Provider references: [deployment](https://docs.livekit.io/transport/self-hosting/deployment/),
[multi-node routing](https://docs.livekit.io/transport/self-hosting/distributed/),
[encryption](https://docs.livekit.io/transport/encryption/),
[token lifecycle](https://docs.livekit.io/home/server/generating-tokens).
