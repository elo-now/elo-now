import {
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import {
  Phone,
  PhoneOff,
  Mic,
  MicOff,
  Video,
  VideoOff,
  ScreenShare,
  ScreenShareOff,
  ChevronDown,
  Pin,
  PinOff,
  Volume2,
  VolumeOff,
  X,
  UserPlus,
  Maximize2,
} from "lucide-react";
import { useDesktopLayout } from "../PageSurface";
import { ActionDialog } from "../ActionDialog";
import { t } from "../i18n";
import type { Stream, View } from "../model";
import { Calls } from "./controller";
import { callErrorCopy } from "./errors";
import { callKey, scopeKey, type MediaTile } from "./types";
import "./calls.css";
import { NativeVideo } from "./NativeVideo";
import { listenNativeSessionEnd } from "./sessionActivity";
import { useAudioOutput } from "./audioOutput";
import { activeSessions, type SessionStarted } from "./sessionPresence";
import { sessionKey, isRingingFor, invitationKey } from "./attention";
import { appHasAttention } from "../useActivityNotifications";
import {
  readNotificationSound,
  playNotificationSound,
  stopNotificationSound,
} from "../notificationSounds";
import { FloatingCall } from "./FloatingCall";
import { SessionDialogs } from "./SessionDialogs";
import { incomingStatus, listenIncomingCalls } from "./incomingNative";
import {
  AudioOutputIcon,
  AudioOutputMenu,
  audioOutputLabel,
} from "./AudioOutputMenu";
export function useCalls(view: View | null | undefined) {
  const [calls] = useState(() => new Calls());
  useEffect(() => {
    calls.activate();
    return () => calls.dispose();
  }, [calls]);
  useEffect(() => calls.update(view), [calls, view]);
  useEffect(() => {
    if (!view?.identity) return;
    const identity = view.identity;
    let disposed = false;
    let stop: (() => void) | undefined;
    let revision = 0;
    const refresh = async () => {
      const current = ++revision;
      const status = await incomingStatus(identity);
      if (disposed || current !== revision) return false;
      calls.setNativePresented(status.presented);
      return status.active ? calls.adoptNative(status.active) : false;
    };
    void listenIncomingCalls(
      (event) => {
        if (event.action !== "answer") {
          void calls.handleNativeAction(event);
          return;
        }
        void refresh()
          .then((adopted) => {
            if (!disposed && !adopted) return calls.handleNativeAction(event);
          })
          .catch(() => {});
      },
      () => {
        void refresh().catch(() => {});
      },
    )
      .then((unlisten) => {
        if (disposed) unlisten();
        else stop = unlisten;
      })
      .catch(() => {});
    void refresh().catch(() => {});
    return () => {
      disposed = true;
      stop?.();
    };
  }, [calls, view?.identity]);
  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listenNativeSessionEnd((sessionId, activation) => {
      if (!disposed) void calls.nativeSessionEnded(sessionId, activation);
    })
      .then((stop) => {
        if (disposed) stop();
        else unlisten = stop;
      })
      .catch(() => {});
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [calls]);
  return calls;
}
export function useSessionStarted(
  calls: Calls,
  listener: (event: SessionStarted) => void,
) {
  const latest = useRef(listener);
  latest.current = listener;
  useEffect(
    () => calls.subscribeSessionStarted((event) => latest.current(event)),
    [calls],
  );
}
export function CallButton({ calls, chat }: { calls: Calls; chat: Stream }) {
  const state = useSyncExternalStore(calls.subscribe, calls.getSnapshot);
  const existing = state.available[scopeKey(chat)];
  const availableGroup =
    existing?.kind === "group" &&
    !(
      state.active?.call_id === existing.call_id &&
      callKey(state.active) === callKey(existing)
    );
  return (
    <button
      type="button"
      className="icon call-trigger"
      aria-label={t(
        availableGroup ? "calls.open" : existing ? "calls.join" : "calls.start",
      )}
      disabled={!chat.can_post || state.answering}
      onClick={() =>
        availableGroup ? calls.reveal(chat) : calls.requestStart(chat, existing)
      }
    >
      <Phone size={22} />
      {existing && <span className="call-indicator" />}
    </button>
  );
}
function Tile({
  tile,
  name,
  muted = false,
}: {
  tile: MediaTile;
  name: string;
  muted?: boolean;
}) {
  // Native audio already plays in the SDK; only video needs a render surface.
  if (tile.native && tile.source === "audio") return null;
  if (tile.native) return <NativeVideo tile={tile} name={name} />;
  return <WebTile tile={tile} name={name} muted={muted} />;
}
function WebTile({
  tile,
  name,
  muted,
}: {
  tile: MediaTile;
  name: string;
  muted: boolean;
}) {
  const media = useRef<HTMLVideoElement>(null);
  const [tap, setTap] = useState(false);
  const video = tile.stream.getVideoTracks().length > 0;
  useEffect(() => {
    const element = media.current;
    if (!element) return;
    if (tile.attach) tile.attach(element);
    else element.srcObject = tile.stream;
    void element.play().catch(() => setTap(true));
    return () => {
      tile.detach?.(element);
      element.srcObject = null;
    };
  }, [tile.stream]);
  useEffect(() => {
    // Media adapters may change element properties while attaching a new track.
    if (media.current) media.current.muted = tile.local || muted;
  }, [tile.stream, tile.local, muted]);
  return (
    <div
      className={video ? "call-tile" : "call-audio"}
      data-source={tile.source}
    >
      <video
        ref={media}
        poster="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='1' height='1'/%3E"
        autoPlay
        playsInline
        muted={tile.local || muted}
        aria-label={name}
      />
      {video && <span>{name}</span>}
      {tap && (
        <button
          className="secondary"
          onClick={() => {
            void media.current?.play().then(() => setTap(false));
          }}
        >
          {t("calls.playAudio")}
        </button>
      )}
    </div>
  );
}

type CallPerson = {
  credential: string;
  name: string;
  local: boolean;
  speaking: boolean;
  audioMuted: boolean;
  camera?: MediaTile;
  screen?: MediaTile;
};

function initials(name: string) {
  const words = name.trim().split(/\s+/u).filter(Boolean);
  return (
    (words.length > 1
      ? words[0][0] + words.at(-1)![0]
      : words[0]?.slice(0, 2)
    )?.toLocaleUpperCase() ?? "?"
  );
}

function ParticipantVisual({
  person,
  main = false,
  selected = false,
  muted = false,
  status,
}: {
  person: CallPerson;
  main?: boolean;
  selected?: boolean;
  muted?: boolean;
  status?: string;
}) {
  const tile =
    main || person.local
      ? (person.screen ?? person.camera)
      : (person.camera ?? person.screen);
  return (
    <div
      className="call-participant"
      data-main={main || undefined}
      data-selected={selected || undefined}
      data-speaking={person.speaking || undefined}
      data-muted={muted || person.audioMuted || undefined}
    >
      {tile ? (
        <Tile tile={tile} name={person.name} muted={muted} />
      ) : (
        <div className="call-initials" aria-label={person.name}>
          <strong>{initials(person.name)}</strong>
          <span>{person.name}</span>
        </div>
      )}
      {(muted || person.audioMuted) && (
        <span className="call-participant-muted" aria-hidden="true">
          <MicOff size={16} />
        </span>
      )}
      {status && (
        <span
          className="call-connection-status"
          role="status"
          aria-live="polite"
        >
          {status}
        </span>
      )}
    </div>
  );
}

export function CallSurface({
  calls,
  view,
  currentChat,
  onShowCalls,
}: {
  calls: Calls;
  view: View;
  currentChat?: Stream;
  onShowCalls: () => void;
}) {
  const desktop = useDesktopLayout();
  const state = useSyncExternalStore(calls.subscribe, calls.getSnapshot);
  const incoming = state.incoming?.find((call) =>
    isRingingFor(call, view.identity),
  );
  const ringKey = incoming ? invitationKey(incoming, view.identity) : undefined;
  const nativePresented =
    incoming &&
    state.nativePresented?.some(
      (item) =>
        item.call_id === incoming.call_id &&
        item.invitation_id ===
          incoming.invitations?.[view.identity]?.invitation_id,
    );
  useEffect(() => {
    if (
      !ringKey ||
      nativePresented ||
      state.answering ||
      /Android|iPhone|iPad|iPod/.test(navigator.userAgent)
    )
      return;
    const play = () => {
      if (appHasAttention())
        void playNotificationSound(readNotificationSound()).catch(() => {});
    };
    play();
    const timer = setInterval(play, 8000);
    return () => {
      clearInterval(timer);
      stopNotificationSound();
    };
  }, [ringKey, nativePresented, state.answering]);

  const expanded = state.expanded === true;
  const setExpanded = (value: boolean) =>
    value ? calls.expand() : calls.collapse();
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviting, setInviting] = useState(false);
  const [selected, setSelected] = useState<string>();
  const [pinned, setPinned] = useState<string>();
  const [mutedPeople, setMutedPeople] = useState<Set<string>>(() => new Set());
  const [speakerMuted, setSpeakerMuted] = useState(false);
  const appliedPlayback = useRef({ speaker: false, people: new Set<string>() });
  const [outputOpen, setOutputOpen] = useState(false);
  const audio = useAudioOutput(calls.audioOutputContext());
  const selectedOutput = audio.outputs.find(
    (output) => output.id === audio.selected,
  );
  const active = state.active;
  const name = (credential: string) => {
    const participant = Object.values(active?.participants ?? {}).find(
      (p) => p.credential_id === credential,
    );
    if (participant?.identity_id === view.identity)
      return view.name || t("calls.you");
    return participant
      ? state.chat?.member_names?.[participant.identity_id] ||
          view.contacts?.find((c) => c.id === participant.identity_id)?.name ||
          t("calls.participant")
      : t("calls.participant");
  };
  const controls = (full: boolean) => (
    <>
      <button
        type="button"
        className="icon call-media-control"
        aria-label={t(state.media.audio_muted ? "calls.unmute" : "calls.mute")}
        aria-pressed={!state.media.audio_muted}
        aria-disabled={state.changingMedia}
        onClick={() => {
          if (!state.changingMedia) void calls.toggle("audio");
        }}
      >
        {state.media.audio_muted ? <MicOff /> : <Mic />}
      </button>
      <button
        type="button"
        className="icon call-media-control call-speaker"
        aria-label={t(
          audio.supported
            ? "calls.chooseOutput"
            : speakerMuted
              ? "calls.unmuteSpeaker"
              : "calls.muteSpeaker",
          { output: audioOutputLabel(selectedOutput) },
        )}
        aria-pressed={audio.supported ? undefined : speakerMuted}
        aria-haspopup={audio.supported ? "dialog" : undefined}
        disabled={audio.supported && !audio.ready}
        onClick={() => {
          if (audio.supported) {
            void audio.refresh();
            setOutputOpen(true);
          } else setSpeakerMuted((value) => !value);
        }}
      >
        {audio.supported ? (
          <AudioOutputIcon output={selectedOutput} muted={speakerMuted} />
        ) : speakerMuted ? (
          <VolumeOff />
        ) : (
          <Volume2 />
        )}
      </button>
      {full && (
        <button
          type="button"
          className="icon call-media-control"
          aria-label={t(
            state.media.video_published ? "calls.cameraOff" : "calls.cameraOn",
          )}
          aria-pressed={state.media.video_published}
          aria-disabled={state.changingMedia}
          onClick={() => {
            if (!state.changingMedia) void calls.toggle("video");
          }}
        >
          {state.media.video_published ? <Video /> : <VideoOff />}
        </button>
      )}
      {full && desktop && (
        <button
          type="button"
          className="icon call-share"
          aria-label={t(
            state.media.screen_published
              ? "calls.stopSharing"
              : "calls.shareScreen",
          )}
          title={t(
            typeof navigator.mediaDevices?.getDisplayMedia === "function"
              ? state.media.screen_published
                ? "calls.stopSharing"
                : "calls.shareScreen"
              : "calls.screenUnsupported",
          )}
          aria-pressed={state.media.screen_published}
          disabled={
            state.changingMedia ||
            typeof navigator.mediaDevices?.getDisplayMedia !== "function"
          }
          onClick={() => void calls.toggle("screen")}
        >
          {state.media.screen_published ? <ScreenShareOff /> : <ScreenShare />}
        </button>
      )}
      <button
        type="button"
        className="icon call-leave"
        aria-label={t("calls.leave")}
        onClick={() => {
          setExpanded(false);
          void calls.leave();
        }}
      >
        <PhoneOff />
      </button>
    </>
  );
  const capture = calls.localCapture();
  const screen = calls.localScreen();
  const people = useMemo<CallPerson[]>(() => {
    if (!active) return [];
    return Object.values(active.participants).map((participant) => {
      const local = participant.identity_id === view.identity;
      const tracks = state.tiles.filter(
        (tile) => tile.credential === participant.credential_id,
      );
      const localCamera =
        local &&
        !calls.isNativeMedia() &&
        capture &&
        state.media.video_published
          ? {
              id: "local-camera",
              credential: view.credential,
              stream: capture,
              local: true,
              source: "camera" as const,
            }
          : undefined;
      const localScreen =
        local && screen && state.media.screen_published
          ? {
              id: "local-screen",
              credential: view.credential,
              stream: screen,
              local: true,
              source: "screen" as const,
            }
          : undefined;
      return {
        credential: participant.credential_id,
        name: name(participant.credential_id),
        local,
        speaking: tracks.some((tile) => tile.speaking),
        audioMuted: participant.media.audio_muted,
        camera:
          localCamera ??
          (participant.media.video_published
            ? tracks.find((tile) => tile.source === "camera")
            : undefined),
        screen:
          localScreen ??
          (participant.media.screen_published
            ? tracks.find((tile) => tile.source === "screen")
            : undefined),
      };
    });
  }, [active, capture, screen, state.media, state.tiles, view.identity]);
  const credentials = people.map((person) => person.credential).join(":");
  const speaker = people.find((person) => person.speaking)?.credential;
  const presenter = people.find((person) => person.screen)?.credential;
  useEffect(() => {
    setSelected(undefined);
    setPinned(undefined);
    setMutedPeople(new Set());
    setSpeakerMuted(false);
    appliedPlayback.current = { speaker: false, people: new Set() };
    setOutputOpen(false);
    setInviteOpen(false);
  }, [active?.call_id]);
  useEffect(() => {
    if (!people.length) return;
    if (pinned && people.some((person) => person.credential === pinned)) {
      setSelected(pinned);
      return;
    }
    if (pinned) setPinned(undefined);
    if (people.length >= 3 && presenter) setSelected(presenter);
    else if (people.length >= 3 && speaker) setSelected(speaker);
    else
      setSelected((current) =>
        current && people.some((person) => person.credential === current)
          ? current
          : (people.find((person) => !person.local) ?? people[0]).credential,
      );
  }, [active?.call_id, credentials, pinned, speaker, presenter]);
  const selectedPerson =
    people.find((person) => person.credential === selected) ??
    people.find((person) => !person.local) ??
    people[0];
  const localPerson = people.find((person) => person.local);
  const remotePerson = people.find((person) => !person.local);
  useEffect(() => {
    let disposed = false;
    const previous = appliedPlayback.current;
    void calls
      .setSpeakerMuted(
        speakerMuted ||
          (!!remotePerson && mutedPeople.has(remotePerson.credential)),
      )
      .then((applied) => {
        if (disposed) return;
        if (applied)
          appliedPlayback.current = {
            speaker: speakerMuted,
            people: mutedPeople,
          };
        else {
          setSpeakerMuted(previous.speaker);
          setMutedPeople(previous.people);
        }
      });
    return () => {
      disposed = true;
    };
  }, [calls, speakerMuted, mutedPeople, remotePerson?.credential]);
  const connectionStatus = t(
    state.phase === "connected"
      ? "calls.connected"
      : state.phase === "reconnecting"
        ? "calls.reconnecting"
        : "calls.connecting",
  );
  const selectPerson = (credential: string) => {
    setSelected(credential);
    if (pinned) setPinned(credential);
  };
  const toggleSelectedMute = async () => {
    if (!selectedPerson) return;
    if (selectedPerson.local) {
      void calls.toggle("audio");
      return;
    }
    const credential = selectedPerson.credential;
    const mute = !mutedPeople.has(credential);
    if (!(await calls.setParticipantMuted(credential, mute))) return;
    setMutedPeople((current) => {
      const next = new Set(current);
      if (mute) next.add(credential);
      else next.delete(credential);
      return next;
    });
  };
  const sessions = activeSessions(view, state.available);
  const visibleSessions = sessions.filter(
    (entry) => !(state.dismissed ?? []).includes(sessionKey(entry.call)),
  );
  const selectedSession =
    visibleSessions.find(
      (entry) =>
        currentChat &&
        scopeKey(entry.chat) ===
          scopeKey({
            ...currentChat,
            space_context:
              currentChat.space_context ?? view.active_space ?? undefined,
          }),
    ) ?? visibleSessions[0];
  const otherCount = sessions.filter(
    (entry) =>
      entry.call.call_id !== (active?.call_id ?? selectedSession?.call.call_id),
  ).length;
  const activeSpace = view.spaces?.find(
    (space) => space.id === active?.scope.hosting_space_id,
  );
  const status = !active
    ? t("calls.establishing")
    : active.phase === "ringing"
      ? t("calls.ringing")
      : connectionStatus;
  const more = otherCount > 0 && (
    <button
      type="button"
      className="quiet call-widget-more"
      onClick={onShowCalls}
      aria-label={t("calls.otherSessions", { count: otherCount })}
    >
      +{otherCount}
    </button>
  );
  const widget =
    active || state.phase === "connecting" ? (
      <FloatingCall
        label={t("calls.active")}
        hidden={expanded}
        title={
          <button
            type="button"
            className="call-widget-title"
            disabled={!active}
            onClick={calls.expand}
            aria-label={t("calls.open")}
          >
            <span className="call-widget-avatar" aria-hidden="true">
              <Phone size={18} />
            </span>
            <span className="call-widget-heading">
              <strong>{state.chat?.name ?? t("calls.establishing")}</strong>
              <small>
                {activeSpace?.name
                  ? t("calls.widgetStatus", { status, space: activeSpace.name })
                  : status}
              </small>
            </span>
            <Maximize2
              size={16}
              className="call-widget-expand"
              aria-hidden="true"
            />
          </button>
        }
      >
        {more}
        {active ? (
          controls(false)
        ) : (
          <button
            type="button"
            className="icon call-leave"
            aria-label={t("calls.cancelCall")}
            onClick={() => void calls.leave()}
          >
            <PhoneOff />
          </button>
        )}
      </FloatingCall>
    ) : selectedSession ? (
      <FloatingCall
        label={t("calls.activeSessions")}
        title={
          <button
            type="button"
            className="call-widget-title"
            onClick={onShowCalls}
          >
            <span className="call-widget-avatar" aria-hidden="true">
              <Phone size={18} />
            </span>
            <span className="call-widget-heading">
              <strong>{selectedSession.chat.name}</strong>
              <small>
                {t("calls.inSpace", { name: selectedSession.spaceName })}
              </small>
            </span>
          </button>
        }
      >
        {more}
        <button
          type="button"
          className="call-widget-join"
          disabled={state.answering}
          onClick={() =>
            calls.requestStart(selectedSession.chat, selectedSession.call)
          }
        >
          <Phone size={18} aria-hidden="true" />
          {t(
            selectedSession.call.kind === "direct" &&
              selectedSession.call.phase === "ringing"
              ? "calls.answer"
              : "calls.joinSession",
          )}
        </button>
        {selectedSession.call.kind === "group" && (
          <button
            type="button"
            className="icon"
            aria-label={t("calls.dismissSession")}
            onClick={() => calls.dismiss(selectedSession.call)}
          >
            <X size={18} />
          </button>
        )}
      </FloatingCall>
    ) : null;
  return (
    <>
      {widget}
      <SessionDialogs calls={calls} view={view} />
      {active && outputOpen && (
        <AudioOutputMenu
          audio={audio}
          muted={speakerMuted}
          onMute={() => setSpeakerMuted((value) => !value)}
          onClose={() => setOutputOpen(false)}
        />
      )}
      <div className="call-media call-media-collapsed">
        {state.tiles
          .filter((tile) => tile.source === "audio")
          .map((tile) => (
            <Tile
              key={tile.id}
              tile={tile}
              name={name(tile.credential)}
              muted={speakerMuted || mutedPeople.has(tile.credential)}
            />
          ))}
      </div>
      {expanded && active && (
        <ActionDialog
          title={t("calls.active")}
          onClose={() => setExpanded(false)}
          className="call-dialog"
          closeIcon={<ChevronDown />}
          closeLabel={t("calls.collapse")}
        >
          <div className="call-stage" data-count={people.length}>
            {people.length >= 3 && (
              <div className="call-participant-strip" role="list">
                {people.map((person) => (
                  <button
                    type="button"
                    role="listitem"
                    key={person.credential}
                    aria-label={person.name}
                    aria-pressed={
                      selectedPerson?.credential === person.credential
                    }
                    onClick={() => selectPerson(person.credential)}
                  >
                    <ParticipantVisual
                      person={person}
                      selected={
                        selectedPerson?.credential === person.credential
                      }
                      muted={speakerMuted || mutedPeople.has(person.credential)}
                    />
                  </button>
                ))}
              </div>
            )}
            {people.length === 2 && remotePerson && (
              <ParticipantVisual
                person={remotePerson}
                main
                muted={speakerMuted || mutedPeople.has(remotePerson.credential)}
                status={connectionStatus}
              />
            )}
            {people.length === 2 && localPerson && (
              <div className="call-self-preview">
                <ParticipantVisual person={localPerson} />
              </div>
            )}
            {people.length !== 2 && selectedPerson && (
              <ParticipantVisual
                person={selectedPerson}
                main
                muted={
                  speakerMuted || mutedPeople.has(selectedPerson.credential)
                }
                status={connectionStatus}
              />
            )}
            {people.length >= 3 && selectedPerson && (
              <div className="call-featured-actions">
                <button
                  type="button"
                  className="icon"
                  aria-label={t(
                    selectedPerson.local
                      ? state.media.audio_muted
                        ? "calls.unmute"
                        : "calls.mute"
                      : mutedPeople.has(selectedPerson.credential)
                        ? "calls.unmuteParticipant"
                        : "calls.muteParticipant",
                  )}
                  aria-pressed={
                    selectedPerson.local
                      ? state.media.audio_muted
                      : mutedPeople.has(selectedPerson.credential)
                  }
                  onClick={toggleSelectedMute}
                >
                  {selectedPerson.local ? (
                    state.media.audio_muted ? (
                      <MicOff />
                    ) : (
                      <Mic />
                    )
                  ) : mutedPeople.has(selectedPerson.credential) ? (
                    <VolumeOff />
                  ) : (
                    <Volume2 />
                  )}
                </button>
                <button
                  type="button"
                  className="icon"
                  aria-label={t(
                    pinned === selectedPerson.credential
                      ? "calls.unpin"
                      : "calls.pin",
                  )}
                  aria-pressed={pinned === selectedPerson.credential}
                  onClick={() =>
                    setPinned((current) =>
                      current === selectedPerson.credential
                        ? undefined
                        : selectedPerson.credential,
                    )
                  }
                >
                  {pinned === selectedPerson.credential ? <PinOff /> : <Pin />}
                </button>
              </div>
            )}
          </div>
          <div className="call-controls">
            {controls(true)}
            {active.kind === "group" && (
              <button
                type="button"
                className="icon"
                aria-label={t("calls.invitePeople")}
                onClick={() => setInviteOpen(true)}
              >
                <UserPlus />
              </button>
            )}
          </div>
        </ActionDialog>
      )}
      {inviteOpen && active?.kind === "group" && (
        <ActionDialog
          title={t("calls.invitePeople")}
          onClose={() => {
            if (!inviting) setInviteOpen(false);
          }}
        >
          <p>{t("calls.inviteHelp")}</p>
          <div className="call-choice">
            {state.chat?.members
              .filter(
                (member) =>
                  member.identity_id !== view.identity &&
                  member.capabilities.includes("POST") &&
                  member.capabilities.includes("READ") &&
                  !active.participants[member.identity_id],
              )
              .map((member) => (
                <button
                  type="button"
                  className="secondary"
                  disabled={
                    inviting ||
                    (active.invitations?.[member.identity_id]?.expires_at ??
                      0) *
                      1000 >
                      Date.now()
                  }
                  key={member.identity_id}
                  onClick={async () => {
                    setInviting(true);
                    try {
                      await calls.invite(member.identity_id);
                    } finally {
                      setInviting(false);
                      setInviteOpen(false);
                    }
                  }}
                >
                  {state.chat?.member_names?.[member.identity_id] ??
                    view.contacts?.find(
                      (person) => person.id === member.identity_id,
                    )?.name ??
                    t("calls.participant")}
                </button>
              ))}
          </div>
        </ActionDialog>
      )}
      {state.error && (
        <ActionDialog
          title={t(callErrorCopy(state.error).title)}
          onClose={calls.dismissError}
        >
          <p>{t(callErrorCopy(state.error).message)}</p>
          <div className="call-choice">
            <button onClick={calls.dismissError}>{t("dialog.close")}</button>
          </div>
        </ActionDialog>
      )}
    </>
  );
}
