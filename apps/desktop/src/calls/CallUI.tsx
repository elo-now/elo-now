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
  ChevronUp,
  Pin,
  PinOff,
  Volume2,
  VolumeOff,
} from "lucide-react";
import { useDesktopLayout } from "../PageSurface";
import { ActionDialog } from "../ActionDialog";
import { t } from "../i18n";
import type { Stream, View } from "../model";
import { Calls } from "./controller";
import { useNativeCalls } from "./useNativeCalls";
import { callErrorCopy } from "./errors";
import { scopeKey, type MediaTile } from "./types";
import { callRinger, unlockRingtoneAudio, type Ringtone } from "./ringtone";
import "./calls.css";
import { NativeVideo } from "./NativeVideo";
export function useCalls(
  view: View | null | undefined,
  ringtone: Ringtone = "classic",
) {
  const [calls] = useState(() => new Calls());
  const nativeRinging = useNativeCalls(calls, view, ringtone);
  useEffect(() => {
    calls.activate();
    return () => calls.dispose();
  }, [calls]);
  useEffect(() => calls.update(view), [calls, view]);
  useEffect(() => {
    document.addEventListener("pointerdown", unlockRingtoneAudio, true);
    document.addEventListener("keydown", unlockRingtoneAudio, true);
    return () => {
      document.removeEventListener("pointerdown", unlockRingtoneAudio, true);
      document.removeEventListener("keydown", unlockRingtoneAudio, true);
      callRinger.stop();
    };
  }, []);
  useEffect(() => {
    const update = () => {
      const state = calls.getSnapshot();
      callRinger.update(
        state.incoming?.call.call_id,
        ringtone,
        state.phase !== "idle" || nativeRinging.current,
      );
    };
    update();
    return calls.subscribe(update);
  }, [calls, ringtone]);
  return calls;
}
export function CallButton({ calls, chat }: { calls: Calls; chat: Stream }) {
  const state = useSyncExternalStore(calls.subscribe, calls.getSnapshot);
  const [choose, setChoose] = useState(false);
  const existing = state.available[scopeKey(chat)];
  return (
    <>
      <button
        type="button"
        className="icon call-trigger"
        aria-label={t(existing ? "calls.join" : "calls.start")}
        disabled={
          !chat.can_post ||
          !!state.active ||
          !!state.nativeAnswer ||
          state.phase !== "idle"
        }
        onClick={() => setChoose(true)}
      >
        <Phone size={22} />
        {existing && <span className="call-indicator" />}
      </button>
      {choose && (
        <ActionDialog
          title={t(existing ? "calls.join" : "calls.start")}
          onClose={() => setChoose(false)}
        >
          <div className="call-choice">
            <button
              onClick={() => {
                setChoose(false);
                void calls.start(chat, false, existing);
              }}
            >
              <Phone size={20} />
              {t("calls.audio")}
            </button>
            <button
              className="secondary"
              onClick={() => {
                setChoose(false);
                void calls.start(chat, true, existing);
              }}
            >
              <Video size={20} />
              {t("calls.video")}
            </button>
          </div>
        </ActionDialog>
      )}
    </>
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

export function CallSurface({ calls, view }: { calls: Calls; view: View }) {
  const desktop = useDesktopLayout();
  const state = useSyncExternalStore(calls.subscribe, calls.getSnapshot);
  const [expanded, setExpanded] = useState(false);
  const [selected, setSelected] = useState<string>();
  const [pinned, setPinned] = useState<string>();
  const [mutedPeople, setMutedPeople] = useState<Set<string>>(() => new Set());
  const [speakerMuted, setSpeakerMuted] = useState(false);
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
          speakerMuted ? "calls.unmuteSpeaker" : "calls.muteSpeaker",
        )}
        aria-pressed={speakerMuted}
        onClick={() => setSpeakerMuted((value) => !value)}
      >
        {speakerMuted ? <VolumeOff /> : <Volume2 />}
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
        !calls.isNativeDirect() &&
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
    calls.setSpeakerMuted(
      speakerMuted ||
        (!!remotePerson && mutedPeople.has(remotePerson.credential)),
    );
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
  const toggleSelectedMute = () => {
    if (!selectedPerson) return;
    if (selectedPerson.local) void calls.toggle("audio");
    else
      setMutedPeople((current) => {
        const next = new Set(current);
        if (next.has(selectedPerson.credential))
          next.delete(selectedPerson.credential);
        else next.add(selectedPerson.credential);
        return next;
      });
  };
  return (
    <>
      {!active && (state.nativeAnswer || state.phase === "connecting") && (
        <section className="call-dock" aria-label={t("calls.active")}>
          <div className="call-dock-title" role="status" aria-live="polite">
            <span>{t("calls.connecting")}</span>
          </div>
          <button
            type="button"
            className="icon call-leave"
            aria-label={t("calls.leave")}
            onClick={() =>
              state.nativeAnswer
                ? state.nativeAnswer.cancel()
                : void calls.leave()
            }
          >
            <PhoneOff />
          </button>
        </section>
      )}
      {active && (
        <section className="call-dock" aria-label={t("calls.active")}>
          <button className="call-dock-title" onClick={() => setExpanded(true)}>
            <ChevronUp size={18} />
            <span>
              {state.chat?.name}
              <small>
                {t(
                  state.phase === "connected"
                    ? "calls.active"
                    : state.phase === "reconnecting"
                      ? "calls.reconnecting"
                      : "calls.connecting",
                )}
              </small>
            </span>
          </button>
          {controls(false)}
        </section>
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
          <div className="call-controls">{controls(true)}</div>
        </ActionDialog>
      )}
      {state.incoming &&
        !active &&
        !state.nativeAnswer &&
        state.nativeAnswerChecked !== false && (
          <ActionDialog
            title={t("calls.incoming")}
            onClose={() => void calls.decline()}
          >
            <p className="call-status">{state.incoming.chat.name}</p>
            <div className="dialog-buttons">
              <button
                className="secondary"
                onClick={() => void calls.decline()}
              >
                {t("calls.decline")}
              </button>
              <button
                onClick={() => {
                  const incoming = state.incoming!;
                  void calls.start(incoming.chat, false, incoming.call);
                }}
              >
                {t("calls.answer")}
              </button>
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
