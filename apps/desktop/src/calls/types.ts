import type { Stream } from "../model";
export type MediaState = {
  audio_muted: boolean;
  video_published: boolean;
  screen_published: boolean;
};
export type Scope = {
  hosting_space_id: string;
  conversation: { space_id: string; stream_id: string };
};
export type Participant = {
  identity_id: string;
  credential_id: string;
  media: MediaState;
};
export type ActiveCall = {
  call_id: string;
  scope: Scope;
  kind: "direct" | "group";
  initial_media: "audio" | "video";
  config_id: string;
  participants: Record<string, Participant>;
  key_epoch: number;
  ringing: boolean;
  started_by: string;
  started_at: number;
};
export type MediaAccess = {
  provider: "livekit" | "p2p";
  url: string;
  token: string;
  epoch: number;
  ice_servers: RTCIceServer[];
};
export type SignalPayload =
  | { type: "request_offer" }
  | { type: "media_key"; epoch: number; key: string }
  | { type: "request_key"; epoch: number }
  | { type: "offer" | "answer"; sdp: string }
  | {
      type: "ice";
      candidate: string;
      sdp_mid: string | null;
      sdp_mline_index: number | null;
    };
export type MediaTile = {
  id: string;
  credential: string;
  stream: MediaStream;
  local: boolean;
  source: "audio" | "camera" | "screen";
  speaking?: boolean;
  native?: {
    session: string;
    track: string;
    render: (frames: unknown[]) => Promise<unknown>;
  };
  attach?: (element: HTMLMediaElement) => void;
  detach?: (element: HTMLMediaElement) => void;
};
export type Snapshot = {
  nativeAnswer?: { id: string; cancel: () => void };
  nativeAnswerChecked?: boolean;
  active?: ActiveCall;
  chat?: Stream;
  phase: "idle" | "connecting" | "connected" | "reconnecting";
  media: MediaState;
  tiles: MediaTile[];
  error?: string;
  changingMedia?: boolean;
  incoming?: { call: ActiveCall; chat: Stream };
  available: Record<string, ActiveCall>;
};
export const muted: MediaState = {
  audio_muted: true,
  video_published: false,
  screen_published: false,
};
export const scopeKey = (chat: Stream) =>
  `${chat.space_context}:${chat.space}:${chat.stream}`;
export const callKey = (call: ActiveCall) =>
  `${call.scope.hosting_space_id}:${call.scope.conversation.space_id}:${call.scope.conversation.stream_id}`;
export const leader = (call: ActiveCall) =>
  Object.values(call.participants)
    .map((p) => p.credential_id)
    .sort()[0];
export interface MediaAdapter {
  setSpeakerMuted?(muted: boolean): Promise<void>;
  stop(): Promise<void>;
  update(
    state: MediaState,
    capture: MediaStream,
    screen?: MediaStream,
  ): Promise<void>;
  signal?(payload: SignalPayload): Promise<void>;
}
