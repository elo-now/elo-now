import type {
  MediaAccess,
  MediaAdapter,
  MediaState,
  MediaTile,
  SignalPayload,
} from "./types";
/** SDP fingerprints are authenticated by elo's signed, recipient-encrypted signaling. */
export class PeerMedia implements MediaAdapter {
  private pc: RTCPeerConnection;
  private channels?: [RTCRtpTransceiver, RTCRtpTransceiver, RTCRtpTransceiver];
  private tracks: (MediaStreamTrack | null)[] = [null, null, null];
  private candidates: RTCIceCandidateInit[] = [];
  private stopped = false;
  private acceptedOffer?: string;
  private acceptedAnswer?: string;
  private offering?: Promise<void>;
  private signals: Promise<void> = Promise.resolve();
  private disconnected?: ReturnType<typeof setTimeout>;
  constructor(
    access: MediaAccess,
    private remote: string,
    private send: (p: SignalPayload) => Promise<void>,
    private tiles: (v: MediaTile[]) => void,
    private failure: () => void,
    private connected: () => void,
  ) {
    this.pc = new RTCPeerConnection({
      iceServers: access.ice_servers,
      bundlePolicy: "max-bundle",
    });
    this.pc.onicecandidate = (event) => {
      if (event.candidate)
        void this.send({
          type: "ice",
          candidate: event.candidate.candidate,
          sdp_mid: event.candidate.sdpMid,
          sdp_mline_index: event.candidate.sdpMLineIndex,
        }).catch(this.failure);
    };
    this.pc.ontrack = () => this.refresh();
    this.pc.onconnectionstatechange = () => {
      clearTimeout(this.disconnected);
      if (!this.stopped && this.pc.connectionState === "connected")
        this.connected();
      if (!this.stopped && this.pc.connectionState === "disconnected")
        this.disconnected = setTimeout(() => {
          if (!this.stopped && this.pc.connectionState === "disconnected")
            this.failure();
        }, 4000);
      if (
        !this.stopped &&
        ["failed", "closed"].includes(this.pc.connectionState)
      )
        this.failure();
    };
  }
  private refresh() {
    if (!this.channels) return;
    this.tiles(
      this.channels
        .map((channel) => channel.receiver)
        .filter((r) => r.track?.readyState === "live")
        .map((r) => ({
          id: r.track.id,
          credential: this.remote,
          stream: new MediaStream([r.track]),
          local: false,
          source:
            r === this.channels![1].receiver
              ? ("camera" as const)
              : r === this.channels![2].receiver
                ? ("screen" as const)
                : ("audio" as const),
        })),
    );
  }
  async offer(restart = false) {
    if (this.offering) return this.offering;
    const work = this.makeOffer(restart);
    this.offering = work;
    try {
      await work;
    } finally {
      if (this.offering === work) this.offering = undefined;
    }
  }
  private async makeOffer(restart: boolean) {
    if (this.stopped) return;
    if (!this.channels) {
      this.channels = [
        this.pc.addTransceiver("audio", { direction: "sendrecv" }),
        this.pc.addTransceiver("video", { direction: "sendrecv" }),
        this.pc.addTransceiver("video", { direction: "sendrecv" }),
      ];
      await this.applyTracks();
    }
    if (this.pc.signalingState === "stable") {
      const offer = await this.pc.createOffer({ iceRestart: restart });
      if (this.stopped) return;
      await this.pc.setLocalDescription(offer);
    }
    // A recovering recipient may have missed the pending offer. Resend it
    // instead of creating a second offer or leaving the new peer waiting.
    if (!this.stopped && this.pc.signalingState === "have-local-offer")
      await this.send({ type: "offer", sdp: this.pc.localDescription!.sdp });
  }
  signal(payload: SignalPayload): Promise<void> {
    // Preparation can drain buffered signals while a fresh one arrives.
    const work = this.signals.then(() => this.applySignal(payload));
    this.signals = work.catch(() => {});
    return work;
  }
  private async applySignal(payload: SignalPayload) {
    if (this.stopped) return;
    if (payload.type === "request_offer") {
      await this.offer(true);
    } else if (payload.type === "ice") {
      const candidate = {
        candidate: payload.candidate,
        sdpMid: payload.sdp_mid,
        sdpMLineIndex: payload.sdp_mline_index,
      };
      if (this.pc.remoteDescription) await this.pc.addIceCandidate(candidate);
      else this.candidates.push(candidate);
    } else if (payload.type === "offer" || payload.type === "answer") {
      // ICE gathering may add candidates to a resent answer. Once negotiation
      // is stable there is no outstanding offer for that answer to complete.
      if (payload.type === "answer" && this.pc.signalingState === "stable")
        return;
      // Retries are authenticated again by the controller, but may carry the
      // same SDP with a fresh nonce. A completed answer cannot be applied twice.
      // Browsers normalize remoteDescription.sdp, so compare the original
      // authenticated bytes instead of the browser's rewritten description.
      if (
        payload.sdp ===
        (payload.type === "offer" ? this.acceptedOffer : this.acceptedAnswer)
      ) {
        if (payload.type === "answer") return;
        if (
          this.pc.signalingState === "stable" &&
          this.pc.localDescription?.type === "answer"
        ) {
          await this.send({
            type: "answer",
            sdp: this.pc.localDescription.sdp,
          });
          return;
        }
      }
      await this.pc.setRemoteDescription({
        type: payload.type,
        sdp: payload.sdp,
      });
      if (payload.type === "offer") this.acceptedOffer = payload.sdp;
      else this.acceptedAnswer = payload.sdp;
      for (const candidate of this.candidates.splice(0))
        await this.pc.addIceCandidate(candidate);
      if (payload.type === "offer") {
        // The answerer must publish on the offered m-lines. Precreating local
        // transceivers leaves them unassociated and produces a receive-only answer.
        if (!this.channels) {
          const channels = this.pc
            .getTransceivers()
            .filter((t) => t.mid !== null);
          if (
            channels.length !== 3 ||
            channels.map((t) => t.receiver.track.kind).join(",") !==
              "audio,video,video"
          )
            throw new Error("Invalid call media layout");
          this.channels = [channels[0], channels[1], channels[2]];
          for (const channel of channels) channel.direction = "sendrecv";
        }
        await this.applyTracks();
        await this.pc.setLocalDescription(await this.pc.createAnswer());
        this.refresh();
        await this.send({ type: "answer", sdp: this.pc.localDescription!.sdp });
      }
    }
  }
  async update(state: MediaState, capture: MediaStream, screen?: MediaStream) {
    this.tracks = [
      state.audio_muted ? null : (capture.getAudioTracks()[0] ?? null),
      state.video_published ? (capture.getVideoTracks()[0] ?? null) : null,
      state.screen_published ? (screen?.getVideoTracks()[0] ?? null) : null,
    ];
    await this.applyTracks();
  }
  private async applyTracks() {
    if (this.stopped || !this.channels) return;
    await Promise.all(
      this.channels.map((channel, i) =>
        channel.sender.replaceTrack(this.tracks[i]),
      ),
    );
  }
  async stop() {
    this.stopped = true;
    clearTimeout(this.disconnected);
    this.pc.close();
    this.tracks = [null, null, null];
    this.tiles([]);
  }
}
