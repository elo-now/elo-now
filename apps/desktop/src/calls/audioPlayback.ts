// Keep autoplay recovery outside the hidden audio track container. Calling
// retry synchronously from a visible control preserves the browser gesture.
export class CallAudioPlayback {
  private tracks = new Map<
    HTMLMediaElement,
    { blocked: boolean; attempt: number }
  >();
  private listeners = new Set<() => void>();
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  getSnapshot = () => [...this.tracks.values()].some((track) => track.blocked);
  private changed() {
    this.listeners.forEach((listener) => listener());
  }

  attach(element: HTMLMediaElement) {
    const track = { blocked: false, attempt: 0 };
    this.tracks.set(element, track);
    const playing = () => {
      if (this.tracks.get(element) !== track) return;
      track.attempt++;
      track.blocked = false;
      this.changed();
    };
    element.addEventListener("playing", playing);
    this.play(element, track);
    return () => {
      element.removeEventListener("playing", playing);
      if (this.tracks.get(element) === track) this.tracks.delete(element);
      this.changed();
    };
  }

  retry = () => {
    for (const [element, track] of this.tracks) {
      if (track.blocked) this.play(element, track);
    }
  };

  private play(
    element: HTMLMediaElement,
    track: { blocked: boolean; attempt: number },
  ) {
    const attempt = ++track.attempt;
    void element.play().then(
      () => {
        if (this.tracks.get(element) !== track || track.attempt !== attempt)
          return;
        track.blocked = false;
        this.changed();
      },
      (error: unknown) => {
        if (this.tracks.get(element) !== track || track.attempt !== attempt)
          return;
        // Detaching/replacing a track can abort play; that is not an autoplay block.
        if (error instanceof Error && error.name === "NotAllowedError") {
          track.blocked = true;
          this.changed();
        }
      },
    );
  }
}
