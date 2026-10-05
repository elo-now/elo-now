// The bundled pronunciation plays only in response to an explicit click.
const pronunciation = document.querySelector('.brand-pronunciation');
if (pronunciation) {
  const button = pronunciation.querySelector('button');
  const audio = pronunciation.querySelector('audio');
  const status = pronunciation.querySelector('[role="status"]');
  const reset = () => { button.dataset.playing = 'false'; };
  const failed = () => {
    reset();
    status.textContent = status.dataset.error;
  };
  pronunciation.hidden = false;
  audio.addEventListener('playing', () => { button.dataset.playing = 'true'; });
  audio.addEventListener('ended', reset);
  audio.addEventListener('pause', reset);
  audio.addEventListener('error', failed);
  button.addEventListener('click', async () => {
    status.textContent = '';
    try {
      audio.pause();
      if (audio.error) audio.load();
      audio.currentTime = 0;
      await audio.play();
    } catch (error) {
      if (error.name !== 'AbortError') failed();
    }
  });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) audio.pause();
  });
  window.addEventListener('pagehide', () => audio.pause());
}
