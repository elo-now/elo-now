import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Minus, Square, X } from "lucide-react";
import { t } from "./i18n";
import { useToast } from "./Toast";

/** Native macOS controls overlay the sidebar; other desktops use scoped controls. */
export function WindowChrome() {
  const [platform, setPlatform] = useState<string>();
  const { reportError } = useToast();
  useEffect(() => {
    let live = true;
    void invoke<{ mobile: boolean; platform?: string }>("profile_environment")
      .then((environment) => {
        if (!live || environment.mobile || !environment.platform) return;
        setPlatform(environment.platform);
        document.documentElement.dataset.windowPlatform = environment.platform;
      })
      .catch(reportError);
    return () => {
      live = false;
    };
  }, []);
  useEffect(() => {
    if (!platform) return;
    const drag = (event: MouseEvent) => {
      if (event.button !== 0 || !(event.target instanceof Element)) return;
      if (
        !event.target.closest(
          ".screen-header, .desktop-workspace, .desktop-window-drag",
        ) ||
        event.target.closest(
          "button, input, select, textarea, a, [role=button]",
        )
      )
        return;
      event.preventDefault();
      const native = getCurrentWindow();
      void (
        event.detail === 2 ? native.toggleMaximize() : native.startDragging()
      ).catch(reportError);
    };
    document.addEventListener("mousedown", drag);
    return () => document.removeEventListener("mousedown", drag);
  }, [platform]);
  if (!platform) return null;
  return (
    <>
      <div className="desktop-window-drag" aria-hidden="true" />
      {platform !== "macos" && (
        <div className="desktop-window-controls">
          <button
            type="button"
            aria-label={t("window.minimize")}
            onClick={() =>
              void getCurrentWindow().minimize().catch(reportError)
            }
          >
            <Minus aria-hidden="true" />
          </button>
          <button
            type="button"
            aria-label={t("window.toggleMaximize")}
            onClick={() =>
              void getCurrentWindow().toggleMaximize().catch(reportError)
            }
          >
            <Square aria-hidden="true" />
          </button>
          <button
            type="button"
            className="window-close"
            aria-label={t("window.close")}
            onClick={() => void getCurrentWindow().close().catch(reportError)}
          >
            <X aria-hidden="true" />
          </button>
        </div>
      )}
    </>
  );
}
