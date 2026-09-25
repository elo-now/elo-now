import { useEffect, type ReactNode } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { t } from "./i18n";
import { setUpdateRequired, useUpdateRequired } from "./releasePolicy";

/** Local access never waits for release discovery and never gets unmounted. */
export function UpdateGate({ children }: { children: ReactNode }) {
  useEffect(() => {
    if (!isTauri()) return;
    let active = true;
    const apply = (required: boolean) => {
      if (active) setUpdateRequired(required);
    };
    const refresh = () => {
      if (document.visibilityState !== "visible") return;
      // Read the cached decision immediately, then refresh in the background.
      void invoke<boolean>("release_policy")
        .then(apply)
        .catch(() => {});
      void invoke<boolean>("check_release_policy")
        .then(apply)
        .catch(() => {});
    };
    const listener = listen<boolean>("release-policy", ({ payload }) =>
      apply(payload),
    );
    void listener
      .then(() => {
        if (active) refresh();
      })
      .catch(() => {
        if (active) refresh();
      });
    document.addEventListener("visibilitychange", refresh);
    window.addEventListener("online", refresh);
    return () => {
      active = false;
      document.removeEventListener("visibilitychange", refresh);
      window.removeEventListener("online", refresh);
      void listener.then((unlisten) => unlisten()).catch(() => {});
    };
  }, []);
  return children;
}

export function UpdateBanner() {
  const required = useUpdateRequired();
  return required ? (
    <div className="update-banner" role="status">
      {t("update.banner")}
    </div>
  ) : null;
}
