import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { diagnostic, type DiagnosticStatus } from "./diagnostics";
import { t } from "./i18n";

export function BetaDiagnosticsHelp({ enabled }: { enabled: boolean }) {
  const [status, setStatus] = useState<DiagnosticStatus>();
  const [sent, setSent] = useState(false);
  useEffect(() => {
    let active = true;
    void invoke<DiagnosticStatus>("diagnostic_task", {
      request: { op: "status" },
    })
      .then((value) => {
        if (active) setStatus(value);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [enabled]);
  if (!status?.available) return null;
  return (
    <>
      <p className="muted">{t(status.live_available ? "diagnostics.liveHelp" : "diagnostics.help")}</p>
      {enabled && (
        <>
          <p className="muted">
            {t("diagnostics.supportId", { id: status.installation ?? "" })}
          </p>
          <button
            type="button"
            className="secondary diagnostics-test-button"
            disabled={sent}
            onClick={() => {
              diagnostic("error", "test", "diagnostics_test");
              setSent(true);
            }}
          >
            {t("diagnostics.test")}
          </button>
          {sent && (
            <p role="status" className="muted">
              {t(status.live_available ? "diagnostics.liveQueued" : "diagnostics.testQueued")}
            </p>
          )}
        </>
      )}
    </>
  );
}
