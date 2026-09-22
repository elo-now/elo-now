import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { SpaceContactInput } from "./SpaceContact";
import { ScreenHeader } from "./ScreenHeader";
import { InvitationCode } from "./InvitationFlow";
import { useToast } from "./Toast";
import { t } from "./i18n";
import type { View } from "./model";

export function SpaceCreate({
  view,
  mobile,
  onView,
  onBack,
}: {
  view: View;
  mobile: boolean;
  onView: (view: View) => void;
  onBack: () => void;
}) {
  const [name, setName] = useState(view.space_creation?.name ?? "");
  const [email, setEmail] = useState(view.space_creation?.contact_email ?? "");
  const [messageLifetime, setMessageLifetime] = useState(
    view.space_creation?.message_lifetime_seconds ?? 86_400,
  );
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const { reportError } = useToast();
  const creation = view.space_creation;
  const call = async (request: Record<string, unknown>) => {
    const reply = await invoke<{ view: View }>("operate", {
      request: { ...request, expected_identity: view.identity },
    });
    if (alive.current) onView(reply.view);
  };
  const finish = async () => {
    if (busy) return;
    setBusy(true);
    try {
      if (creation?.space) await call({ op: "space_setup_done" });
      onBack();
    } catch (error) {
      reportError(error);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="spaces-page">
      <ScreenHeader
        title={creation?.invitation ? t("spaces.created") : t("spaces.create")}
        onBack={busy ? undefined : () => void finish()}
      />
      <div className="settings-page">
        {creation?.invitation ? (
          <>
            <p className="page-description">
              {t("spaces.createdHelp", { name: creation.name })}
            </p>
            <InvitationCode
              link={creation.invitation}
              mobile={mobile}
              showLink={false}
            />
            <p className="muted">{t("spaces.firstInvitationHelp")}</p>
            <button disabled={busy} onClick={() => void finish()}>
              {t("spaces.openCreated")}
            </button>
          </>
        ) : (
          <form
            className="space-create-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (busy) return;
              setBusy(true);
              void call({
                op: "space_create",
                name: creation?.name ?? name.trim(),
                contact_email: creation?.contact_email || email.trim(),
                message_lifetime_seconds:
                  creation?.message_lifetime_seconds ?? messageLifetime,
              })
                .catch(async (error) => {
                  if (!alive.current) return;
                  reportError(error);
                  await call({ op: "space_list" }).catch(() => {});
                })
                .finally(() => {
                  if (alive.current) setBusy(false);
                });
            }}
          >
            <p className="page-description">{t("spaces.createHelp")}</p>
            <div className="space-form-field">
              <label htmlFor="space-name">{t("spaces.name")}</label>
              <input
                id="space-name"
                value={creation?.name ?? name}
                maxLength={80}
                disabled={busy || !!creation}
                onChange={(event) => setName(event.target.value)}
                autoComplete="off"
                aria-describedby="space-hosting-limits"
              />
            </div>
            <SpaceContactInput
              value={creation?.contact_email || email}
              onChange={setEmail}
              disabled={busy || !!creation?.contact_email}
            />
            <div className="space-form-field">
              <label htmlFor="space-message-lifetime">
                {t("spaces.messageLifetime.label")}
              </label>
              <select
                id="space-message-lifetime"
                value={creation?.message_lifetime_seconds ?? messageLifetime}
                disabled={busy || !!creation}
                onChange={(event) =>
                  setMessageLifetime(Number(event.target.value))
                }
              >
                {[21_600, 43_200, 86_400].map((seconds) => (
                  <option value={seconds} key={seconds}>
                    {t(
                      `spaces.messageLifetime.${seconds}` as "spaces.messageLifetime.21600",
                    )}
                  </option>
                ))}
              </select>
              <p className="caption muted">
                {t("spaces.messageLifetime.help")}
              </p>
            </div>
            {creation && <p className="muted">{t("spaces.resumeHelp")}</p>}
            <p id="space-hosting-limits" className="space-hosting-limits muted">
              {t("spaces.hostingLimits")}
            </p>
            <button
              type="submit"
              className="space-switch"
              disabled={busy || !(creation?.name ?? name).trim()}
              aria-busy={busy}
            >
              {busy && (
                <span
                  className="invitation-qr-loader space-switch-loader"
                  aria-hidden="true"
                />
              )}
              <span className="space-switch-label">
                {t(
                  busy
                    ? "spaces.creating"
                    : creation
                      ? "spaces.resume"
                      : "spaces.create",
                )}
              </span>
            </button>
          </form>
        )}
      </div>
    </section>
  );
}
