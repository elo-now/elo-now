import { useEffect, useId, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { t } from "./i18n";
import { useToast } from "./Toast";
import type { SpaceSummary, View } from "./model";

export function SpaceContactInput({
  value,
  onChange,
  disabled,
  readOnly = false,
}: {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  readOnly?: boolean;
}) {
  const id = useId();
  return (
    <div className="space-contact-field">
      <label htmlFor={id}>{t("spaces.contactEmail")}</label>
      <input
        id={id}
        type="email"
        inputMode="email"
        autoComplete="email"
        autoCapitalize="none"
        spellCheck={false}
        maxLength={254}
        required
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
        readOnly={readOnly}
        aria-describedby={`${id}-help`}
      />
      <p id={`${id}-help`} className="caption muted">
        {t(readOnly ? "spaces.contactReadOnlyHelp" : "spaces.contactEmailHelp")}
      </p>
    </div>
  );
}

export function SpaceContact({
  identity,
  space,
  email,
  revision,
  primaryName,
  editable,
  onView,
  onChanged,
}: {
  identity: string;
  space: SpaceSummary;
  email: string;
  revision: number;
  primaryName: string;
  editable: boolean;
  onView: (view: View) => void;
  onChanged: () => Promise<void>;
}) {
  const [value, setValue] = useState(email);
  const [busy, setBusy] = useState(false);
  const active = useRef(true);
  const pending = useRef(false);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  useEffect(() => {
    setValue(email);
  }, [email]);
  const { notify, reportError } = useToast();
  return (
    <form
      className="space-contact-form space-details-section"
      onSubmit={(event) => {
        event.preventDefault();
        if (!editable || pending.current) return;
        pending.current = true;
        setBusy(true);
        void invoke<{ view: View }>("operate", {
          request: {
            op: "space_contact_update",
            id: space.id,
            expected_identity: identity,
            body: { revision, contact_email: value.trim() },
          },
        })
          .then(async (reply) => {
            if (!active.current) return;
            onView(reply.view);
            await onChanged();
            if (active.current) notify(t("spaces.contactSaved"));
          })
          .catch((error) => {
            if (active.current) reportError(error);
          })
          .finally(() => {
            pending.current = false;
            if (active.current) setBusy(false);
          });
      }}
    >
      <h3>{t("spaces.contactTitle")}</h3>
      <p className="space-primary-owner">
        {t("spaces.primaryOwnerName", { name: primaryName })}
      </p>
      <SpaceContactInput
        value={value}
        onChange={setValue}
        disabled={busy}
        readOnly={!editable}
      />
      {editable && (
        <button
          type="submit"
          className="secondary"
          disabled={busy || !value.trim() || value.trim() === email}
          aria-busy={busy}
        >
          {t("spaces.contactSave")}
        </button>
      )}
    </form>
  );
}
