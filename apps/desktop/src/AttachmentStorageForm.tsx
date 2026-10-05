import { useId } from "react";
import { t } from "./i18n";

export type AttachmentStorageProvider = "mega_folder" | "s3_compatible";
export type AttachmentStorageDraft = {
  enabled: boolean;
  provider: AttachmentStorageProvider;
  folder_link: string;
  write_auth: string;
  endpoint: string;
  region: string;
  bucket: string;
  access_key: string;
  secret_key: string;
};
export type AttachmentStorageStatus = {
  available: boolean;
  enabled: boolean;
  configured: boolean;
  provider?: AttachmentStorageProvider | null;
  revision: number;
  used_bytes: number;
  max_space_bytes: number;
  max_file_bytes: number;
  retention_hours: number | null;
};

/** Credentials belong only to the mounted form, never to a profile or view. */
export const emptyAttachmentStorage = (
  enabled = false,
  provider: AttachmentStorageProvider = "mega_folder",
): AttachmentStorageDraft => ({
  enabled,
  provider,
  folder_link: "",
  write_auth: "",
  endpoint: "",
  region: "",
  bucket: "",
  access_key: "",
  secret_key: "",
});

export function attachmentStorageRequest(value: AttachmentStorageDraft) {
  if (!value.enabled) return { enabled: false } as const;
  if (value.provider === "mega_folder")
    return {
      enabled: true,
      provider: value.provider,
      folder_link: value.folder_link.trim(),
      write_auth: value.write_auth.trim(),
    } as const;
  return {
    enabled: true,
    provider: value.provider,
    endpoint: value.endpoint.trim(),
    region: value.region.trim(),
    bucket: value.bucket.trim(),
    access_key: value.access_key.trim(),
    secret_key: value.secret_key,
  } as const;
}

export async function saveAttachmentStorage(
  draft: AttachmentStorageDraft,
  revision: number,
  request: (op: string, body?: object) => Promise<AttachmentStorageStatus>,
  retentionHours = 1,
): Promise<AttachmentStorageStatus> {
  await request(
    draft.enabled
      ? "space_external_storage_configure"
      : "space_external_storage_disable",
    {
      ...attachmentStorageRequest(draft),
      expected_revision: revision,
      ...(draft.enabled ? { retention_hours: retentionHours } : {}),
    },
  );
  const next = await request("space_external_storage_status");
  if (
    !next.available ||
    next.enabled !== draft.enabled ||
    (draft.enabled &&
      (!next.configured ||
        next.provider !== draft.provider ||
        next.retention_hours !== retentionHours))
  )
    throw new Error("Attachment storage has not been confirmed.");
  return next;
}

export async function saveAttachmentRetention(
  hours: number,
  status: AttachmentStorageStatus,
  request: (op: string, body?: object) => Promise<AttachmentStorageStatus>,
): Promise<AttachmentStorageStatus> {
  await request("space_attachment_retention", {
    hours,
    expected_revision: status.revision,
  });
  const next = await request("space_external_storage_status");
  if (!next.available || !next.configured || next.retention_hours !== hours)
    throw new Error("Invalid attachment storage response.");
  return next;
}

export function AttachmentStorageForm({
  value,
  onChange,
  disabled = false,
}: {
  value: AttachmentStorageDraft;
  onChange: (value: AttachmentStorageDraft) => void;
  disabled?: boolean;
}) {
  const id = useId();
  const fields =
    value.provider === "mega_folder"
      ? (["folder_link", "write_auth"] as const)
      : (["endpoint", "region", "bucket", "access_key", "secret_key"] as const);
  const labels = {
    folder_link: "spaces.attachments.folderLink",
    write_auth: "spaces.attachments.writeKey",
    endpoint: "spaces.attachments.endpoint",
    region: "spaces.attachments.region",
    bucket: "spaces.attachments.bucket",
    access_key: "spaces.attachments.accessKey",
    secret_key: "spaces.attachments.secretKey",
  } as const;
  return (
    <div className="attachment-storage-form">
      <label className="check">
        <input
          type="checkbox"
          checked={value.enabled}
          disabled={disabled}
          onChange={(event) =>
            onChange(
              event.target.checked
                ? { ...value, enabled: true }
                : emptyAttachmentStorage(false, value.provider),
            )
          }
        />
        <span>{t("spaces.attachments.enable")}</span>
      </label>
      {value.enabled && (
        <>
          <div className="space-form-field">
            <label htmlFor={`${id}-provider`}>
              {t("spaces.attachments.provider")}
            </label>
            <select
              id={`${id}-provider`}
              value={value.provider}
              disabled={disabled}
              onChange={(event) =>
                onChange(
                  emptyAttachmentStorage(
                    true,
                    event.target.value as AttachmentStorageProvider,
                  ),
                )
              }
            >
              <option value="mega_folder">
                {t("spaces.attachments.mega")}
              </option>
              <option value="s3_compatible">
                {t("spaces.attachments.s3")}
              </option>
            </select>
            <p id={`${id}-help`} className="caption muted">
              {t(
                value.provider === "mega_folder"
                  ? "spaces.attachments.megaHelp"
                  : "spaces.attachments.s3Help",
              )}
            </p>
          </div>
          {fields.map((field) => (
            <div className="space-form-field" key={field}>
              <label htmlFor={`${id}-${field}`}>{t(labels[field])}</label>
              <input
                id={`${id}-${field}`}
                type={
                  field === "endpoint"
                    ? "url"
                    : [
                          "folder_link",
                          "write_auth",
                          "access_key",
                          "secret_key",
                        ].includes(field)
                      ? "password"
                      : "text"
                }
                value={value[field]}
                disabled={disabled}
                required
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                aria-describedby={`${id}-help`}
                onChange={(event) =>
                  onChange({ ...value, [field]: event.target.value })
                }
              />
            </div>
          ))}
          <p className="caption muted">
            {t("spaces.attachments.credentialsHelp")}
          </p>
        </>
      )}
    </div>
  );
}
