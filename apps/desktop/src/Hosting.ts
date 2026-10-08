import { useEffect, useRef, useState } from "react";
import { invoke } from "./diagnosticInvoke";
import {
  attachmentStorageRequest,
  type AttachmentStorageDraft,
} from "./AttachmentStorageForm";
import { t } from "./i18n";
import { presentError } from "./errors";

export type MessageLifetime = number | "no_expiry";
export type HostingProfileSummary = {
  id: string;
  name: string;
  url: string;
  message_lifetimes: MessageLifetime[];
  default_message_lifetime: MessageLifetime;
  attachment_storage_available: boolean;
  attachment_storage_managed: boolean;
  builtin: boolean;
  storage_provider?: "mega" | "s3";
};
export type HostingCatalogRequest =
  | { op: "list" | "restore_default" }
  | { op: "preview" | "add"; link: string }
  | { op: "remove"; id: string };
export type HostingCatalogReply = {
  entries: HostingProfileSummary[];
  preview?: HostingProfileSummary;
};

export function hostingCatalog(request: HostingCatalogRequest) {
  return invoke<HostingCatalogReply>("hosting_catalog", { request });
}

export function hostingErrorMessage(
  error: unknown,
  fallback:
    "hosting.previewFailed" | "hosting.addFailed" | "hosting.saveFailed",
) {
  const { message } = presentError(error);
  return message === t("error.generic") ? t(fallback) : message;
}

/** The catalog is device-local. An empty catalog must stay empty until restored. */
export function chooseHosting(
  entries: HostingProfileSummary[],
  selectedId?: string,
) {
  return entries.find((entry) => entry.id === selectedId) ?? entries[0];
}

export function hostingLifetime(
  host: HostingProfileSummary,
  selected?: MessageLifetime,
): MessageLifetime | undefined {
  return selected !== undefined && host.message_lifetimes.includes(selected)
    ? selected
    : host.message_lifetimes.includes(host.default_message_lifetime)
      ? host.default_message_lifetime
      : host.message_lifetimes[0];
}

export function messageLifetimeLabel(lifetime: MessageLifetime) {
  return lifetime === "no_expiry"
    ? t("spaces.messageLifetime.no_expiry")
    : t("spaces.messageLifetime.hours", { hours: lifetime / 3600 });
}

export function hostingAttachmentRequest(
  host: Pick<
    HostingProfileSummary,
    "attachment_storage_available" | "attachment_storage_managed"
  >,
  draft: AttachmentStorageDraft,
) {
  if (host.attachment_storage_managed) return { enabled: true, managed: true };
  if (host.attachment_storage_available) return attachmentStorageRequest(draft);
  return undefined;
}

export function useHostingCatalog() {
  const [entries, setEntries] = useState<HostingProfileSummary[]>([]);
  const [status, setStatus] = useState<"loading" | "ready" | "failed">(
    "loading",
  );
  const mounted = useRef(true);
  const generation = useRef(0);
  const request = async (input: HostingCatalogRequest) => {
    const current = ++generation.current;
    if (input.op === "list") setStatus("loading");
    try {
      const result = await hostingCatalog(input);
      if (mounted.current && generation.current === current) {
        setEntries(result.entries);
        setStatus("ready");
      }
      return result;
    } catch (error) {
      if (
        mounted.current &&
        generation.current === current &&
        input.op === "list"
      )
        setStatus("failed");
      throw error;
    }
  };
  const refresh = async () => {
    try {
      await request({ op: "list" });
    } catch {
      /* The current request exposes its failure beside the selector. */
    }
  };
  useEffect(() => {
    mounted.current = true;
    void refresh();
    return () => {
      mounted.current = false;
      generation.current += 1;
    };
  }, []);
  return { entries, status, request, refresh };
}
