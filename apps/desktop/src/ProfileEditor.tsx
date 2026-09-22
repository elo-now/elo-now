import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon";
import { ProfileNameField, checkedProfileName } from "./ProfileName";
import { t } from "./i18n";
import { useToast } from "./Toast";

export type ProfilePresentation = { name: string; avatar: string | null };

export function ProfileAvatar({ name, avatar }: ProfilePresentation) {
  return (
    <span className="profile-avatar" aria-hidden="true">
      {avatar ? (
        <img src={avatar} alt="" />
      ) : name ? (
        name
          .trim()
          .split(/\s+/u)
          .slice(0, 2)
          .map((word) => Array.from(word)[0])
          .join("")
          .toLocaleUpperCase()
      ) : (
        <Icon name="person" />
      )}
    </span>
  );
}

function clearCapture() {
  (
    window as Window & { eloPhotos?: { clearCapture: () => void } }
  ).eloPhotos?.clearCapture();
}

async function prepareAvatar(file: File): Promise<string> {
  if (file.size > 20 * 1024 * 1024) throw t("profile.photoTooLarge");
  if (!file.type.startsWith("image/") || file.type === "image/svg+xml") {
    throw t("profile.photoInvalid");
  }
  const source = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(t("profile.photoInvalid"));
    reader.readAsDataURL(file);
  });
  const image = new Image();
  try {
    image.src = source;
    await image.decode();
    const side = Math.min(image.naturalWidth, image.naturalHeight);
    if (!side) throw new Error("Empty image");
    // Store a small square of pixels, never the source photo or its metadata.
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 384;
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Image canvas unavailable");
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, 384, 384);
    context.drawImage(
      image,
      (image.naturalWidth - side) / 2,
      (image.naturalHeight - side) / 2,
      side,
      side,
      0,
      0,
      384,
      384,
    );
    const result = canvas.toDataURL("image/jpeg", 0.85);
    if (result.length > 175000) throw new Error("Image encoding too large");
    return result;
  } catch {
    throw t("profile.photoInvalid");
  } finally {
    image.src = "";
  }
}

export function ProfileEditor({
  name: initialName,
  avatar: initialAvatar,
  busy,
  mobile,
  onSave,
}: ProfilePresentation & {
  busy: boolean;
  mobile: boolean;
  onSave: (profile: ProfilePresentation) => Promise<void>;
}) {
  const [name, setName] = useState(initialName);
  const [avatar, setAvatar] = useState(initialAvatar);
  const [preparing, setPreparing] = useState(false);
  const selection = useRef(0);
  const gallery = useRef<HTMLInputElement>(null);
  const camera = useRef<HTMLInputElement>(null);
  const { reportError, onInvalid } = useToast();
  useEffect(() => {
    const inputs = [gallery.current, camera.current];
    inputs.forEach((input) => input?.addEventListener("cancel", clearCapture));
    return () => {
      selection.current++;
      inputs.forEach((input) =>
        input?.removeEventListener("cancel", clearCapture),
      );
      clearCapture();
    };
  }, []);
  const choose = async (input: HTMLInputElement) => {
    const file = input.files?.[0];
    input.value = "";
    if (!file) return;
    const request = ++selection.current;
    setPreparing(true);
    try {
      const result = await prepareAvatar(file);
      if (selection.current === request) setAvatar(result);
    } catch (error) {
      if (selection.current === request) reportError(error);
    } finally {
      clearCapture();
      if (selection.current === request) setPreparing(false);
    }
  };
  return (
    <div className="settings-page">
      <form
        className="profile-edit-form"
        onInvalid={onInvalid}
        onSubmit={(event) => {
          event.preventDefault();
          if (busy || preparing) return;
          void (async () => {
            try {
              await onSave({ name: checkedProfileName(name), avatar });
            } catch (error) {
              reportError(error);
            }
          })();
        }}
      >
        <div className="profile-photo-preview">
          <ProfileAvatar name={name} avatar={avatar} />
        </div>
        <input
          ref={gallery}
          type="file"
          accept="image/*"
          hidden
          aria-label={t("profile.choosePhoto")}
          onChange={(event) => void choose(event.currentTarget)}
        />
        {mobile && (
          <input
            ref={camera}
            type="file"
            accept="image/*"
            capture="user"
            hidden
            aria-label={t("profile.takePhoto")}
            onChange={(event) => void choose(event.currentTarget)}
          />
        )}
        <div className="profile-photo-actions">
          <button
            type="button"
            className="ghost"
            disabled={busy || preparing}
            onClick={() => gallery.current?.click()}
          >
            {t("profile.choosePhoto")}
          </button>
          {mobile && (
            <button
              type="button"
              className="ghost"
              disabled={busy || preparing}
              onClick={() => camera.current?.click()}
            >
              {t("profile.takePhoto")}
            </button>
          )}
        </div>
        {avatar && (
          <button
            type="button"
            className="ghost profile-remove-photo"
            disabled={busy || preparing}
            onClick={() => setAvatar(null)}
          >
            {t("profile.removePhoto")}
          </button>
        )}
        <ProfileNameField value={name} onChange={setName} />
        <button disabled={busy || preparing}>
          {busy || preparing ? t("sync.busy") : t("profile.saveName")}
        </button>
      </form>
    </div>
  );
}
