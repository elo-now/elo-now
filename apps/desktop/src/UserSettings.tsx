import { PasswordInput } from "./PasswordInput";
import {
  useEffect,
  useRef,
  useState,
  lazy,
  Suspense,
  type ReactNode,
  type CSSProperties,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon, NewIndicator, type IconName } from "./Icon";
import {
  ProfileAvatar,
  ProfileEditor,
  type ProfilePresentation,
} from "./ProfileEditor";
import { ScreenHeader } from "./ScreenHeader";
import { getVersion } from "@tauri-apps/api/app";
import { version as configuredVersion } from "../src-tauri/tauri.conf.json";
const LicenseSettings = lazy(() => import("./LicenseSettings"));
import { ColorPicker } from "./ColorPicker";
import { RingtonePicker } from "./calls/RingtonePicker";
import { MotifPicker } from "./MotifPicker";
import { DevicesSettings, RecoverySettings } from "./ProfileDevices";
import { t } from "./i18n";
import {
  colorSchemes,
  selectColorScheme,
  selectMotif,
  savePreferences,
  updateColorOverride,
  type ColorScheme,
  type PaletteKey,
  type UserPreferences,
} from "./preferences";
import type { Theme } from "./theme";
import type { ViewMode } from "./viewMode";
import { useToast } from "./Toast";
import {
  biometricName,
  disableBiometricUnlock,
  enableBiometricUnlock,
  markBiometricOfferHandled,
  readBiometricState,
  type BiometricState,
} from "./biometric";

export type SettingsPage =
  | "actions"
  | "profile"
  | "edit-profile"
  | "appearance"
  | "licenses"
  | "settings"
  | "devices"
  | "recovery"
  | "blocked-users"
  | "spaces";

const paletteKeys: PaletteKey[] = [
  "background",
  "surface",
  "text",
  "accent",
  "button",
];
const scaleValues = ["compact", "system", "large"] as const;

export function UserSettings({
  page,
  name,
  avatar,
  notifications,
  invitations,
  theme,
  mode,
  preferences,
  identity,
  credential,
  busy,
  mobile,
  demoProfile,
  onPage,
  onClose,
  onTheme,
  onMode,
  onPreferences,
  onLock,
  onProfile,
  onNotifications,
  onInvitations,
  onReminders,
  remindersDue,
  onCode,
  notificationSettings,
  spaceContext,
  spacesPage,
  blockedUsersPage,
  serviceRequests,
}: {
  page: Exclude<SettingsPage, "actions">;
  name: string;
  avatar: string | null;
  notifications: number;
  invitations: number;
  theme: Theme;
  mode: ViewMode;
  preferences: UserPreferences;
  identity: string;
  credential: string;
  busy: boolean;
  mobile: boolean;
  demoProfile?: string;
  onPage: (page: Exclude<SettingsPage, "actions">) => void;
  onClose: () => void;
  onTheme: (theme: Theme) => void;
  onMode: (mode: ViewMode) => void;
  onPreferences: (preferences: UserPreferences) => void;
  onLock: () => void;
  onProfile: (profile: ProfilePresentation) => Promise<void>;
  onNotifications: () => void;
  onInvitations: () => void;
  onReminders: () => void;
  remindersDue: boolean;
  onCode: () => void;
  notificationSettings?: ReactNode;
  spaceContext?: ReactNode;
  spacesPage?: ReactNode;
  blockedUsersPage?: ReactNode;
  serviceRequests?: ReactNode;
}) {
  const title = {
    profile: t("nav.you"),
    "edit-profile": t("profile.edit"),
    appearance: t("settings.appearance"),
    licenses: t("legal.title"),
    settings: t("settings.title"),
    devices: t("devices.title"),
    recovery: t("recover.settingsTitle"),
    "blocked-users": t("blocking.title"),
    spaces: t("spaces.title"),
  }[page];
  return (
    <>
      {page !== "profile" && page !== "licenses" && page !== "spaces" && (
        <ScreenHeader
          title={title}
          desktopRoot={page !== "edit-profile"}
          onBack={() => onPage("profile")}
          backLabel={t("settings.back")}
        />
      )}
      {page === "profile" && (
        <div className="settings-page profile-page" aria-label={title}>
          <div className="profile-content">
            <div className="profile-hero">
              <button
                type="button"
                className="icon profile-logout"
                aria-label={t("profile.lock")}
                disabled={busy}
                onClick={onLock}
              >
                <Icon name="power" />
              </button>
              <button
                type="button"
                className="icon profile-code"
                aria-label={t("invite.myCode")}
                onClick={onCode}
              >
                <Icon name="qr" />
              </button>
              <button
                type="button"
                className="profile-edit-button"
                aria-label={t("profile.edit")}
                onClick={() => onPage("edit-profile")}
              >
                <ProfileAvatar name={name} avatar={avatar} />
                <span className="profile-edit-badge">
                  <Icon name="edit" />
                </span>
              </button>
              <div className="profile-name-row">
                <h2>{name || t("profile.yourProfile")}</h2>
                {spaceContext}
              </div>
            </div>
            <nav className="settings-tiles" aria-label={t("settings.title")}>
              <SettingsLink
                icon="clock"
                label={t("reminders.title")}
                hasNew={remindersDue}
                row
                onClick={onReminders}
              />
              <SettingsLink
                row
                icon="bell"
                label={t("invite.page.notifications")}
                hasNew={notifications > 0}
                accessibleLabel={
                  notifications > 0
                    ? t("notifications.count", { count: notifications })
                    : undefined
                }
                onClick={onNotifications}
              />
              <SettingsLink
                row
                icon="rejected"
                label={t("blocking.title")}
                onClick={() => onPage("blocked-users")}
              />
              <SettingsLink
                row
                icon="inbox"
                label={t("invite.page.activity")}
                hasNew={invitations > 0}
                accessibleLabel={
                  invitations > 0
                    ? t("invite.activity.count", { count: invitations })
                    : undefined
                }
                onClick={onInvitations}
              />
              <hr className="settings-tiles-divider" />
              <SettingsLink
                icon="palette"
                label={t("settings.appearance")}
                onClick={() => onPage("appearance")}
              />
              <SettingsLink
                icon="actions"
                label={t("settings.title")}
                onClick={() => onPage("settings")}
              />
              <SettingsLink
                icon="device"
                label={t("devices.title")}
                onClick={() => onPage("devices")}
              />
              <SettingsLink
                icon="lock"
                label={t("recover.settingsTitle")}
                onClick={() => onPage("recovery")}
              />
              <SettingsLink
                icon="file"
                label={t("legal.title")}
                onClick={() => onPage("licenses")}
              />
            </nav>
            <AppVersion />
          </div>
          <button
            className="settings-close ghost desktop-only"
            onClick={onClose}
          >
            {t("dialog.close")}
          </button>
        </div>
      )}
      {page === "edit-profile" && (
        <ProfileEditor
          name={name}
          avatar={avatar}
          mobile={mobile}
          busy={busy}
          onSave={async (value) => {
            await onProfile(value);
            onPage("profile");
          }}
        />
      )}
      {page === "appearance" && (
        <AppearanceSettings
          theme={theme}
          preferences={preferences}
          onTheme={onTheme}
          onChange={onPreferences}
        />
      )}
      {page === "licenses" && (
        <Suspense
          fallback={
            <ScreenHeader
              title={t("legal.title")}
              desktopRoot
              onBack={() => onPage("profile")}
            />
          }
        >
          <LicenseSettings
            onBack={() => onPage("profile")}
            serviceRequests={serviceRequests}
          />
        </Suspense>
      )}
      {page === "spaces" && spacesPage}
      {page === "blocked-users" && blockedUsersPage}
      {page === "devices" && <DevicesSettings mobile={mobile} />}
      {page === "recovery" && (
        <RecoverySettings
          mobile={mobile}
          identity={identity}
          demoProfile={demoProfile}
        />
      )}
      {page === "settings" && (
        <div className="settings-page general-settings">
          <section aria-labelledby="settings-language-title">
            <h3 id="settings-language-title">{t("language.label")}</h3>
            <select
              aria-labelledby="settings-language-title"
              value={preferences.language}
              onChange={(event) =>
                onPreferences({
                  ...preferences,
                  language: event.target.value === "system" ? "system" : "en",
                })
              }
            >
              <option value="en">{t("language.english")}</option>
              <option value="system">{t("language.system")}</option>
            </select>
            <p className="muted">{t("language.help")}</p>
          </section>
          {notificationSettings && (
            <section aria-labelledby="settings-notifications-title">
              <h3 id="settings-notifications-title">
                {t("invite.page.notifications")}
              </h3>
              {notificationSettings}
            </section>
          )}
          {mobile && (
            <section aria-labelledby="settings-security-title">
              <h3 id="settings-security-title">{t("settings.security")}</h3>
              <SecuritySettings
                identity={identity}
                demoProfile={demoProfile}
                busy={busy}
              />
            </section>
          )}
          <section aria-labelledby="settings-view-title">
            <h3 id="settings-view-title">{t("view.label")}</h3>
            <label className="check">
              <input
                type="checkbox"
                checked={mode === "expert"}
                onChange={(event) =>
                  onMode(event.target.checked ? "expert" : "default")
                }
              />
              <span>{t("view.enableDebug")}</span>
            </label>
            <p className="muted">{t("view.help")}</p>
          </section>
          {mode === "expert" && (
            <section className="profile-identifiers muted">
              <h3>{t("profile.identifiers")}</h3>
              <dl>
                <dt>{t("profile.identityId")}</dt>
                <dd>
                  <code>{identity}</code>
                </dd>
                <dt>{t("profile.credentialId")}</dt>
                <dd>
                  <code>{credential}</code>
                </dd>
              </dl>
            </section>
          )}
        </div>
      )}
    </>
  );
}

function SettingsLink({
  icon,
  label,
  hasNew = false,
  accessibleLabel,
  row = false,
  onClick,
}: {
  icon: IconName;
  label: string;
  hasNew?: boolean;
  accessibleLabel?: string;
  row?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className="settings-tile"
      aria-label={accessibleLabel}
      data-row={row}
      onClick={onClick}
    >
      <Icon name={icon} />
      <span>{label}</span>
      {hasNew && <NewIndicator />}
    </button>
  );
}

function SecuritySettings({
  identity,
  demoProfile,
  busy,
}: {
  identity: string;
  demoProfile?: string;
  busy: boolean;
}) {
  const { reportError, onInvalid } = useToast();
  const [biometric, setBiometric] = useState<BiometricState | null>(null);
  const [password, setPassword] = useState("");
  const [editing, setEditing] = useState(false);
  const [working, setWorking] = useState(false);
  const [notice, setNotice] = useState("");
  const dialog = useRef<HTMLDialogElement>(null);
  const refresh = () =>
    readBiometricState(identity)
      .then(setBiometric)
      .catch((error) => {
        setBiometric(null);
        reportError(error);
      });
  useEffect(() => {
    void refresh();
  }, []);
  useEffect(() => {
    if (editing) dialog.current?.showModal();
    else dialog.current?.close();
  }, [editing]);
  const closeDialog = () => {
    setPassword("");
    setEditing(false);
  };
  const enable = async () => {
    setWorking(true);
    setNotice("");
    try {
      if (!demoProfile) await invoke("verify_password", { password });
      if (!biometric?.profile) throw new Error("dataNeedsReenrollment");
      await enableBiometricUnlock(password, demoProfile, biometric.profile);
      markBiometricOfferHandled(biometric.profile);
      closeDialog();
      await refresh();
      setNotice(t("biometric.enabled"));
    } catch (error) {
      reportError(error, new TextEncoder().encode(password).length);
    } finally {
      setPassword("");
      setWorking(false);
    }
  };
  const disable = async () => {
    setWorking(true);
    setNotice("");
    try {
      await disableBiometricUnlock(biometric?.profile);
      await refresh();
      setNotice(t("biometric.disabled"));
    } catch (error) {
      reportError(error);
    } finally {
      setWorking(false);
    }
  };
  const name = biometric ? biometricName(biometric.type) : t("biometric.name");
  return (
    <div className="security-settings">
      <div className="security-summary">
        <span className="settings-icon">
          <Icon name="verified" />
        </span>
        <div>
          <strong>{name}</strong>
          <small>
            {biometric?.enabled
              ? t("biometric.on")
              : biometric?.available
                ? t("biometric.off")
                : t("biometric.unavailable")}
          </small>
        </div>
      </div>
      <p className="muted">
        {biometric?.available && demoProfile
          ? t("biometric.demoHelp", { name })
          : biometric?.available
            ? t("biometric.help", { name })
            : t("biometric.setupHelp")}
      </p>
      {notice && <p className="settings-notice">{notice}</p>}
      {biometric?.enabled ? (
        <button
          className="secondary"
          disabled={busy || working}
          onClick={() => void disable()}
        >
          {t("biometric.disable")}
        </button>
      ) : (
        <button
          disabled={busy || working || !biometric?.available}
          onClick={() => (demoProfile ? void enable() : setEditing(true))}
        >
          {t("biometric.enable", { name })}
        </button>
      )}
      {editing && !demoProfile && (
        <dialog
          ref={dialog}
          className="dialog biometric-dialog"
          aria-labelledby="biometric-dialog-title"
          onCancel={(event) => {
            event.preventDefault();
            closeDialog();
          }}
        >
          <button
            className="icon close"
            type="button"
            aria-label={t("dialog.close")}
            onClick={closeDialog}
          >
            <Icon name="close" />
          </button>
          <h2 id="biometric-dialog-title">{t("biometric.confirmTitle")}</h2>
          <p>{t("biometric.confirmHelp", { name })}</p>
          <form
            onInvalid={onInvalid}
            onSubmit={(event) => {
              event.preventDefault();
              void enable();
            }}
          >
            <label>
              {t("unlock.password")}
              <PasswordInput
                autoFocus
                required
                maxLength={1024}
                value={password}
                autoComplete="current-password"
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>
            <button disabled={working}>{t("biometric.confirm")}</button>
          </form>
        </dialog>
      )}
    </div>
  );
}

function Segmented<T extends string>({
  values,
  selected,
  labels,
  onSelect,
}: {
  values: readonly T[];
  selected: T;
  labels: string[];
  onSelect: (value: T) => void;
}) {
  return (
    <div className="appearance" role="group">
      {values.map((value, index) => (
        <button
          key={value}
          type="button"
          aria-pressed={selected === value}
          onClick={() => onSelect(value)}
        >
          {labels[index]}
        </button>
      ))}
    </div>
  );
}

function AppearanceSettings({
  theme,
  preferences,
  onTheme,
  onChange,
}: {
  theme: Theme;
  preferences: UserPreferences;
  onTheme: (theme: Theme) => void;
  onChange: (preferences: UserPreferences) => void;
}) {
  const index = scaleValues.indexOf(preferences.uiScale);
  const [editingColor, setEditingColor] = useState<PaletteKey | null>(null);
  const palette = {
    ...colorSchemes[preferences.colorScheme][theme],
    ...preferences.colorOverrides[theme],
  };
  return (
    <div className="settings-page appearance-page">
      <h3>{t("theme.mode")}</h3>
      <Segmented
        values={["light", "dark"]}
        selected={theme}
        labels={[t("theme.light"), t("theme.dark")]}
        onSelect={onTheme}
      />
      <button
        type="button"
        className="settings-toggle"
        role="switch"
        aria-checked={preferences.hideAvatars}
        onClick={() =>
          onChange({ ...preferences, hideAvatars: !preferences.hideAvatars })
        }
      >
        <span>{t("settings.hideAvatars")}</span>
        <span className="toggle-track" aria-hidden="true">
          <span />
        </span>
      </button>
      <button
        type="button"
        className="settings-toggle"
        role="switch"
        aria-checked={preferences.highlightMyMessages}
        onClick={() =>
          onChange({
            ...preferences,
            highlightMyMessages: !preferences.highlightMyMessages,
          })
        }
      >
        <span>{t("settings.highlightMyMessages")}</span>
        <span className="toggle-track" aria-hidden="true">
          <span />
        </span>
      </button>
      <h3>{t("scale.label")}</h3>
      <input
        className="scale-slider"
        data-scale={preferences.uiScale}
        type="range"
        min="0"
        max="2"
        step="1"
        value={index}
        aria-label={t("scale.label")}
        aria-valuetext={t(`scale.${preferences.uiScale}` as "scale.system")}
        onChange={(event) =>
          onChange({
            ...preferences,
            uiScale: scaleValues[Number(event.target.value)],
          })
        }
      />
      <div className="scale-labels" aria-hidden="true">
        <span>{t("scale.compact")}</span>
        <span>{t("scale.system")}</span>
        <span>{t("scale.large")}</span>
      </div>
      <RingtonePicker
        value={preferences.callRingtone}
        onChange={(callRingtone) => onChange({ ...preferences, callRingtone })}
      />
      <MotifPicker
        value={preferences.motif}
        onChange={(motif) => onChange(selectMotif(preferences, motif))}
        drawing={preferences.customMotif}
        onDrawing={(customMotif) => {
          const next = {
            ...preferences,
            motif: "custom" as const,
            customMotif,
          };
          // Do not discard user-created artwork when storage is unavailable.
          if (!savePreferences(next)) return false;
          onChange(next);
          return true;
        }}
      />
      <input
        id="motif-opacity"
        className="scale-slider motif-opacity-slider"
        style={
          {
            "--scale-fill": `${(preferences.motifOpacity / 0.3) * 100}%`,
          } as CSSProperties
        }
        type="range"
        min="0"
        max="30"
        step="1"
        value={Math.round(preferences.motifOpacity * 100)}
        disabled={preferences.motif === "none"}
        aria-valuetext={t("motif.percent", {
          value: Math.round(preferences.motifOpacity * 100),
        })}
        onChange={(event) =>
          onChange({
            ...preferences,
            motifOpacity: Number(event.target.value) / 100,
          })
        }
      />
      <label className="motif-opacity-label" htmlFor="motif-opacity">
        <span>{t("motif.opacity")}</span>
        <span>
          {t("motif.percent", {
            value: Math.round(preferences.motifOpacity * 100),
          })}
        </span>
      </label>
      <h3>{t("scheme.label")}</h3>
      <div className="scheme-grid">
        {(Object.keys(colorSchemes) as ColorScheme[]).map((scheme) => (
          <button
            key={scheme}
            type="button"
            aria-pressed={preferences.colorScheme === scheme}
            onClick={() => onChange(selectColorScheme(preferences, scheme))}
          >
            <span className="scheme-swatches">
              {Object.values(colorSchemes[scheme][theme])
                .slice(0, 5)
                .map((color) => (
                  <i key={color} style={{ background: color }} />
                ))}
            </span>
            {t(`scheme.${scheme}` as "scheme.mint")}
          </button>
        ))}
      </div>
      <h3>{t("scheme.customize")}</h3>
      <div className="color-editor">
        {paletteKeys.map((color) => (
          <button
            key={color}
            type="button"
            className="color-edit"
            aria-haspopup="dialog"
            onClick={() => setEditingColor(color)}
          >
            <span>{t(`color.${color}` as "color.text")}</span>
            <i
              className="color-edit-swatch"
              style={{ background: palette[color] }}
            />
          </button>
        ))}
      </div>
      {editingColor && (
        <ColorPicker
          label={t(`color.${editingColor}` as "color.text")}
          value={palette[editingColor]}
          onClose={() => setEditingColor(null)}
          onSave={(value) => {
            onChange(
              updateColorOverride(preferences, theme, editingColor, value),
            );
            setEditingColor(null);
          }}
        />
      )}
    </div>
  );
}

function AppVersion() {
  const [version, setVersion] = useState(configuredVersion);
  useEffect(() => {
    let active = true;
    void getVersion()
      .then((value) => {
        if (active && value) setVersion(value);
      })
      .catch(() => {
        // Browser previews use the native build configuration version.
      });
    return () => {
      active = false;
    };
  }, []);
  return <p className="app-version">{t("app.version", { version })}</p>;
}
