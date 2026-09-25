import { UpdateBanner } from "./UpdateGate";
import { PasswordInput } from "./PasswordInput";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { invoke } from "@tauri-apps/api/core";
import { t } from "./i18n";
import { Icon } from "./Icon";
import type { Theme } from "./theme";
import { useToast } from "./Toast";
import { Brand, useBrandIntro } from "./Brand";
import { BrandPronunciation } from "./BrandPronunciation";
import { acceptLegal, hasAcceptedLegal, LegalNotice } from "./LegalInfo";
import { ProfileNameField, checkedProfileName } from "./ProfileName";
import { ProfileRecovery, RecoveryQr } from "./ProfileRecovery";
import { recoveryCode } from "./recoveryCode";
import { RecoveryCodePanel } from "./RecoveryCodePanel";
import type { View } from "./model";
import {
  biometricCancelled,
  biometricName,
  readBiometricCredential,
  readBiometricState,
  clearLegacyBiometricUnlock,
  type BiometricState,
} from "./biometric";

type Environment = {
  mobile: boolean;
  directory: string;
  has_profile: boolean;
  demo_helpers: boolean;
  saved_profiles: { id: string; identity: string; active: boolean }[];
};
type Card = { identity_id: string; phrase: string };
export function ProfileGate({
  appearance,
  theme,
  onTheme,
  onOpen,
}: {
  appearance: ReactNode;
  theme: Theme;
  onTheme: (theme: Theme) => void;
  onOpen: (
    view: View,
    mobile: boolean,
    verifiedPassword?: string,
    demoProfile?: string,
  ) => void;
}) {
  const introFrame = useBrandIntro();
  const [environment, setEnvironment] = useState<Environment | null>(null);
  const [existing, setExisting] = useState(false);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [card, setCard] = useState<Card | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const { showError: setError, reportError, onInvalid, notify } = useToast();
  const [recovering, setRecovering] = useState(false);
  const [biometric, setBiometric] = useState<BiometricState | null>(null);
  useEffect(() => {
    let live = true;
    void invoke<Environment>("profile_environment")
      .then(async (env) => {
        // Unbound legacy entries are never read. Failed cleanup must not block
        // password login (e.g. while the device keychain is unavailable).
        if (env.mobile) await clearLegacyBiometricUnlock().catch(() => {});
        if (live) {
          setBiometric(null);
          setEnvironment(env);
          setExisting(env.has_profile);
        }
      })
      .catch((e: unknown) => {
        if (live) reportError(e);
      });
    return () => {
      live = false;
    };
  }, []);
  useEffect(() => {
    setBiometric(null);
    if (!environment?.mobile || !environment.has_profile) return;
    let live = true;
    void readBiometricState()
      .then((value) => {
        if (live) setBiometric(value);
      })
      .catch(() => {
        if (live) setBiometric(null);
      });
    return () => {
      live = false;
    };
  }, [environment]);
  const perform = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      reportError(e, new TextEncoder().encode(password).length);
    } finally {
      setBusy(false);
    }
  };
  const open = async (unlockPassword = password, offerBiometrics = true) => {
    if (!environment) return;
    const directory = environment.directory;
    const view = await invoke<View>(
      card ? "create_profile" : "unlock",
      card
        ? {
            directory,
            password: unlockPassword,
            initialChannel: t("onboarding.initialChannel"),
            name: checkedProfileName(name),
            acknowledged,
          }
        : {
            directory,
            password: unlockPassword,
            allowInsecureLoopback: false,
          },
    );
    acceptLegal(view.identity);
    setPassword("");
    setRepeat("");
    setCard(null);
    setAcknowledged(false);
    onOpen(
      view,
      environment.mobile,
      offerBiometrics ? unlockPassword : undefined,
    );
  };
  const unlocking = existing && !card;
  const existingIdentity = environment?.saved_profiles.find(
    (profile) => profile.active,
  )?.identity;
  const needsLegalNotice =
    !existingIdentity || !hasAcceptedLegal(existingIdentity);
  const pinAppearance = environment?.mobile && !card;
  const unlockWithBiometrics = async () => {
    if (!environment || !biometric?.enabled || !biometric.profile) return;
    setBusy(true);
    setError("");
    try {
      const credential = await readBiometricCredential(
        t("biometric.unlockReason"),
        biometric.profile,
      );
      if (credential.demoProfile) {
        const view = await invoke<View>("open_demo", {
          person: credential.demoProfile,
        });
        onOpen(view, environment.mobile, undefined, credential.demoProfile);
      } else {
        const view = await invoke<View>("unlock", {
          directory: environment.directory,
          password: "",
          allowInsecureLoopback: false,
          biometricKey: credential.key,
          biometricProfile: biometric.profile.id,
          biometricIdentity: biometric.profile.identity,
        });
        acceptLegal(view.identity);
        setPassword("");
        onOpen(view, environment.mobile);
      }
    } catch (error) {
      if (!biometricCancelled(error)) reportError(error);
    } finally {
      setBusy(false);
    }
  };
  if (recovering && environment)
    return (
      <ProfileRecovery
        mobile={environment.mobile}
        hasProfile={environment.has_profile}
        onBack={() => setRecovering(false)}
        onOpen={(view, password) => onOpen(view, environment.mobile, password)}
      />
    );
  const menu = (
    <AuthMenu
      theme={theme}
      onTheme={onTheme}
      disabled={busy || !environment}
      savedProfiles={environment?.saved_profiles ?? []}
      onSelectProfile={(id) =>
        void perform(async () => {
          await invoke("profile_task", { request: { op: "select", id } });
          const env = await invoke<Environment>("profile_environment");
          setBiometric(null);
          setEnvironment(env);
          setExisting(env.has_profile);
          setPassword("");
          setRepeat("");
        })
      }
      onRecover={() => {
        setPassword("");
        setRepeat("");
        setRecovering(true);
      }}
    />
  );
  return (
    <main className={`unlock${card ? " recovery" : ""}`}>
      <div className={card ? "unlock-brand" : "unlock-tools"}>
        {card && <Brand />}
        {!pinAppearance && (card ? appearance : menu)}
      </div>
      <UpdateBanner />
      <div
        className="unlock-content"
        data-credentials={!card}
        data-registration={!existing && !card}
      >
        {!card ? (
          <div className="unlock-logo">
            <Brand introFrame={introFrame} />
          </div>
        ) : (
          <h1>{t("onboarding.recovery")}</h1>
        )}
        {card && <p>{t("onboarding.recoveryHelp")}</p>}
        {card && (
          <RecoveryCodePanel value={recoveryCode(card)} disabled={busy}>
            <RecoveryQr mobile={!!environment?.mobile} />
          </RecoveryCodePanel>
        )}
        <form
          aria-label={
            unlocking
              ? t("unlock.title")
              : card
                ? t("onboarding.recovery")
                : t("onboarding.new")
          }
          onInvalid={onInvalid}
          onSubmit={(event) => {
            event.preventDefault();
            void perform(async () => {
              if (existing || card) {
                await open();
                return;
              }
              setName(checkedProfileName(name));
              if (password !== repeat) throw t("onboarding.passwordMismatch");
              setCard(await invoke<Card>("prepare_profile"));
            });
          }}
        >
          {unlocking && needsLegalNotice && <LegalNotice unlocking />}
          {unlocking && environment?.mobile && biometric?.enabled && (
            <>
              <button
                className="biometric-unlock"
                type="button"
                disabled={busy}
                onClick={() => void unlockWithBiometrics()}
              >
                {t("biometric.unlockWith", {
                  name: biometricName(biometric.type),
                })}
              </button>
              <div className="auth-divider">{t("biometric.orPassword")}</div>
            </>
          )}
          {card && (
            <>
              <label className="check">
                <input
                  type="checkbox"
                  checked={acknowledged}
                  onChange={(e) => setAcknowledged(e.target.checked)}
                />
                {t("onboarding.confirm")}
              </label>
            </>
          )}
          {!card && (
            <>
              {!existing && (
                <ProfileNameField value={name} onChange={setName} />
              )}
              <label>
                {t("unlock.password")}
                <PasswordInput
                  required
                  minLength={existing ? undefined : 12}
                  maxLength={1024}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="off"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                />
              </label>
              {!existing && (
                <>
                  <small>{t("onboarding.passwordHelp")}</small>
                  <label>
                    {t("onboarding.confirmPassword")}
                    <PasswordInput
                      required
                      minLength={12}
                      maxLength={1024}
                      value={repeat}
                      onChange={(e) => setRepeat(e.target.value)}
                      autoComplete="off"
                    />
                  </label>
                </>
              )}
            </>
          )}
          {!existing && !card && (
            <LegalNotice action={t("onboarding.create")} />
          )}
          <div className="auth-actions">
            <button
              disabled={busy || !environment || (!!card && !acknowledged)}
            >
              {busy
                ? t("sync.busy")
                : card
                  ? t("onboarding.finish")
                  : existing
                    ? t("unlock.open")
                    : t("onboarding.create")}
            </button>
          </div>
          <button
            className="ghost"
            type="button"
            disabled={busy}
            onClick={() =>
              void perform(async () => {
                if (card) {
                  await invoke("cancel_profile");
                  setCard(null);
                  setAcknowledged(false);
                } else if (
                  environment?.mobile &&
                  !environment.has_profile &&
                  !existing
                ) {
                  setRecovering(true);
                } else setExisting(!existing);
                setPassword("");
                setRepeat("");
              })
            }
          >
            {card
              ? t("onboarding.cancel")
              : existing
                ? t("onboarding.newPrompt")
                : t("onboarding.existing")}
          </button>
        </form>
      </div>
      {pinAppearance &&
        createPortal(
          <div className="unlock-pinned-tools">
            <BrandPronunciation />
            {menu}
          </div>,
          document.getElementById("root") ?? document.body,
        )}
    </main>
  );
}

function AuthMenu({
  theme,
  onTheme,
  onRecover,
  savedProfiles,
  onSelectProfile,
  disabled,
}: {
  theme: Theme;
  onTheme: (theme: Theme) => void;
  onRecover: () => void;
  savedProfiles: Environment["saved_profiles"];
  onSelectProfile: (id: string) => void;
  disabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const menuId = useId();
  const close = () => {
    setOpen(false);
    trigger.current?.focus({ preventScroll: true });
  };
  useEffect(() => {
    if (!open) return;
    root.current
      ?.querySelector<HTMLButtonElement>('[role="menuitem"]')
      ?.focus({ preventScroll: true });
    const dismiss = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", dismiss);
    return () => document.removeEventListener("pointerdown", dismiss);
  }, [open]);
  return (
    <div
      ref={root}
      className="auth-menu"
      onBlur={(event) => {
        // iOS can blur a menu item with no related target before its tap clicks.
        // Outside taps are handled separately; only a known focus exit closes it.
        if (
          event.relatedTarget &&
          !event.currentTarget.contains(event.relatedTarget)
        )
          setOpen(false);
      }}
      onKeyDown={(event) => {
        if (event.key === "Escape" && open) {
          event.preventDefault();
          close();
        } else if (
          ["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)
        ) {
          event.preventDefault();
          if (!open) {
            setOpen(true);
            return;
          }
          const items = [
            ...event.currentTarget.querySelectorAll<HTMLButtonElement>(
              '[role="menuitem"]',
            ),
          ];
          const current = items.indexOf(
            document.activeElement as HTMLButtonElement,
          );
          const index =
            event.key === "Home"
              ? 0
              : event.key === "End"
                ? items.length - 1
                : (current +
                    (event.key === "ArrowUp" ? -1 : 1) +
                    items.length) %
                  items.length;
          items[index]?.focus({ preventScroll: true });
        }
      }}
    >
      <button
        ref={trigger}
        type="button"
        className="icon auth-menu-trigger"
        aria-label={t("nav.more")}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={menuId}
        disabled={disabled}
        onClick={() => setOpen((value) => !value)}
      >
        <Icon name="more" />
      </button>
      {open && (
        <div
          id={menuId}
          className="auth-menu-list"
          role="menu"
          aria-label={t("nav.more")}
        >
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              close();
              onTheme(theme === "dark" ? "light" : "dark");
            }}
          >
            {t(theme === "dark" ? "theme.lightMode" : "theme.darkMode")}
          </button>
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              close();
              onRecover();
            }}
          >
            {t("recover.title")}
          </button>
          {savedProfiles.length > 1 &&
            savedProfiles.map((profile, index) => (
              <button
                key={profile.id}
                type="button"
                role="menuitem"
                aria-current={profile.active ? "true" : undefined}
                onClick={() => {
                  close();
                  if (!profile.active) onSelectProfile(profile.id);
                }}
              >
                {t("profile.savedNumber", { number: index + 1 })}
                {profile.active ? ` · ${t("profile.currentLocal")}` : ""}
                <small>{profile.identity.slice(0, 12)}</small>
              </button>
            ))}
        </div>
      )}
    </div>
  );
}
