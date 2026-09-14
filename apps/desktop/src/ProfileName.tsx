import { t } from "./i18n";

export function checkedProfileName(value: string): string {
  const name = value.trim();
  if (
    !name ||
    new TextEncoder().encode(name).length > 120 ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(name)
  ) {
    throw t("profile.nameInvalid");
  }
  return name;
}

export function ProfileNameField({
  value,
  onChange,
  compact = false,
}: {
  value: string;
  onChange: (name: string) => void;
  compact?: boolean;
}) {
  return (
    <label>
      {!compact && <span>{t("profile.name")}</span>}
      <input
        required
        name="name"
        className="profile-name-input"
        aria-label={compact ? t("profile.name") : undefined}
        autoComplete="nickname"
        autoCapitalize="words"
        autoCorrect="off"
        spellCheck={false}
        maxLength={120}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}
