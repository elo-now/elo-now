import { useRef, type ReactNode, type RefObject } from "react";
import { useBackSwipe } from "./useBackSwipe";
import { ParticipantTitle } from "./ParticipantTitle";
import { Icon } from "./Icon";
import { t } from "./i18n";
import { navigateBackWithFade } from "./navigationFade";

/** Shared location header for every unlocked screen. */
export function ScreenHeader({
  title,
  onBack,
  backLabel,
  actions,
  titleRef,
  participants,
}: {
  title: string;
  participants?: string[];
  onBack?: () => void;
  backLabel?: string;
  actions?: ReactNode;
  titleRef?: RefObject<HTMLHeadingElement | null>;
}) {
  const header = useRef<HTMLElement>(null);
  const back = onBack
    ? () => {
        const source = header.current;
        void navigateBackWithFade(
          onBack,
          () =>
            !!source?.isConnected && source.getBoundingClientRect().height > 0,
        );
      }
    : undefined;
  useBackSwipe(header, back);
  return (
    <header ref={header} className="screen-header">
      <div className="screen-header-start">
        {onBack && (
          <button
            type="button"
            className="icon"
            aria-label={backLabel ?? t("onboarding.back")}
            onClick={back}
          >
            <Icon name="back" />
          </button>
        )}
      </div>
      <div className="screen-header-title">
        <h2 ref={titleRef} tabIndex={titleRef ? -1 : undefined}>
          {participants?.length ? (
            <ParticipantTitle names={participants} />
          ) : (
            title
          )}
        </h2>
      </div>
      <div className="screen-header-actions">{actions}</div>
    </header>
  );
}
