import { UpdateBanner } from "./UpdateGate";
import { useRef, type ReactNode, type RefObject } from "react";
import { useBackSwipe } from "./useBackSwipe";
import { ParticipantTitle } from "./ParticipantTitle";
import { Icon } from "./Icon";
import { t } from "./i18n";
import { navigateBack } from "./navigation";
import { useDesktopLayout } from "./PageSurface";

/** Shared location header for every unlocked screen. */
export function ScreenHeader({
  title,
  onBack,
  backLabel,
  actions,
  search,
  titleRef,
  participants,
  desktopRoot = false,
  callSlot,
}: {
  title: string;
  participants?: string[];
  onBack?: () => void;
  backLabel?: string;
  actions?: ReactNode;
  search?: ReactNode;
  titleRef?: RefObject<HTMLHeadingElement | null>;
  /** Menu destinations use the persistent desktop navigation instead of Back. */
  desktopRoot?: boolean;
  /** The persistent media host portals one strip into the visible screen. */
  callSlot?: string;
}) {
  const desktop = useDesktopLayout();
  const header = useRef<HTMLElement>(null);
  const back =
    onBack && !(desktop && desktopRoot)
      ? () => {
          const source = header.current;
          navigateBack(
            onBack,
            () =>
              !!source?.isConnected &&
              source.getBoundingClientRect().height > 0,
          );
        }
      : undefined;
  useBackSwipe(header, back);
  return (
    <>
      <header ref={header} className="screen-header">
        <div className="screen-header-start">
          {back && (
            <button
              type="button"
              className="icon"
              data-system-back
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
        <div className="screen-header-actions">
          {desktop && search && (
            <div className="desktop-header-search">{search}</div>
          )}
          {actions}
        </div>
        <UpdateBanner />
      </header>
      {callSlot && <div id={callSlot} className="call-header-slot" />}
    </>
  );
}
