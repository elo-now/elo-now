import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon";
import { t } from "./i18n";
import { useToast } from "./Toast";

/** Background synchronization must not animate or dim a manual refresh control. */
export function RefreshButton({
  onRefresh,
  className = "",
}: {
  onRefresh: () => Promise<void>;
  className?: string;
}) {
  const [refreshing, setRefreshing] = useState(false);
  const pending = useRef(false);
  const mounted = useRef(true);
  const { reportError } = useToast();
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const refresh = async () => {
    if (pending.current) return;
    pending.current = true;
    setRefreshing(true);
    try {
      await onRefresh();
    } catch (error) {
      reportError(error);
    } finally {
      pending.current = false;
      if (mounted.current) setRefreshing(false);
    }
  };
  return (
    <button
      type="button"
      className={`icon desktop-refresh-button ${className}`}
      disabled={refreshing}
      data-busy={refreshing || undefined}
      aria-busy={refreshing}
      aria-label={t("refresh.action")}
      title={t(refreshing ? "refresh.busy" : "refresh.action")}
      onClick={() => void refresh()}
    >
      <Icon name="sync" />
    </button>
  );
}
