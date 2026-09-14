import type { ReactNode } from "react";

export function EmptyState({
  message,
  children,
}: {
  message: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <p className="empty-state-label">{message}</p>
      {children}
    </div>
  );
}
