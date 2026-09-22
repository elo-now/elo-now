import type { ComponentProps } from "react";

/** Shared desktop content width, inset and scroll area; mobile keeps its layout. */
export function PageContent({
  className = "",
  ...props
}: ComponentProps<"div">) {
  return <div {...props} className={`page-content ${className}`} />;
}
