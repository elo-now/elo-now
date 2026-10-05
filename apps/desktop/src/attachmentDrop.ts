/** Accept actual OS/browser-provided files, never fetch dropped URLs or HTML. */
export function hasDroppedFiles(data: Pick<DataTransfer, "types">) {
  return Array.from(data.types).includes("Files");
}

export function droppedAttachment(
  data: Pick<DataTransfer, "files" | "items">,
): File {
  const items = Array.from(data.items ?? []).filter(
    (item) => item.kind === "file",
  );
  if (items.some((item) => item.webkitGetAsEntry?.()?.isDirectory))
    throw new Error("Drop a file, not a folder.");
  const files = Array.from(data.files);
  if (files.length !== 1) throw new Error("Attach one file at a time.");
  if (files[0].size > 5 * 1024 * 1024)
    throw new Error("Attachment files cannot exceed 5 MB.");
  return files[0];
}
