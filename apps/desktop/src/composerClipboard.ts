/** Read only the image bytes provided by an explicit paste event. Never fetch HTML image URLs. */
export function pastedImage(
  data: Pick<DataTransfer, "items" | "files">,
): File | undefined {
  for (const item of Array.from(data.items ?? [])) {
    if (item.kind !== "file" || !item.type.startsWith("image/")) continue;
    const file = item.getAsFile();
    if (file) return file;
  }
  return Array.from(data.files ?? []).find((file) =>
    file.type.startsWith("image/"),
  );
}
