import { expect, test } from "vitest";
import { droppedAttachment, hasDroppedFiles } from "./attachmentDrop";

const transfer = (files: File[], directory = false) =>
  ({
    files,
    items: directory
      ? [{ kind: "file", webkitGetAsEntry: () => ({ isDirectory: true }) }]
      : [],
  }) as unknown as Pick<DataTransfer, "files" | "items">;
test("only an actual dropped file is accepted, never a URL or HTML copy", () => {
  expect(hasDroppedFiles({ types: ["text/uri-list", "text/html"] })).toBe(
    false,
  );
  const file = new File(["photo"], "photo.png", { type: "image/png" });
  expect(hasDroppedFiles({ types: ["Files"] })).toBe(true);
  expect(droppedAttachment(transfer([file]))).toBe(file);
});
test("folders, multiple files and oversized files are rejected without silently losing files", () => {
  const file = new File(["data"], "file.txt");
  expect(() => droppedAttachment(transfer([file], true))).toThrow(
    "not a folder",
  );
  expect(() => droppedAttachment(transfer([file, file]))).toThrow("one file");
  expect(() => droppedAttachment(transfer([]))).toThrow("one file");
  expect(() =>
    droppedAttachment(
      transfer([new File([new Uint8Array(5 * 1024 * 1024 + 1)], "big")]),
    ),
  ).toThrow("5 MB");
});
