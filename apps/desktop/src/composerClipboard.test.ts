import { expect, it } from "vitest";
import { pastedImage } from "./composerClipboard";

function clipboard(items: Partial<DataTransferItem>[], files: File[] = []) {
  return { items, files } as unknown as Pick<DataTransfer, "items" | "files">;
}

it("uses copied image bytes even when the browser also supplies HTML and a URL", () => {
  const image = new File([new Uint8Array([137, 80, 78, 71])], "image.png", {
    type: "image/png",
  });
  expect(
    pastedImage(
      clipboard([
        { kind: "string", type: "text/html" },
        { kind: "string", type: "text/plain" },
        { kind: "file", type: "image/png", getAsFile: () => image },
      ]),
    ),
  ).toBe(image);
});

it("supports WebViews that expose images only through the pasted file list", () => {
  const image = new File(["image"], "photo.jpg", { type: "image/jpeg" });
  expect(pastedImage(clipboard([], [image]))).toBe(image);
  expect(
    pastedImage(
      clipboard(
        [{ kind: "file", type: "image/jpeg", getAsFile: () => null }],
        [image],
      ),
    ),
  ).toBe(image);
});

it("leaves ordinary text, copied image links and non-image files to normal paste", () => {
  expect(
    pastedImage(
      clipboard([
        { kind: "string", type: "text/html" },
        { kind: "string", type: "text/uri-list" },
      ]),
    ),
  ).toBeUndefined();
  const file = new File(["text"], "note.txt", { type: "text/plain" });
  expect(pastedImage(clipboard([], [file]))).toBeUndefined();
});
