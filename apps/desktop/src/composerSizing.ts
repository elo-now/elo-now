const measuredProperties = [
  "box-sizing",
  "font-family",
  "font-size",
  "font-size-adjust",
  "font-style",
  "font-weight",
  "font-stretch",
  "font-variant",
  "font-feature-settings",
  "font-variation-settings",
  "line-height",
  "letter-spacing",
  "word-spacing",
  "text-indent",
  "text-transform",
  "text-rendering",
  "tab-size",
  "white-space",
  "word-break",
  "overflow-wrap",
  "padding-top",
  "padding-right",
  "padding-bottom",
  "padding-left",
  "border-top-width",
  "border-right-width",
  "border-bottom-width",
  "border-left-width",
  "border-style",
  "-webkit-text-size-adjust",
] as const;

/** Measure offscreen: collapsing a focused textarea can move WebKit's caret. */
export function createComposerSizer() {
  let mirror: HTMLTextAreaElement | undefined;
  let previousKey: string | undefined;
  let contentHeight = 0;
  return {
    resize(node: HTMLTextAreaElement) {
      if (!node.getClientRects().length) return;
      const computed = getComputedStyle(node);
      const properties = measuredProperties.map((name) => [
        name,
        computed.getPropertyValue(name),
      ]);
      const width = computed.width;
      const key = JSON.stringify([
        node.value,
        node.placeholder,
        node.wrap,
        width,
        properties,
      ]);
      const borders =
        Number.parseFloat(computed.borderTopWidth) +
        Number.parseFloat(computed.borderBottomWidth);
      const padding =
        Number.parseFloat(computed.paddingTop) +
        Number.parseFloat(computed.paddingBottom);
      if (key !== previousKey) {
        if (!mirror) {
          mirror = document.createElement("textarea");
          mirror.tabIndex = -1;
          mirror.setAttribute("aria-hidden", "true");
          mirror.inert = true;
          mirror.readOnly = true;
          mirror.style.cssText =
            "position:fixed;top:0;left:0;height:0;min-height:0;max-height:none;overflow:hidden;visibility:hidden;pointer-events:none;";
          document.body.appendChild(mirror);
        }
        for (const [name, value] of properties)
          mirror.style.setProperty(name, value);
        mirror.style.width = width;
        mirror.wrap = node.wrap;
        mirror.value = node.value || node.placeholder || " ";
        contentHeight =
          mirror.scrollHeight +
          (computed.boxSizing === "border-box" ? borders : -padding);
        previousKey = key;
      }
      // A viewport/keyboard change only changes the cap, not text measurement.
      const minimum = Number.parseFloat(computed.minHeight) || 0;
      const cssMaximum = Number.parseFloat(computed.maxHeight);
      const maximum = Math.max(
        minimum,
        Math.min(
          (window.visualViewport?.height ?? window.innerHeight) / 3,
          Number.isFinite(cssMaximum) ? cssMaximum : Infinity,
        ),
      );
      const height = `${Math.min(Math.max(minimum, contentHeight), maximum)}px`;
      if (node.style.height !== height) node.style.height = height;
      const overflow =
        node.scrollHeight > node.clientHeight ? "auto" : "hidden";
      if (node.style.overflowY !== overflow) node.style.overflowY = overflow;
    },
    invalidate() {
      previousKey = undefined;
    },
    dispose() {
      mirror?.remove();
      mirror = undefined;
      previousKey = undefined;
    },
  };
}
