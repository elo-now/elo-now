"use strict";

(() => {
  const lifetimes = [21600, 43200, 86400, 172800, "no_expiry"];
  const app = document.getElementById("app");
  const form = document.getElementById("settings-form");
  const fields = document.getElementById("fields");
  const status = document.getElementById("status");
  const error = document.getElementById("error");
  const save = document.getElementById("save");
  let catalog = {};
  let state = null;
  let busy = false;
  let dirty = false;
  let saveUnconfirmed = false;

  function t(key, values = {}) {
    return (catalog[key] || key).replace(/\{([a-z_]+)\}/g, (match, name) => String(values[name] ?? match));
  }

  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function showError(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  async function request(path, options = {}) {
    const response = await fetch(new URL(path, document.baseURI), {
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(20000),
      ...options,
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      const message = response.status === 401 || response.status === 403
        ? t("error.session")
        : typeof body?.error === "string" ? body.error : t("error.connection");
      const failure = new Error(message);
      failure.responseReceived = true;
      throw failure;
    }
    if (!body || typeof body !== "object") throw new Error(t("error.connection"));
    return body;
  }

  function field(name, labelKey, value = "", hintKey = null, type = "text") {
    const wrapper = element("div", undefined, "field");
    const label = element("label", t(labelKey));
    label.htmlFor = name;
    const input = document.createElement(type === "textarea" ? "textarea" : "input");
    if (type !== "textarea") input.type = type;
    else input.rows = 4;
    input.id = name;
    input.name = name;
    input.value = value;
    input.autocomplete = "off";
    if (name !== "name") {
      input.spellcheck = false;
      input.setAttribute("autocapitalize", "off");
    }
    if (hintKey) {
      const hint = element("p", t(hintKey), "help");
      hint.id = `${name}-hint`;
      input.setAttribute("aria-describedby", hint.id);
      wrapper.append(label, input, hint);
    } else wrapper.append(label, input);
    return { wrapper, input };
  }

  function selectField(name, labelKey, options, selected, hintKey = null) {
    const wrapper = element("div", undefined, "field");
    const label = element("label", t(labelKey));
    label.htmlFor = name;
    const input = document.createElement("select");
    input.id = name;
    input.name = name;
    for (const [value, key] of options) {
      const option = element("option", t(key));
      option.value = String(value);
      option.selected = String(value) === String(selected ?? "");
      input.append(option);
    }
    wrapper.append(label, input);
    if (hintKey) {
      const hint = element("p", t(hintKey), "help");
      hint.id = `${name}-hint`;
      input.setAttribute("aria-describedby", hint.id);
      wrapper.append(hint);
    }
    return { wrapper, input };
  }

  function choice(type, name, value, label, checked) {
    const wrapper = element("label", undefined, "choice");
    const input = document.createElement("input");
    input.type = type;
    input.name = name;
    input.value = String(value);
    input.checked = checked;
    wrapper.append(input, element("span", label));
    return { wrapper, input };
  }

  function readLifetimes() {
    return [...form.querySelectorAll('input[name="message_lifetimes"]:checked')]
      .map(input => input.value === "no_expiry" ? input.value : Number(input.value));
  }

  function renderApi(configuration) {
    const name = field("name", "hosting.name.label", configuration.name || "", "hosting.name.hint");
    name.input.required = true;
    name.input.maxLength = 80;
    fields.append(name.wrapper);

    const retention = document.createElement("fieldset");
    retention.append(element("legend", t("retention.legend")), element("p", t("retention.hint"), "help"));
    const choices = element("div", undefined, "choices");
    const selected = configuration.message_lifetimes || [];
    for (const value of lifetimes) {
      choices.append(choice("checkbox", "message_lifetimes", value, t(`retention.${value}`), selected.includes(value)).wrapper);
    }
    retention.append(choices);
    const defaultLifetime = selectField("default_message_lifetime", "retention.default", [], "");
    defaultLifetime.wrapper.classList.add("nested");
    const updateDefault = (preferred) => {
      const current = String(preferred ?? defaultLifetime.input.value);
      const values = readLifetimes();
      defaultLifetime.input.replaceChildren(...values.map(value => {
        const option = element("option", t(`retention.${value}`));
        option.value = String(value);
        option.selected = String(value) === current;
        return option;
      }));
      defaultLifetime.input.required = true;
    };
    retention.append(defaultLifetime.wrapper);
    fields.append(retention);
    updateDefault(configuration.default_message_lifetime);
    choices.addEventListener("change", () => updateDefault());

    const creation = document.createElement("fieldset");
    creation.append(element("legend", t("creation.legend")));
    const radios = element("div", undefined, "radio-choices");
    for (const value of ["public", "allowlist"]) {
      radios.append(choice("radio", "creation_mode", value, t(`creation.${value}`), configuration.creation_mode === value).wrapper);
    }
    const identities = field("allowed_creators", "creation.identities.label", (configuration.allowed_creators || []).join("\n"), "creation.identities.hint", "textarea");
    identities.wrapper.classList.add("nested");
    const updateMode = () => {
      const allowlist = form.querySelector('input[name="creation_mode"]:checked')?.value === "allowlist";
      identities.wrapper.hidden = !allowlist;
      identities.input.disabled = !allowlist;
      identities.input.required = allowlist;
    };
    creation.append(radios, identities.wrapper);
    fields.append(creation);
    radios.addEventListener("change", updateMode);
    updateMode();

    const provider = selectField("managed_provider", "storage.api.label", [
      ["", "storage.none"], ["mega", "storage.mega"], ["s3", "storage.s3"],
    ], configuration.managed_provider, configuration.storage_available ? "storage.api.hint" : "storage.unavailable");
    fields.append(provider.wrapper);
    const updateManagedProvider = () => {
      const privateHosting = form.querySelector('input[name="creation_mode"]:checked')?.value === "allowlist";
      provider.input.disabled = !configuration.storage_available || !privateHosting;
      if (provider.input.disabled) provider.input.value = "";
      provider.wrapper.querySelector(".help").textContent = t(!configuration.storage_available
        ? "storage.unavailable" : privateHosting ? "storage.api.hint" : "storage.api.private");
    };
    radios.addEventListener("change", updateManagedProvider);
    updateManagedProvider();
  }

  function renderWitness(configuration) {
    const provider = selectField("provider", "storage.provider.label", [
      ["", "storage.disabled"], ["mega", "storage.mega"], ["s3", "storage.s3"],
    ], configuration.provider);
    fields.append(provider.wrapper);
    const notice = element("p", "", "credential-notice");
    fields.append(notice);
    const providerGroups = {};
    const publicFields = configuration.public_fields || {};
    const definitions = {
      mega: [
        ["folder_link", "mega.folder.label", "", "mega.folder.hint", "password"],
        ["write_auth", "mega.auth.label", "", "mega.auth.hint", "password"],
      ],
      s3: [
        ["s3_endpoint", "s3.endpoint.label", publicFields.s3_endpoint || "", "s3.endpoint.hint", "url"],
        ["s3_region", "s3.region.label", publicFields.s3_region || "", null, "text"],
        ["s3_bucket", "s3.bucket.label", publicFields.s3_bucket || "", null, "text"],
        ["s3_access_key", "s3.access.label", "", null, "password"],
        ["s3_secret_key", "s3.secret.label", "", null, "password"],
      ],
    };
    for (const [key, items] of Object.entries(definitions)) {
      const group = element("div", undefined, "credential-fields");
      for (const definition of items) group.append(field(...definition).wrapper);
      providerGroups[key] = group;
      fields.append(group);
    }
    const owners = field("allowed_owners", "storage.owners.label", (configuration.allowed_owners || []).join("\n"), "storage.owners.hint", "textarea");
    fields.append(owners.wrapper);

    const updateProvider = () => {
      const current = provider.input.value;
      const retaining = Boolean(configuration.configured && current && current === configuration.provider);
      notice.textContent = t(retaining ? "storage.configured" : "storage.new");
      notice.hidden = !current;
      for (const [key, group] of Object.entries(providerGroups)) {
        group.hidden = key !== current;
        for (const input of group.querySelectorAll("input")) {
          input.disabled = key !== current;
          input.required = key === current && !retaining;
        }
      }
      owners.wrapper.hidden = !current;
      owners.input.disabled = !current;
    };
    provider.input.addEventListener("change", updateProvider);
    updateProvider();
  }

  function renderHosting(configuration, hosting) {
    const panel = document.getElementById("hosting-panel");
    panel.hidden = !hosting?.link;
    if (panel.hidden) return;
    document.getElementById("hosting-title").textContent = t("qr.title");
    document.getElementById("hosting-instructions").textContent = t("qr.instructions");
    document.getElementById("copy-link").textContent = t("qr.copy");
    document.getElementById("configuration-link-label").textContent = t("qr.link.label");
    document.getElementById("configuration-link").value = hosting.link;
    document.getElementById("qr-hint").textContent = t("qr.hint");
    const details = document.getElementById("hosting-details");
    details.replaceChildren(
      element("p", configuration.name || "elo", "hosting-name"),
      element("p", t("qr.retention", { lifetimes: (configuration.message_lifetimes || []).map(value => t(`retention.${value}`)).join(", ") }), "hosting-policy"),
      element("p", t("qr.default", { lifetime: t(`retention.${configuration.default_message_lifetime}`) }), "hosting-policy"),
      element("p", t("qr.revision", { revision: hosting.revision }), "hosting-policy"),
    );
    const image = document.getElementById("hosting-qr");
    image.alt = t("qr.alt");
    image.hidden = false;
    image.onerror = () => {
      image.hidden = true;
      showError(t("error.qr"));
    };
    try {
      const url = new URL(hosting.qr_url, document.baseURI);
      if (url.origin !== window.location.origin) throw new Error("Invalid QR origin");
      url.searchParams.set("revision", String(hosting.revision));
      image.src = url.href;
    } catch {
      image.hidden = true;
      showError(t("error.qr"));
    }
    const keys = document.getElementById("key-details");
    keys.hidden = !hosting.public_keys;
    if (hosting.public_keys) {
      document.getElementById("key-details-title").textContent = t("qr.keys");
      document.getElementById("public-keys").textContent = JSON.stringify(hosting.public_keys, null, 2);
    }
  }

  function render(next) {
    if (!["api", "witness"].includes(next.role) || !next.configuration || typeof next.csrf_token !== "string") {
      throw new Error(t("error.load"));
    }
    state = next;
    fields.replaceChildren();
    const role = state.role;
    const title = t(`page.${role}.title`);
    document.title = `elo · ${title}`;
    document.getElementById("page-title").textContent = title;
    document.getElementById("page-intro").textContent = t(`page.${role}.intro`);
    document.getElementById("settings-title").textContent = t("settings.title");
    document.getElementById("save-hint").textContent = t(`settings.${role}.hint`);
    document.getElementById("content").classList.toggle("witness", role === "witness");
    const related = document.getElementById("related-panel");
    related.hidden = true;
    if (state.related_admin_url) {
      try {
        const url = new URL(state.related_admin_url);
        if (url.protocol === "https:" && !url.username && !url.password) {
          related.href = url.href;
          related.textContent = t(`page.related.${role === "api" ? "witness" : "api"}`);
          related.rel = "noreferrer noopener";
          related.hidden = false;
        }
      } catch { /* An unavailable related panel does not prevent local administration. */ }
    }
    if (role === "api") renderApi(state.configuration);
    else renderWitness(state.configuration);
    renderHosting(state.configuration, role === "api" ? state.hosting : null);
    document.getElementById("content").hidden = false;
    app.setAttribute("aria-busy", "false");
    dirty = false;
    setBusy(false);
  }

  function identities(name) {
    const values = [...new Set((form.elements.namedItem(name)?.value || "").split(/[\s,]+/).filter(Boolean).map(value => value.toLowerCase()))];
    if (values.some(value => !/^[a-fA-F0-9]{64}$/.test(value))) throw new Error(t("error.identities"));
    return values;
  }

  function payload() {
    const value = name => (form.elements.namedItem(name)?.value || "").trim();
    if (state.role === "api") {
      const retentions = readLifetimes();
      if (!retentions.length) throw new Error(t("error.retention"));
      const mode = value("creation_mode");
      const creators = mode === "allowlist" ? identities("allowed_creators") : [];
      if (mode === "allowlist" && !creators.length) throw new Error(t("error.allowlist"));
      const defaultLifetime = value("default_message_lifetime");
      return {
        name: value("name"), message_lifetimes: retentions,
        default_message_lifetime: defaultLifetime === "no_expiry" ? defaultLifetime : Number(defaultLifetime),
        creation_mode: mode, allowed_creators: creators,
        managed_provider: mode === "allowlist" && state.configuration.storage_available ? value("managed_provider") || null : null,
      };
    }
    const provider = value("provider") || null;
    const result = { provider, allowed_owners: provider ? identities("allowed_owners") : [] };
    const names = provider === "mega" ? ["folder_link", "write_auth"]
      : provider === "s3" ? ["s3_endpoint", "s3_region", "s3_bucket", "s3_access_key", "s3_secret_key"] : [];
    for (const name of names) result[name] = value(name);
    return result;
  }

  function setBusy(value) {
    busy = value;
    save.disabled = value || saveUnconfirmed;
    save.textContent = t(value ? "settings.saving" : "settings.save");
    fields.inert = value || saveUnconfirmed;
    form.setAttribute("aria-busy", String(value));
  }

  async function watchJob(id) {
    if (typeof id !== "string" || !/^[a-zA-Z0-9_-]{1,128}$/.test(id)) throw new Error(t("error.unknown.save"));
    setBusy(true);
    status.textContent = t("status.pending");
    const deadline = Date.now() + 10 * 60 * 1000;
    while (Date.now() < deadline) {
      const job = await request(`./api/jobs/${encodeURIComponent(id)}`);
      if (job.status === "failed") {
        saveUnconfirmed = false;
        throw new Error(typeof job.error === "string" ? job.error : t("error.save"));
      }
      if (job.status === "succeeded") {
        const next = await request("./api/state");
        saveUnconfirmed = false;
        showError("");
        render(next);
        status.textContent = t("status.saved");
        return;
      }
      if (job.status !== "pending") throw new Error(t("error.unknown.save"));
      await new Promise(resolve => setTimeout(resolve, 1500));
    }
    throw new Error(t("error.pending"));
  }

  function markDirty() {
    dirty = true;
    status.textContent = "";
    if (state?.role === "api") document.getElementById("qr-hint").textContent = t("qr.unsaved");
  }
  form.addEventListener("input", markDirty);
  form.addEventListener("change", markDirty);
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (busy || saveUnconfirmed || !form.reportValidity()) return;
    let configuration;
    try { configuration = payload(); }
    catch (failure) { showError(failure.message); return; }
    showError("");
    setBusy(true);
    status.textContent = t("status.pending");
    let submitted = false;
    try {
      const job = await request("./api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": state.csrf_token },
        body: JSON.stringify(configuration),
      });
      submitted = true;
      saveUnconfirmed = true;
      // Secrets are no longer needed in the browser after the server accepts the job.
      for (const input of fields.querySelectorAll('input[type="password"]')) input.value = "";
      await watchJob(job.id);
    } catch (failure) {
      if (!submitted && !failure.responseReceived) saveUnconfirmed = true;
      showError(saveUnconfirmed ? t("error.unknown.save") : failure.message || t("error.save"));
      status.textContent = "";
    } finally { setBusy(false); }
  });

  document.getElementById("copy-link").addEventListener("click", async () => {
    const link = document.getElementById("configuration-link");
    try {
      await navigator.clipboard.writeText(link.value);
      status.textContent = t("status.copied");
    } catch {
      link.focus();
      link.select();
      status.textContent = t("status.copy.select");
    }
  });

  window.addEventListener("beforeunload", event => {
    if (dirty && !busy && !saveUnconfirmed) {
      event.preventDefault();
      event.returnValue = "";
    }
  });

  async function start() {
    try {
      const response = await fetch(new URL("./en.json", document.baseURI), { credentials: "same-origin", cache: "no-cache", redirect: "error" });
      if (!response.ok) throw new Error("Could not load the administration panel. Reload this page to try again.");
      catalog = await response.json();
      status.textContent = t("status.loading");
      const next = await request("./api/state");
      render(next);
      status.textContent = "";
      if (next.pending?.status === "pending") {
        saveUnconfirmed = true;
        await watchJob(next.pending.id);
      } else if (next.pending?.status === "failed") {
        showError(typeof next.pending.error === "string" ? next.pending.error : t("error.save"));
      }
    } catch (failure) {
      showError(saveUnconfirmed ? t("error.unknown.save") : failure.message || t("error.load"));
      status.textContent = "";
      app.setAttribute("aria-busy", "false");
      setBusy(false);
    }
  }

  start();
})();
