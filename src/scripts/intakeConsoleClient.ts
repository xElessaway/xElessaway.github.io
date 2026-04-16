import { buildGeneratedContent, createInitialValues, slugify, type IntakeField, type IntakeTemplate } from "../utils/intakeConsole";

type StatusTone = "neutral" | "pending" | "success" | "error";

const templatesElement = document.querySelector("#intake-console-templates");
const initialStateElement = document.querySelector("#intake-console-initial-state");
const consoleRoot = document.querySelector("[data-intake-console]");

const templates = JSON.parse(templatesElement?.textContent ?? "[]") as IntakeTemplate[];
const initialState = JSON.parse(initialStateElement?.textContent ?? "{}") as Record<string, Record<string, unknown>>;
const templateMap = new Map<string, IntakeTemplate>(templates.map((template) => [template.id, template]));
const panelMap = new Map<string, HTMLElement>();
const tabButtons = [...document.querySelectorAll<HTMLElement>("[data-intake-tab]")];
const renderTimers = new Map<string, number>();
const baseUrl = consoleRoot?.getAttribute("data-base-url") ?? "/";
const submitDefaults = {
  owner: consoleRoot?.getAttribute("data-submit-owner-default") ?? "xElessaway",
  repo: consoleRoot?.getAttribute("data-submit-repo-default") ?? "xElessaway.github.io",
  branch: consoleRoot?.getAttribute("data-submit-branch-default") ?? "main"
};

document.querySelectorAll<HTMLElement>("[data-intake-panel]").forEach((panel) => {
  const panelId = panel.getAttribute("data-intake-panel");

  if (panelId) {
    panelMap.set(panelId, panel);
  }
});

const escapeSelector = (value: string) => window.CSS?.escape?.(value) ?? value.replace(/[^a-zA-Z0-9_-]/g, "\\$&");

const setActiveTemplate = (templateId: string) => {
  tabButtons.forEach((button) => {
    const isActive = button.getAttribute("data-intake-tab") === templateId;
    button.classList.toggle("is-active", isActive);
    button.setAttribute("aria-selected", String(isActive));
  });

  panelMap.forEach((panel, panelId) => {
    const active = panelId === templateId;
    panel.hidden = !active;
    panel.classList.toggle("is-active", active);
  });
};

const setStatusTone = (element: HTMLElement, message: string, tone: StatusTone) => {
  element.textContent = message;
  element.classList.toggle("is-pending", tone === "pending");
  element.classList.toggle("is-success", tone === "success");
  element.classList.toggle("is-error", tone === "error");
};

const createObjectRow = (field: IntakeField): HTMLElement => {
  const row = document.createElement("div");
  row.className = "intake-object-row";
  row.setAttribute("data-object-row", "");

  const rowGrid = document.createElement("div");
  rowGrid.className = "intake-object-row-grid";

  for (const itemField of field.fields ?? []) {
    const label = document.createElement("label");
    label.className = "intake-field";

    const title = document.createElement("span");
    title.className = "intake-field-label";
    title.textContent = itemField.label;
    label.append(title);

    let control: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;

    if (itemField.type === "textarea") {
      const textarea = document.createElement("textarea");
      textarea.className = "filter-input intake-textarea";
      textarea.rows = 3;
      control = textarea;
    } else if (itemField.type === "select") {
      const select = document.createElement("select");
      select.className = "filter-input intake-select";

      for (const option of itemField.options ?? []) {
        const optionElement = document.createElement("option");
        optionElement.value = option.value;
        optionElement.textContent = option.label;
        select.append(optionElement);
      }

      control = select;
    } else {
      const input = document.createElement("input");
      input.type = itemField.type === "number" ? "number" : itemField.type;
      if (itemField.type !== "checkbox") {
        input.className = "filter-input intake-text-input";
      }
      control = input;
    }

    control.setAttribute("data-object-field", itemField.name);
    control.setAttribute("data-object-field-type", itemField.type);

    if ("placeholder" in control && itemField.placeholder) {
      control.placeholder = itemField.placeholder;
    }

    label.append(control);
    rowGrid.append(label);
  }

  const removeButton = document.createElement("button");
  removeButton.type = "button";
  removeButton.className = "button button-ghost intake-row-remove";
  removeButton.setAttribute("data-remove-row", "");
  removeButton.textContent = "Remove";

  row.append(rowGrid, removeButton);
  return row;
};

const syncObjectEmptyState = (fieldRoot: HTMLElement) => {
  const rows = fieldRoot.querySelectorAll("[data-object-row]");
  const emptyState = fieldRoot.querySelector("[data-object-empty]");

  if (emptyState instanceof HTMLElement) {
    emptyState.hidden = rows.length !== 0;
  }
};

const collectPanelValues = (panel: HTMLElement, template: IntakeTemplate): Record<string, unknown> => {
  const values: Record<string, unknown> = {};

  template.fields.forEach((field) => {
    const fieldRoot = panel.querySelector<HTMLElement>(`[data-intake-field="${escapeSelector(field.name)}"]`);

    if (!fieldRoot) {
      values[field.name] = "";
      return;
    }

    if (field.type === "checkbox" && fieldRoot instanceof HTMLInputElement) {
      values[field.name] = fieldRoot.checked;
      return;
    }

    if (field.type === "objectList") {
      const rows = [...fieldRoot.querySelectorAll<HTMLElement>("[data-object-row]")];
      values[field.name] = rows.map((row) => {
        const rowValues: Record<string, unknown> = {};

        row.querySelectorAll<HTMLElement>("[data-object-field]").forEach((control) => {
          const name = control.getAttribute("data-object-field");
          if (!name) {
            return;
          }

          if (control instanceof HTMLInputElement && control.type === "checkbox") {
            rowValues[name] = control.checked;
            return;
          }

          if (control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement || control instanceof HTMLSelectElement) {
            rowValues[name] = control.value;
          }
        });

        return rowValues;
      });
      return;
    }

    if (fieldRoot instanceof HTMLInputElement && fieldRoot.type === "checkbox") {
      values[field.name] = fieldRoot.checked;
      return;
    }

    if (fieldRoot instanceof HTMLInputElement || fieldRoot instanceof HTMLTextAreaElement || fieldRoot instanceof HTMLSelectElement) {
      values[field.name] = fieldRoot.value;
    }
  });

  return values;
};

const getPrimaryTitle = (template: IntakeTemplate, values: Record<string, unknown>): string => {
  const preferredKeys = ["title", "name", "slug"];

  for (const key of preferredKeys) {
    const value = values[key];

    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }

  return template.label;
};

const getDefaultCommitMessage = (template: IntakeTemplate, values: Record<string, unknown>): string => {
  const title = getPrimaryTitle(template, values);

  switch (template.id) {
    case "report-writeup":
      return `Publish report: ${title}`;
    case "threat-intel":
      return `Publish threat intel: ${title}`;
    case "ctf-collection":
      return `Publish CTF collection: ${title}`;
    case "ctf-challenge":
      return `Publish CTF challenge: ${title}`;
    default:
      return `Publish ${template.label.toLowerCase()}: ${title}`;
  }
};

const syncCommitMessage = (panel: HTMLElement, template: IntakeTemplate, values: Record<string, unknown>) => {
  const input = panel.querySelector("[data-submit-message]");

  if (!(input instanceof HTMLInputElement)) {
    return;
  }

  if (!input.dataset.manual) {
    input.dataset.manual = "false";
  }

  if (input.dataset.manual !== "true" || !input.value.trim()) {
    input.value = getDefaultCommitMessage(template, values);
  }
};

const setActionState = (panel: HTMLElement, disabled: boolean) => {
  panel.dataset.intakeReady = disabled ? "false" : "true";

  panel.querySelectorAll<HTMLButtonElement>("[data-copy-markdown], [data-copy-path], [data-download-markdown], [data-submit-entry]").forEach((button) => {
    const isPending = button.dataset.pending === "true";
    button.disabled = disabled || isPending;
  });

  const previewLink = panel.querySelector("[data-preview-link]");
  if (previewLink instanceof HTMLAnchorElement) {
    previewLink.classList.toggle("is-disabled", disabled);
    previewLink.tabIndex = disabled ? -1 : 0;
    previewLink.setAttribute("aria-disabled", String(disabled));
  }
};

const setSubmitPendingState = (panel: HTMLElement, pending: boolean) => {
  const button = panel.querySelector("[data-submit-entry]");

  if (!(button instanceof HTMLButtonElement)) {
    return;
  }

  button.dataset.pending = pending ? "true" : "false";
  button.disabled = pending || panel.dataset.intakeReady !== "true";
  button.textContent = pending ? "Submitting..." : "Submit";
};

const encodeUtf8ToBase64 = (value: string): string => {
  const bytes = new TextEncoder().encode(value);
  let binary = "";

  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });

  return window.btoa(binary);
};

const encodeGitHubPath = (value: string): string => value.split("/").map((segment) => encodeURIComponent(segment)).join("/");

const readGitHubError = async (response: Response): Promise<string> => {
  try {
    const payload = await response.json();

    if (typeof payload?.message === "string" && payload.message.trim()) {
      return payload.message.trim();
    }
  } catch {
    return response.statusText || "GitHub request failed.";
  }

  return response.statusText || "GitHub request failed.";
};

const getFileSha = async (owner: string, repo: string, branch: string, path: string, token: string): Promise<string | undefined> => {
  const endpoint = new URL(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodeGitHubPath(path)}`);
  endpoint.searchParams.set("ref", branch);

  const response = await fetch(endpoint, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`
    }
  });

  if (response.status === 404) {
    return undefined;
  }

  if (!response.ok) {
    throw new Error(await readGitHubError(response));
  }

  const payload = (await response.json()) as { sha?: string };
  return payload.sha;
};

const publishMarkdownFile = async ({
  owner,
  repo,
  branch,
  path,
  content,
  message,
  token
}: {
  owner: string;
  repo: string;
  branch: string;
  path: string;
  content: string;
  message: string;
  token: string;
}) => {
  const sha = await getFileSha(owner, repo, branch, path, token);
  const endpoint = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodeGitHubPath(path)}`;
  const response = await fetch(endpoint, {
    method: "PUT",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      message,
      content: encodeUtf8ToBase64(content),
      branch,
      ...(sha ? { sha } : {})
    })
  });

  if (!response.ok) {
    throw new Error(await readGitHubError(response));
  }

  return (await response.json()) as { commit?: { html_url?: string } };
};

const renderPanel = async (panel: HTMLElement, template: IntakeTemplate) => {
  const values = collectPanelValues(panel, template);
  const output = panel.querySelector("[data-intake-output]");
  const targetPath = panel.querySelector("[data-intake-target-path]");
  const previewUrl = panel.querySelector("[data-intake-preview-url]");
  const previewLink = panel.querySelector("[data-preview-link]");
  const status = panel.querySelector("[data-intake-status]");
  const submitStatus = panel.querySelector("[data-submit-status]");

  if (
    !(output instanceof HTMLTextAreaElement) ||
    !(targetPath instanceof HTMLInputElement) ||
    !(previewUrl instanceof HTMLInputElement) ||
    !(previewLink instanceof HTMLAnchorElement) ||
    !(status instanceof HTMLElement) ||
    !(submitStatus instanceof HTMLElement)
  ) {
    return;
  }

  const result = await buildGeneratedContent(template, values);
  const resolvedPreview = new URL(result.previewPath.replace(/^\//, ""), window.location.origin + baseUrl).toString();

  syncCommitMessage(panel, template, values);

  output.value = result.markdown;
  targetPath.value = result.targetPath;
  previewUrl.value = resolvedPreview;
  previewLink.href = result.previewPath || "#";

  if (result.missingRequired.length > 0) {
    setStatusTone(status, `Missing required fields: ${result.missingRequired.join(", ")}`, "error");
    setStatusTone(submitStatus, "Complete the required fields before submitting to xElessaway.github.io.", "neutral");
    setActionState(panel, true);
  } else {
    setStatusTone(status, "Markdown ready. Copy, download, or submit it directly to GitHub.", "success");
    setStatusTone(submitStatus, "Submit commits the source markdown file to xElessaway.github.io. GitHub Actions then rebuild the public site.", "neutral");
    setActionState(panel, false);
  }
};

const scheduleRender = (panel: HTMLElement, template: IntakeTemplate) => {
  const currentTimer = renderTimers.get(template.id);
  if (currentTimer) {
    window.clearTimeout(currentTimer);
  }

  const nextTimer = window.setTimeout(() => {
    void renderPanel(panel, template);
  }, 120);

  renderTimers.set(template.id, nextTimer);
};

const applyDerivedFieldValues = (panel: HTMLElement, template: IntakeTemplate) => {
  template.fields
    .filter((field) => field.deriveFrom)
    .forEach((field) => {
      const target = panel.querySelector(`[data-intake-field="${escapeSelector(field.name)}"]`);
      const source = panel.querySelector(`[data-intake-field="${escapeSelector(field.deriveFrom ?? "")}"]`);

      if (!(target instanceof HTMLInputElement) || !(source instanceof HTMLInputElement || source instanceof HTMLTextAreaElement)) {
        return;
      }

      const nextSlug = slugify(source.value);
      if (target.dataset.manual !== "true" || !target.value.trim()) {
        target.value = nextSlug;
      }
    });
};

const syncDerivedFields = (panel: HTMLElement, template: IntakeTemplate) => {
  template.fields
    .filter((field) => field.deriveFrom)
    .forEach((field) => {
      const target = panel.querySelector(`[data-intake-field="${escapeSelector(field.name)}"]`);
      const source = panel.querySelector(`[data-intake-field="${escapeSelector(field.deriveFrom ?? "")}"]`);

      if (!(target instanceof HTMLInputElement) || !(source instanceof HTMLInputElement || source instanceof HTMLTextAreaElement)) {
        return;
      }

      if (!target.dataset.manual) {
        target.dataset.manual = "false";
      }

      source.addEventListener("input", () => {
        applyDerivedFieldValues(panel, template);
        scheduleRender(panel, template);
      });

      target.addEventListener("input", () => {
        const derivedValue = slugify(source.value);
        target.dataset.manual = target.value.trim() && target.value.trim() !== derivedValue ? "true" : "false";
        scheduleRender(panel, template);
      });

      applyDerivedFieldValues(panel, template);
    });
};

const wireObjectLists = (panel: HTMLElement, template: IntakeTemplate) => {
  panel.querySelectorAll<HTMLButtonElement>("[data-add-row]").forEach((button) => {
    const fieldName = button.getAttribute("data-add-row");
    const field = template.fields.find((entry) => entry.name === fieldName);
    const fieldRoot = fieldName ? panel.querySelector<HTMLElement>(`[data-intake-field="${escapeSelector(fieldName)}"]`) : null;
    const rowContainer = fieldRoot?.querySelector("[data-object-list-rows]");

    if (!field || !(rowContainer instanceof HTMLElement) || !(fieldRoot instanceof HTMLElement)) {
      return;
    }

    button.addEventListener("click", () => {
      rowContainer.append(createObjectRow(field));
      syncObjectEmptyState(fieldRoot);
      scheduleRender(panel, template);
    });
  });

  panel.addEventListener("click", (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement) || !target.matches("[data-remove-row]")) {
      return;
    }

    const row = target.closest("[data-object-row]");
    const fieldRoot = target.closest("[data-intake-field]");

    row?.remove();

    if (fieldRoot instanceof HTMLElement) {
      syncObjectEmptyState(fieldRoot);
    }

    scheduleRender(panel, template);
  });

  panel.querySelectorAll<HTMLElement>("[data-intake-field][data-field-type='objectList']").forEach((fieldRoot) => {
    syncObjectEmptyState(fieldRoot);
  });
};

const resetPanel = (panel: HTMLElement, template: IntakeTemplate) => {
  const defaults = initialState[template.id] ?? createInitialValues(template);

  template.fields.forEach((field) => {
    const fieldRoot = panel.querySelector<HTMLElement>(`[data-intake-field="${escapeSelector(field.name)}"]`);

    if (!fieldRoot) {
      return;
    }

    if (field.type === "objectList") {
      const rowsRoot = fieldRoot.querySelector("[data-object-list-rows]");

      if (!(rowsRoot instanceof HTMLElement)) {
        return;
      }

      rowsRoot.innerHTML = "";
      const rows = Array.isArray(defaults[field.name]) ? (defaults[field.name] as Record<string, unknown>[]) : [];

      rows.forEach((rowData) => {
        const row = createObjectRow(field);
        row.querySelectorAll<HTMLElement>("[data-object-field]").forEach((control) => {
          const name = control.getAttribute("data-object-field");
          if (!name) {
            return;
          }

          const nextValue = rowData?.[name];

          if (control instanceof HTMLInputElement && control.type === "checkbox") {
            control.checked = Boolean(nextValue);
          } else if (control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement || control instanceof HTMLSelectElement) {
            control.value = typeof nextValue === "string" || typeof nextValue === "number" ? String(nextValue) : "";
          }
        });
        rowsRoot.append(row);
      });

      syncObjectEmptyState(fieldRoot);
      return;
    }

    if (fieldRoot instanceof HTMLInputElement && fieldRoot.type === "checkbox") {
      fieldRoot.checked = Boolean(defaults[field.name]);
      return;
    }

    if (fieldRoot instanceof HTMLInputElement || fieldRoot instanceof HTMLTextAreaElement || fieldRoot instanceof HTMLSelectElement) {
      const nextValue = defaults[field.name];
      fieldRoot.value =
        Array.isArray(nextValue) ? nextValue.join("\n") : typeof nextValue === "string" || typeof nextValue === "number" ? String(nextValue) : "";
    }
  });

  template.fields
    .filter((field) => field.deriveFrom)
    .forEach((field) => {
      const target = panel.querySelector(`[data-intake-field="${escapeSelector(field.name)}"]`);

      if (target instanceof HTMLInputElement) {
        target.dataset.manual = "false";
      }
    });

  const commitMessageInput = panel.querySelector("[data-submit-message]");
  if (commitMessageInput instanceof HTMLInputElement) {
    commitMessageInput.dataset.manual = "false";
  }

  const submitTokenInput = panel.querySelector("[data-submit-token]");
  if (submitTokenInput instanceof HTMLInputElement) {
    submitTokenInput.value = "";
  }

  applyDerivedFieldValues(panel, template);
  scheduleRender(panel, template);
};

const wireOutputActions = (panel: HTMLElement, template: IntakeTemplate) => {
  const output = panel.querySelector("[data-intake-output]");
  const targetPath = panel.querySelector("[data-intake-target-path]");
  const copyMarkdown = panel.querySelector("[data-copy-markdown]");
  const copyPath = panel.querySelector("[data-copy-path]");
  const downloadButton = panel.querySelector("[data-download-markdown]");
  const clearButton = panel.querySelector("[data-clear-form]");
  const commitMessageInput = panel.querySelector("[data-submit-message]");

  if (!(output instanceof HTMLTextAreaElement) || !(targetPath instanceof HTMLInputElement)) {
    return;
  }

  if (commitMessageInput instanceof HTMLInputElement) {
    commitMessageInput.dataset.manual = "false";

    commitMessageInput.addEventListener("input", () => {
      const values = collectPanelValues(panel, template);
      const derivedValue = getDefaultCommitMessage(template, values);
      commitMessageInput.dataset.manual =
        commitMessageInput.value.trim() && commitMessageInput.value.trim() !== derivedValue ? "true" : "false";
    });
  }

  copyMarkdown?.addEventListener("click", async () => {
    await navigator.clipboard.writeText(output.value);
  });

  copyPath?.addEventListener("click", async () => {
    await navigator.clipboard.writeText(targetPath.value);
  });

  downloadButton?.addEventListener("click", () => {
    const fileName = targetPath.value.split("/").filter(Boolean).at(-1) ?? `${template.id}.md`;
    const blob = new Blob([output.value], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    URL.revokeObjectURL(url);
  });

  clearButton?.addEventListener("click", () => {
    resetPanel(panel, template);
  });
};

const wireSubmitAction = (panel: HTMLElement) => {
  const submitButton = panel.querySelector("[data-submit-entry]");
  const output = panel.querySelector("[data-intake-output]");
  const targetPath = panel.querySelector("[data-intake-target-path]");
  const submitStatus = panel.querySelector("[data-submit-status]");
  const messageInput = panel.querySelector("[data-submit-message]");
  const tokenInput = panel.querySelector("[data-submit-token]");

  if (
    !(submitButton instanceof HTMLButtonElement) ||
    !(output instanceof HTMLTextAreaElement) ||
    !(targetPath instanceof HTMLInputElement) ||
    !(submitStatus instanceof HTMLElement) ||
    !(messageInput instanceof HTMLInputElement) ||
    !(tokenInput instanceof HTMLInputElement)
  ) {
    return;
  }

  submitButton.addEventListener("click", async () => {
    if (panel.dataset.intakeReady !== "true") {
      setStatusTone(submitStatus, "Complete the required fields before submitting to xElessaway.github.io.", "error");
      return;
    }

    const owner = submitDefaults.owner.trim();
    const repo = submitDefaults.repo.trim();
    const branch = submitDefaults.branch.trim() || "main";
    const message = messageInput.value.trim();
    const token = tokenInput.value.trim();
    const path = targetPath.value.trim();
    const content = output.value;

    if (!owner || !repo || !message || !path) {
      setStatusTone(submitStatus, "Owner, repository, branch, commit message, and target path are required.", "error");
      return;
    }

    if (!token) {
      setStatusTone(submitStatus, "Paste a GitHub token before submitting.", "error");
      return;
    }

    setSubmitPendingState(panel, true);
    setStatusTone(submitStatus, "Submitting markdown to GitHub...", "pending");

    try {
      await publishMarkdownFile({
        owner,
        repo,
        branch,
        path,
        content,
        message,
        token
      });

      tokenInput.value = "";
      setStatusTone(
        submitStatus,
        `Submitted to ${owner}/${repo} on ${branch}. GitHub Actions will rebuild the public site next.`,
        "success"
      );
    } catch (error) {
      const messageText = error instanceof Error ? error.message : "GitHub rejected the publish request.";
      setStatusTone(submitStatus, `Submit failed: ${messageText}`, "error");
    } finally {
      setSubmitPendingState(panel, false);
    }
  });
};

panelMap.forEach((panel, templateId) => {
  const template = templateMap.get(templateId);

  if (!template) {
    return;
  }

  wireObjectLists(panel, template);
  syncDerivedFields(panel, template);

  panel.addEventListener("input", (event) => {
    const target = event.target;

    if (
      target instanceof HTMLInputElement ||
      target instanceof HTMLTextAreaElement ||
      target instanceof HTMLSelectElement
    ) {
      scheduleRender(panel, template);
    }
  });

  panel.addEventListener("change", (event) => {
    const target = event.target;

    if (
      target instanceof HTMLInputElement ||
      target instanceof HTMLTextAreaElement ||
      target instanceof HTMLSelectElement
    ) {
      scheduleRender(panel, template);
    }
  });

  wireOutputActions(panel, template);
  wireSubmitAction(panel);
  scheduleRender(panel, template);
});

tabButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const templateId = button.getAttribute("data-intake-tab");
    if (templateId) {
      setActiveTemplate(templateId);
    }
  });
});

const initialTemplate = Object.keys(initialState)[0] ?? templates[0]?.id ?? "";
if (initialTemplate) {
  setActiveTemplate(initialTemplate);
}
