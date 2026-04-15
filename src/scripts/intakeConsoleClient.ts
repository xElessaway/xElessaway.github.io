import { buildGeneratedContent, createInitialValues, slugify, type IntakeField, type IntakeTemplate } from "../utils/intakeConsole";

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

const setActionState = (panel: HTMLElement, disabled: boolean) => {
  panel.querySelectorAll<HTMLButtonElement>("[data-copy-markdown], [data-copy-path], [data-download-markdown]").forEach((button) => {
    button.disabled = disabled;
  });

  const previewLink = panel.querySelector("[data-preview-link]");
  if (previewLink instanceof HTMLAnchorElement) {
    previewLink.classList.toggle("is-disabled", disabled);
    previewLink.tabIndex = disabled ? -1 : 0;
    previewLink.setAttribute("aria-disabled", String(disabled));
  }
};

const renderPanel = async (panel: HTMLElement, template: IntakeTemplate) => {
  const values = collectPanelValues(panel, template);
  const output = panel.querySelector("[data-intake-output]");
  const targetPath = panel.querySelector("[data-intake-target-path]");
  const previewUrl = panel.querySelector("[data-intake-preview-url]");
  const previewLink = panel.querySelector("[data-preview-link]");
  const status = panel.querySelector("[data-intake-status]");

  if (
    !(output instanceof HTMLTextAreaElement) ||
    !(targetPath instanceof HTMLInputElement) ||
    !(previewUrl instanceof HTMLInputElement) ||
    !(previewLink instanceof HTMLAnchorElement) ||
    !(status instanceof HTMLElement)
  ) {
    return;
  }

  const result = await buildGeneratedContent(template, values);
  const resolvedPreview = new URL(result.previewPath.replace(/^\//, ""), window.location.origin + baseUrl).toString();

  output.value = result.markdown;
  targetPath.value = result.targetPath;
  previewUrl.value = resolvedPreview;
  previewLink.href = result.previewPath || "#";

  if (result.missingRequired.length > 0) {
    status.textContent = `Missing required fields: ${result.missingRequired.join(", ")}`;
    setActionState(panel, true);
  } else {
    status.textContent = "Markdown ready. Copy or download the file.";
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

  if (!(output instanceof HTMLTextAreaElement) || !(targetPath instanceof HTMLInputElement)) {
    return;
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
