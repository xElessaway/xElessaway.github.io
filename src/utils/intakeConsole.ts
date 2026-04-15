import { normalizeAndHashAnswer } from "./ctfAnswer";

export type JsonValue = string | number | boolean | JsonValue[] | { [key: string]: JsonValue };

export type IntakePrimitiveFieldType = "text" | "textarea" | "date" | "number" | "select" | "checkbox";
export type IntakeFieldType =
  | IntakePrimitiveFieldType
  | "stringList"
  | "objectList"
  | "markdownBody"
  | "specialRawAnswers";

export interface IntakeSelectOption {
  label: string;
  value: string;
}

interface IntakeSharedField {
  name: string;
  label: string;
  required?: boolean;
  description?: string;
  placeholder?: string;
  options?: IntakeSelectOption[];
  defaultValue?: JsonValue;
}

export interface IntakeItemField extends IntakeSharedField {
  type: IntakePrimitiveFieldType;
}

export interface IntakeField extends IntakeSharedField {
  type: IntakeFieldType;
  deriveFrom?: string;
  outputName?: string;
  itemLabel?: string;
  addLabel?: string;
  rows?: number;
  fields?: IntakeItemField[];
}

export interface IntakeFieldGroup {
  label: string;
  description?: string;
  fields: string[];
}

export interface IntakeTemplate {
  id: string;
  label: string;
  contentType: "blog" | "actors" | "ctfCollections" | "ctfChallenges";
  targetPathPattern: string;
  previewPathPattern: string;
  fieldGroups: IntakeFieldGroup[];
  fields: IntakeField[];
  defaultValues: Record<string, JsonValue>;
  frontmatterOrder: string[];
  bodyTemplate: string;
}

export interface IntakeBuildResult {
  markdown: string;
  targetPath: string;
  previewPath: string;
  outputValues: Record<string, unknown>;
  missingRequired: string[];
}

function cloneJsonValue<T>(value: T): T {
  if (value === undefined) {
    return value;
  }

  return JSON.parse(JSON.stringify(value)) as T;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isScalar(value: unknown): value is string | number | boolean {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function hasOwnValue(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function normalizeTextValue(value: unknown, preserveWhitespace = false): string {
  const text = typeof value === "string" ? value : String(value ?? "");
  const normalized = text.replace(/\r\n/g, "\n");
  return preserveWhitespace ? normalized.trim() : normalized.trim();
}

function normalizeLineList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .map((entry) => (typeof entry === "string" ? entry : String(entry ?? "")))
      .map((entry) => entry.trim())
      .filter(Boolean);
  }

  return String(value ?? "")
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeNumber(value: unknown): number | undefined {
  if (value === "" || value === undefined || value === null) {
    return undefined;
  }

  const number = Number(value);
  return Number.isFinite(number) ? number : undefined;
}

function isMeaningfulValue(value: unknown): boolean {
  if (value === undefined || value === null) {
    return false;
  }

  if (typeof value === "string") {
    return value.trim().length > 0;
  }

  if (Array.isArray(value)) {
    return value.length > 0;
  }

  if (isPlainObject(value)) {
    return Object.keys(value).length > 0;
  }

  return true;
}

function normalizeObjectRow(field: IntakeField, row: unknown): Record<string, unknown> {
  const normalized: Record<string, unknown> = {};
  const rowRecord = isPlainObject(row) ? row : {};

  for (const itemField of field.fields ?? []) {
    const rawValue = rowRecord[itemField.name];
    let value: unknown;

    switch (itemField.type) {
      case "checkbox":
        value = Boolean(rawValue);
        break;
      case "number":
        value = normalizeNumber(rawValue);
        break;
      case "textarea":
        value = normalizeTextValue(rawValue, true);
        break;
      case "text":
      case "date":
      case "select":
      default:
        value = normalizeTextValue(rawValue);
        break;
    }

    if (isMeaningfulValue(value) || value === false) {
      normalized[itemField.name] = value;
    }
  }

  return normalized;
}

function collectMissingRequiredFields(
  template: IntakeTemplate,
  normalizedValues: Record<string, unknown>
): string[] {
  const missing: string[] = [];

  for (const field of template.fields) {
    const value = normalizedValues[field.name];

    if (!field.required) {
      continue;
    }

    if (field.type === "objectList") {
      if (!Array.isArray(value) || value.length === 0) {
        missing.push(field.label);
        continue;
      }

      value.forEach((row, rowIndex) => {
        const rowRecord = isPlainObject(row) ? row : {};

        (field.fields ?? []).forEach((itemField) => {
          if (!itemField.required) {
            return;
          }

          if (!isMeaningfulValue(rowRecord[itemField.name]) && rowRecord[itemField.name] !== false) {
            missing.push(`${field.label} row ${rowIndex + 1}: ${itemField.label}`);
          }
        });
      });

      continue;
    }

    if (!isMeaningfulValue(value) && value !== false) {
      missing.push(field.label);
    }
  }

  return missing;
}

function yamlScalar(value: string | number | boolean): string {
  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  return String(value);
}

function yamlInline(value: unknown): string {
  if (Array.isArray(value) && value.length === 0) {
    return "[]";
  }

  if (isPlainObject(value) && Object.keys(value).length === 0) {
    return "{}";
  }

  if (isScalar(value)) {
    return yamlScalar(value);
  }

  return JSON.stringify(value);
}

function yamlPropertyLines(key: string, value: unknown, indent = 0): string[] {
  const spaces = "  ".repeat(indent);

  if (
    isScalar(value) ||
    (Array.isArray(value) && value.length === 0) ||
    (isPlainObject(value) && Object.keys(value).length === 0)
  ) {
    return [`${spaces}${key}: ${yamlInline(value)}`];
  }

  return [`${spaces}${key}:`, ...yamlNestedLines(value, indent + 1)];
}

function yamlNestedLines(value: unknown, indent = 0): string[] {
  const spaces = "  ".repeat(indent);

  if (Array.isArray(value)) {
    return value.flatMap((entry) => {
      if (
        isScalar(entry) ||
        (Array.isArray(entry) && entry.length === 0) ||
        (isPlainObject(entry) && Object.keys(entry).length === 0)
      ) {
        return [`${spaces}- ${yamlInline(entry)}`];
      }

      if (Array.isArray(entry)) {
        return [`${spaces}-`, ...yamlNestedLines(entry, indent + 1)];
      }

      return [`${spaces}-`, ...Object.entries(entry).flatMap(([key, nestedValue]) => yamlPropertyLines(key, nestedValue, indent + 1))];
    });
  }

  if (isPlainObject(value)) {
    return Object.entries(value).flatMap(([key, nestedValue]) => yamlPropertyLines(key, nestedValue, indent));
  }

  return [`${spaces}${yamlInline(value)}`];
}

function replaceTemplateTokens(templateText: string, values: Record<string, unknown>): string {
  return templateText.replace(/{{\s*([a-zA-Z0-9_.-]+)\s*}}/g, (_, token: string) => {
    const value = values[token];

    if (Array.isArray(value)) {
      return value.filter((entry) => isScalar(entry)).map((entry) => String(entry)).join("\n");
    }

    if (value === undefined || value === null) {
      return "";
    }

    if (typeof value === "boolean" || typeof value === "number") {
      return String(value);
    }

    return String(value);
  });
}

export function slugify(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
}

export function interpolatePattern(pattern: string, values: Record<string, unknown>): string {
  return pattern.replace(/{{\s*([a-zA-Z0-9_.-]+)\s*}}/g, (_, token: string) => {
    const value = values[token];
    return value === undefined || value === null ? "" : String(value);
  });
}

export function getFieldDefaultValue(template: IntakeTemplate, field: IntakeField): unknown {
  if (hasOwnValue(template.defaultValues, field.name)) {
    return cloneJsonValue(template.defaultValues[field.name]);
  }

  if (field.defaultValue !== undefined) {
    return cloneJsonValue(field.defaultValue);
  }

  switch (field.type) {
    case "checkbox":
      return false;
    case "stringList":
    case "objectList":
    case "specialRawAnswers":
      return [];
    case "number":
      return "";
    default:
      return "";
  }
}

export function createInitialValues(template: IntakeTemplate): Record<string, unknown> {
  return Object.fromEntries(template.fields.map((field) => [field.name, getFieldDefaultValue(template, field)]));
}

export async function buildGeneratedContent(
  template: IntakeTemplate,
  rawValues: Record<string, unknown>
): Promise<IntakeBuildResult> {
  const normalizedValues: Record<string, unknown> = {};
  const outputValues: Record<string, unknown> = {};
  let bodyValue = "";

  for (const field of template.fields) {
    const rawValue = rawValues[field.name];
    let normalizedValue: unknown;

    switch (field.type) {
      case "checkbox":
        normalizedValue = Boolean(rawValue);
        break;
      case "number":
        normalizedValue = normalizeNumber(rawValue);
        break;
      case "textarea":
        normalizedValue = normalizeTextValue(rawValue, true);
        break;
      case "markdownBody":
        normalizedValue = normalizeTextValue(rawValue, true);
        bodyValue = String(normalizedValue);
        break;
      case "stringList":
        normalizedValue = normalizeLineList(rawValue);
        break;
      case "objectList":
        normalizedValue = (Array.isArray(rawValue) ? rawValue : [])
          .map((row) => normalizeObjectRow(field, row))
          .filter((row) => Object.keys(row).length > 0);
        break;
      case "specialRawAnswers":
        normalizedValue = normalizeLineList(rawValue);
        break;
      case "text":
      case "date":
      case "select":
      default:
        normalizedValue = normalizeTextValue(rawValue);
        break;
    }

    normalizedValues[field.name] = normalizedValue;
  }

  const missingRequired = collectMissingRequiredFields(template, normalizedValues);

  for (const field of template.fields) {
    if (field.type === "markdownBody") {
      continue;
    }

    const outputKey = field.outputName ?? field.name;

    if (field.type === "specialRawAnswers") {
      const rawAnswers = Array.isArray(normalizedValues[field.name]) ? (normalizedValues[field.name] as string[]) : [];
      const hashes = await Promise.all(rawAnswers.map((answer) => normalizeAndHashAnswer(answer)));
      outputValues[outputKey] = [...new Set(hashes)];
      continue;
    }

    outputValues[outputKey] = normalizedValues[field.name];
  }

  const orderedKeys = [
    ...template.frontmatterOrder,
    ...template.fields
      .filter((field) => field.type !== "markdownBody")
      .map((field) => field.outputName ?? field.name)
      .filter((key) => !template.frontmatterOrder.includes(key))
  ];

  const frontmatterLines = ["---"];

  for (const key of orderedKeys) {
    const field = template.fields.find((candidate) => (candidate.outputName ?? candidate.name) === key);
    const value = outputValues[key];
    const includeEmptyCollection =
      field !== undefined &&
      (field.type === "stringList" || field.type === "objectList" || field.type === "specialRawAnswers");
    const includeEmptyBoolean = field?.type === "checkbox";

    if (
      value === undefined ||
      (typeof value === "string" && value.trim().length === 0 && !hasOwnValue(template.defaultValues, field?.name ?? "")) ||
      ((!includeEmptyCollection && Array.isArray(value) && value.length === 0) ||
        (!includeEmptyBoolean && value === false && !hasOwnValue(template.defaultValues, field?.name ?? "")))
    ) {
      if (!includeEmptyCollection && !(includeEmptyBoolean && value === false)) {
        continue;
      }
    }

    frontmatterLines.push(...yamlPropertyLines(key, value));
  }

  frontmatterLines.push("---");

  const templateValues = {
    ...normalizedValues,
    ...outputValues
  };
  const rawBodyTemplate = template.bodyTemplate.trim();
  const finalBody =
    rawBodyTemplate.length > 0
      ? replaceTemplateTokens(rawBodyTemplate, templateValues).trim()
      : bodyValue.trim();

  const markdown = [frontmatterLines.join("\n"), finalBody].filter(Boolean).join("\n\n");
  const interpolationValues = {
    ...templateValues,
    slug: normalizedValues.slug ?? outputValues.slug ?? ""
  };

  return {
    markdown,
    targetPath: interpolatePattern(template.targetPathPattern, interpolationValues),
    previewPath: interpolatePattern(template.previewPathPattern, interpolationValues),
    outputValues,
    missingRequired
  };
}
