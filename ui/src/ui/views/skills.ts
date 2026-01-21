import { html, nothing } from "lit";

import { clampText } from "../format";
import type { SkillStatusEntry, SkillStatusReport } from "../types";
import type { SkillMessageMap } from "../controllers/skills";

export type SkillsProps = {
  loading: boolean;
  report: SkillStatusReport | null;
  error: string | null;
  filter: string;
  statusFilter: string;
  sourceFilter: string;
  edits: Record<string, string>;
  busyKey: string | null;
  messages: SkillMessageMap;
  onFilterChange: (next: string) => void;
  onStatusFilterChange: (next: string) => void;
  onSourceFilterChange: (next: string) => void;
  onRefresh: () => void;
  onToggle: (skillKey: string, enabled: boolean) => void;
  onEdit: (skillKey: string, value: string) => void;
  onSaveKey: (skillKey: string) => void;
  onInstall: (skillKey: string, name: string, installId: string) => void;
};

type SkillSourceKind = "workspace" | "managed" | "bundled" | "other";

type SkillStatusKind = "enabled" | "disabled" | "blocked" | "ineligible";

function resolveSkillSourceKind(
  report: SkillStatusReport | null,
  skill: SkillStatusEntry,
): SkillSourceKind {
  const base = skill.baseDir || "";
  const workspace = report?.workspaceDir || "";
  const managed = report?.managedSkillsDir || "";
  const source = (skill.source || "").toLowerCase();

  // Guard against misconfigured/empty roots (e.g. workspaceDir="/") which would match everything.
  const isValidRoot = (p: string) => Boolean(p) && p !== "/";

  if (isValidRoot(workspace) && base.startsWith(workspace)) return "workspace";
  if (isValidRoot(managed) && base.startsWith(managed)) return "managed";

  // Bundled/built-in skills typically have a source string like "clawdbot-bundled".
  if (source.includes("bundled")) return "bundled";
  // Managed/ClawdHub-installed skills may include clawdhub in the source string.
  if (source.includes("clawdhub")) return "managed";

  return "other";
}

function resolveSkillStatusKind(skill: SkillStatusEntry): SkillStatusKind {
  if (skill.blockedByAllowlist) return "blocked";
  if (skill.disabled) return "disabled";
  if (!skill.eligible) return "ineligible";
  return "enabled";
}

export function renderSkills(props: SkillsProps) {
  const skills = props.report?.skills ?? [];
  const filter = props.filter.trim().toLowerCase();

  const filtered = skills
    .filter((skill) => {
      if (!filter) return true;
      return [skill.name, skill.description, skill.source]
        .join(" ")
        .toLowerCase()
        .includes(filter);
    })
    .filter((skill) => {
      const status = resolveSkillStatusKind(skill);
      if (props.statusFilter === "all") return true;
      return status === props.statusFilter;
    })
    .filter((skill) => {
      const source = resolveSkillSourceKind(props.report, skill);
      if (props.sourceFilter === "all") return true;
      return source === props.sourceFilter;
    });

  return html`
    <section class="card">
      <div class="row" style="justify-content: space-between;">
        <div>
          <div class="card-title">Skills</div>
          <div class="card-sub">Bundled, managed, and workspace skills.</div>
        </div>
        <button class="btn" ?disabled=${props.loading} @click=${props.onRefresh}>
          ${props.loading ? "Loading…" : "Refresh"}
        </button>
      </div>

      <div class="filters" style="margin-top: 14px;">
        <label class="field" style="flex: 1;">
          <span>Filter</span>
          <input
            .value=${props.filter}
            @input=${(e: Event) =>
              props.onFilterChange((e.target as HTMLInputElement).value)}
            placeholder="Search skills"
          />
        </label>

        <label class="field" style="min-width: 180px;">
          <span>Status</span>
          <select
            .value=${props.statusFilter}
            @change=${(e: Event) =>
              props.onStatusFilterChange((e.target as HTMLSelectElement).value)}
          >
            <option value="all">all</option>
            <option value="enabled">enabled</option>
            <option value="disabled">disabled</option>
            <option value="blocked">blocked</option>
            <option value="ineligible">needs setup</option>
          </select>
        </label>

        <label class="field" style="min-width: 200px;">
          <span>Source</span>
          <select
            .value=${props.sourceFilter}
            @change=${(e: Event) =>
              props.onSourceFilterChange((e.target as HTMLSelectElement).value)}
          >
            <option value="all">all</option>
            <option value="workspace">workspace</option>
            <option value="managed">clawdhub</option>
            <option value="bundled">built-in</option>
            <option value="other">other</option>
          </select>
        </label>

        <div class="muted">${filtered.length} shown</div>
      </div>

      ${props.error
        ? html`<div class="callout danger" style="margin-top: 12px;">${props.error}</div>`
        : nothing}

      ${filtered.length === 0
        ? html`<div class="muted" style="margin-top: 16px;">No skills found.</div>`
        : html`
            <div class="list" style="margin-top: 16px;">
              ${filtered.map((skill) => renderSkill(skill, props))}
            </div>
          `}
    </section>
  `;
}

function renderSkill(skill: SkillStatusEntry, props: SkillsProps) {
  const busy = props.busyKey === skill.skillKey;
  const apiKey = props.edits[skill.skillKey] ?? "";
  const message = props.messages[skill.skillKey] ?? null;
  const canInstall =
    skill.install.length > 0 && skill.missing.bins.length > 0;
  const missing = [
    ...skill.missing.bins.map((b) => `bin:${b}`),
    ...skill.missing.env.map((e) => `env:${e}`),
    ...skill.missing.config.map((c) => `config:${c}`),
    ...skill.missing.os.map((o) => `os:${o}`),
  ];
  const reasons: string[] = [];
  if (skill.disabled) reasons.push("disabled");
  if (skill.blockedByAllowlist) reasons.push("blocked by allowlist");
  return html`
    <div class="list-item">
      <div class="list-main">
        <div class="list-title">
          ${skill.emoji ? `${skill.emoji} ` : ""}${skill.name}
        </div>
        <div class="list-sub">${clampText(skill.description, 140)}</div>
        <div class="chip-row" style="margin-top: 6px;">
          <span class="chip">${skill.source}</span>
          <span class="chip ${skill.eligible ? "chip-ok" : "chip-warn"}">
            ${skill.eligible ? "eligible" : "blocked"}
          </span>
          ${skill.disabled ? html`<span class="chip chip-warn">disabled</span>` : nothing}
        </div>
        ${missing.length > 0
          ? html`
              <div class="muted" style="margin-top: 6px;">
                Missing: ${missing.join(", ")}
              </div>
            `
          : nothing}
        ${reasons.length > 0
          ? html`
              <div class="muted" style="margin-top: 6px;">
                Reason: ${reasons.join(", ")}
              </div>
            `
          : nothing}
      </div>
      <div class="list-meta">
        <div class="row" style="justify-content: flex-end; flex-wrap: wrap;">
          <button
            class="btn"
            ?disabled=${busy}
            @click=${() => props.onToggle(skill.skillKey, skill.disabled)}
          >
            ${skill.disabled ? "Enable" : "Disable"}
          </button>
          ${canInstall
            ? html`<button
                class="btn"
                ?disabled=${busy}
                @click=${() =>
                  props.onInstall(skill.skillKey, skill.name, skill.install[0].id)}
              >
                ${busy ? "Installing…" : skill.install[0].label}
              </button>`
            : nothing}
        </div>
        ${message
          ? html`<div
              class="muted"
              style="margin-top: 8px; color: ${
                message.kind === "error"
                  ? "var(--danger-color, #d14343)"
                  : "var(--success-color, #0a7f5a)"
              };"
            >
              ${message.message}
            </div>`
          : nothing}
        ${skill.primaryEnv
          ? html`
              <div class="field" style="margin-top: 10px;">
                <span>API key</span>
                <input
                  type="password"
                  .value=${apiKey}
                  @input=${(e: Event) =>
                    props.onEdit(skill.skillKey, (e.target as HTMLInputElement).value)}
                />
              </div>
              <button
                class="btn primary"
                style="margin-top: 8px;"
                ?disabled=${busy}
                @click=${() => props.onSaveKey(skill.skillKey)}
              >
                Save key
              </button>
            `
          : nothing}
      </div>
    </div>
  `;
}
