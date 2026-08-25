"use strict";

const STAGE_STATES = Object.freeze({
  pass: { icon: "✓", label: "Verified" },
  deny: { icon: "×", label: "Stopped" },
  effect: { icon: "✓", label: "Effect" },
  no_effect: { icon: "0", label: "No effect" },
  not_reached: { icon: "—", label: "Not reached" },
  reused: { icon: "↻", label: "Reused" },
  tampered: { icon: "!", label: "Tampered" },
});

const numberFormat = new Intl.NumberFormat("en-US");
const decimalFormat = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 2,
  minimumFractionDigits: 0,
});

function element(id) {
  const value = document.getElementById(id);
  if (value === null) {
    throw new Error(`Missing required demonstration element: ${id}`);
  }
  return value;
}

function setText(id, value) {
  element(id).textContent = String(value);
}

function finiteNumber(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`Invalid numeric evidence field: ${label}`);
  }
  return value;
}

function ratePercent(value, label = "rate") {
  const rate = finiteNumber(value, label);
  if (rate < 0 || rate > 1) {
    throw new Error(`Invalid source-scale evidence rate: ${label}`);
  }
  return `${decimalFormat.format(rate * 100)}%`;
}

function count(value, label) {
  const number = finiteNumber(value, label);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new Error(`Invalid count evidence field: ${label}`);
  }
  return numberFormat.format(number);
}

function createTextElement(tagName, className, text) {
  const node = document.createElement(tagName);
  if (className) {
    node.className = className;
  }
  node.textContent = String(text);
  return node;
}

function renderProject(evidence) {
  setText("project-question", evidence.project.question);
  setText("project-milestone", evidence.project.milestone);
  setText("project-status", evidence.project.overall_status);
  setText("project-mode", evidence.project.mode.replaceAll("-", " ").toUpperCase());
  setText("claim-boundary", evidence.project.claim_boundary);
  setText("hero-sessions", count(evidence.m3.sessions, "M3 sessions"));
  setText("hero-trials", count(evidence.m3.trial_records, "M3 trials"));
  setText("hero-events", count(evidence.m3.evidence_events, "M3 evidence events"));
  setText("hero-hash", evidence.m3.deterministic_outcome_sha256);
}

function renderPath(architecture, condition) {
  if (!Array.isArray(architecture) || architecture.length !== condition.path.length) {
    throw new Error("The architecture and recorded path lengths disagree.");
  }

  const stages = architecture.map((stage, index) => {
    const stateName = condition.path[index];
    const state = STAGE_STATES[stateName];
    if (state === undefined) {
      throw new Error(`Unknown transaction stage state: ${stateName}`);
    }

    const item = document.createElement("div");
    item.className = "path-stage";
    item.dataset.state = stateName;
    item.setAttribute("role", "listitem");
    item.setAttribute(
      "aria-label",
      `Stage ${index + 1}, ${stage.label}: ${state.label}. ${stage.responsibility}`,
    );
    item.append(
      createTextElement("span", "stage-index", String(index + 1).padStart(2, "0")),
      createTextElement("span", "stage-indicator", state.icon),
      createTextElement("strong", "", stage.label),
      createTextElement("small", "", state.label),
    );
    return item;
  });

  const path = element("path-grid");
  path.setAttribute("role", "list");
  path.setAttribute("aria-label", `${condition.label} recorded transaction stages`);
  path.replaceChildren(...stages);
}

function renderCondition(evidence, condition, selectedButton) {
  for (const button of element("condition-tabs").querySelectorAll("button")) {
    button.setAttribute("aria-selected", String(button === selectedButton));
    button.tabIndex = button === selectedButton ? 0 : -1;
  }

  const panel = element("condition-panel");
  panel.setAttribute("aria-labelledby", selectedButton.id);
  renderPath(evidence.architecture, condition);
  setText("condition-title", condition.label);
  setText("condition-disposition", condition.disposition);
  setText("condition-trials", count(condition.trials, "condition trials"));
  setText("condition-effects", count(condition.modeled_effects, "modeled effects"));
  setText("condition-applied", count(condition.device_applied, "device applications"));
  setText("condition-unknown", count(condition.unknown_effects, "unknown effects"));
  setText("condition-note", condition.evidence_note);
}

function moveTabFocus(buttons, currentIndex, key) {
  let nextIndex = currentIndex;
  if (key === "ArrowRight" || key === "ArrowDown") {
    nextIndex = (currentIndex + 1) % buttons.length;
  } else if (key === "ArrowLeft" || key === "ArrowUp") {
    nextIndex = (currentIndex - 1 + buttons.length) % buttons.length;
  } else if (key === "Home") {
    nextIndex = 0;
  } else if (key === "End") {
    nextIndex = buttons.length - 1;
  } else {
    return false;
  }
  buttons[nextIndex].focus();
  buttons[nextIndex].click();
  return true;
}

function renderConditions(evidence) {
  if (!Array.isArray(evidence.m3.conditions) || evidence.m3.conditions.length === 0) {
    throw new Error("No M3 conditions were supplied.");
  }

  const buttons = evidence.m3.conditions.map((condition, index) => {
    const button = createTextElement("button", "condition-tab", condition.label);
    button.type = "button";
    button.id = `condition-tab-${condition.condition_id}`;
    button.setAttribute("role", "tab");
    button.setAttribute("aria-controls", "condition-panel");
    button.setAttribute("aria-selected", "false");
    button.tabIndex = -1;
    button.addEventListener("click", () => renderCondition(evidence, condition, button));
    button.addEventListener("keydown", (event) => {
      if (moveTabFocus(buttons, index, event.key)) {
        event.preventDefault();
      }
    });
    return button;
  });

  element("condition-tabs").replaceChildren(...buttons);
  const defaultIndex = Math.max(
    0,
    evidence.m3.conditions.findIndex(
      (condition) => condition.condition_id === "nominal_permitted_execution",
    ),
  );
  renderCondition(evidence, evidence.m3.conditions[defaultIndex], buttons[defaultIndex]);
}

function renderMetrics(metrics) {
  const cards = metrics.map((metric) => {
    const card = document.createElement("article");
    card.className = "metric-card";

    const value = createTextElement(
      "strong",
      "metric-value",
      ratePercent(metric.estimate, `${metric.metric_id} estimate`),
    );
    const label = createTextElement("span", "metric-label", metric.label);
    const observed = createTextElement(
      "span",
      "metric-observed",
      `${count(metric.numerator, "metric numerator")}/${count(metric.denominator, "metric denominator")} observed`,
    );
    const interval = createTextElement(
      "span",
      "metric-interval",
      `95% Wilson interval ${ratePercent(
        metric.wilson_ci95.lower,
        `${metric.metric_id} interval lower bound`,
      )}–${ratePercent(
        metric.wilson_ci95.upper,
        `${metric.metric_id} interval upper bound`,
      )}`,
    );
    const interpretation = createTextElement("p", "", metric.interpretation);
    card.append(value, label, observed, interval, interpretation);
    return card;
  });
  element("metric-grid").replaceChildren(...cards);
}

function renderNominalState(m3) {
  const state = m3.nominal_state;
  setText("nominal-voltage", decimalFormat.format(finiteNumber(state.minimum_voltage_pu, "voltage")));
  setText(
    "nominal-loading",
    decimalFormat.format(finiteNumber(state.maximum_line_loading_pct, "line loading")),
  );
  setText(
    "nominal-load",
    decimalFormat.format(finiteNumber(state.priority_load_served_pct, "priority load")),
  );
  setText(
    "nominal-latency",
    decimalFormat.format(finiteNumber(state.host_latency_median_ms, "host latency")),
  );
  setText("m3-finding", m3.finding);
  setText("m3-limitation", m3.limitation);
}

function createProgressBar(className, label, metric, baseline) {
  const row = document.createElement("div");
  row.className = "bar-line";
  const progress = document.createElement("progress");
  progress.className = className;
  progress.max = 1;
  progress.value = finiteNumber(metric.estimate, `${baseline.baseline_id} ${label} estimate`);

  const numerator = count(metric.numerator, `${baseline.baseline_id} ${label} numerator`);
  const denominator = count(
    metric.denominator,
    `${baseline.baseline_id} ${label} denominator`,
  );
  const estimate = ratePercent(metric.estimate, `${baseline.baseline_id} ${label} estimate`);
  const lower = ratePercent(
    metric.wilson_ci95.lower,
    `${baseline.baseline_id} ${label} interval lower bound`,
  );
  const upper = ratePercent(
    metric.wilson_ci95.upper,
    `${baseline.baseline_id} ${label} interval upper bound`,
  );
  progress.setAttribute(
    "aria-label",
    `${baseline.baseline_id} (${baseline.display_id}), ${baseline.label}; ${label}: ${numerator}/${denominator}, ${estimate}; 95% Wilson interval ${lower}–${upper}`,
  );
  const visibleValue = createTextElement(
    "span",
    "bar-value",
    `${numerator}/${denominator} · ${estimate}`,
  );
  visibleValue.setAttribute("aria-hidden", "true");
  row.append(progress, visibleValue);
  return row;
}

function renderBaselines(m2) {
  const rows = m2.baselines.map((baseline) => {
    const row = document.createElement("div");
    row.className = "baseline-row";
    const name = document.createElement("div");
    name.className = "baseline-name";
    name.append(
      createTextElement("span", "", `${baseline.display_id} · ${baseline.label}`),
      createTextElement(
        "small",
        "",
        `${count(baseline.trials, "baseline trials")} total trials`,
      ),
    );
    const stack = document.createElement("div");
    stack.className = "bar-stack";
    stack.append(
      createProgressBar(
        "bar-unsafe",
        "Unsafe escape",
        baseline.metrics.unsafe_action_escape,
        baseline,
      ),
      createProgressBar(
        "bar-unauthorized",
        "Unauthorized execution",
        baseline.metrics.unauthorized_execution,
        baseline,
      ),
      createProgressBar(
        "bar-false-block",
        "False block",
        baseline.metrics.false_block,
        baseline,
      ),
      createProgressBar(
        "bar-mission",
        "Mission success",
        baseline.metrics.mission_success,
        baseline,
      ),
    );
    row.append(name, stack);
    return row;
  });
  element("baseline-chart").replaceChildren(...rows);
  setText("m2-finding", m2.finding);
  setText("m2-limitation", m2.limitation);
}

function renderProvenance(evidence) {
  const artifacts = evidence.generated_from.map((artifact) => {
    const item = document.createElement("div");
    item.className = "provenance-item";
    item.append(
      createTextElement("strong", "", artifact.path),
      createTextElement("code", "", artifact.sha256),
    );
    return item;
  });
  element("provenance-list").replaceChildren(...artifacts);
  setText("m2-experiment", evidence.m2.experiment_id);
  setText("m2-hash", evidence.m2.deterministic_outcome_sha256);
  setText("m2-commit", evidence.m2.evidence_commit);
  setText("m2-retention", evidence.m2.retention_commit);
  setText("m3-experiment", evidence.m3.experiment_id);
  setText("m3-reproduction", evidence.m3.reproduction_experiment_id);
  setText("m3-model", evidence.m3.model_digest);
  setText("m3-commit", evidence.m3.evidence_commit);
  setText("m3-retention", evidence.m3.retention_commit);

  const verification = evidence.m3.verification;
  setText(
    "m3-verification-status",
    `Primary internal checks ${verification.primary_internal_checks_passed ? "passed" : "not passed"}; reproduction internal checks ${verification.reproduction_internal_checks_passed ? "passed" : "not passed"}; recorded-commit binding ${verification.recorded_commit_bound ? "passed" : "not passed"}; current checkout binding ${verification.current_checkout_binding_status}.`,
  );
  setText("m3-verification-boundary", verification.boundary);
}

function renderNextGates(nextGates) {
  const items = nextGates.map((gate) => createTextElement("li", "", gate));
  element("next-gates").replaceChildren(...items);
}

function renderEvidence(evidence) {
  if (evidence.schema_version !== "public-demo-v2") {
    throw new Error("Unsupported public demonstration evidence schema.");
  }
  renderProject(evidence);
  renderConditions(evidence);
  renderMetrics(evidence.m3.metrics);
  renderNominalState(evidence.m3);
  renderBaselines(evidence.m2);
  renderProvenance(evidence);
  renderNextGates(evidence.next_gates);
}

function renderFatalError(error) {
  for (const section of document.querySelectorAll(
    ".transaction-section, .evidence-section, .provenance-section, .next-section",
  )) {
    section.hidden = true;
  }
  const actions = document.querySelector(".hero-actions");
  if (actions !== null) {
    actions.hidden = true;
  }
  const navigation = document.querySelector("nav");
  if (navigation !== null) {
    navigation.hidden = true;
  }
  setText("project-question", "The packaged evidence summary is unavailable.");
  setText("project-milestone", "Evidence unavailable");
  setText("project-status", "No retained result is being displayed.");
  setText("project-mode", "EVIDENCE UNAVAILABLE");
  setText("hero-note", "Evidence unavailable; this page issues no control commands.");
  setText(
    "claim-boundary",
    "The evidence package could not be validated and rendered, so no recorded result is displayed.",
  );
  setText("hero-sessions", "—");
  setText("hero-trials", "—");
  setText("hero-events", "—");
  setText("hero-hash", "Unavailable");

  const panel = document.createElement("div");
  panel.className = "error-panel";
  panel.setAttribute("role", "alert");
  panel.append(
    createTextElement("strong", "", "The retained evidence could not be rendered."),
    createTextElement(
      "p",
      "",
      error instanceof Error ? error.message : "An unknown rendering error occurred.",
    ),
  );
  element("main-content").prepend(panel);
}

const REQUEST_TIMEOUT_MS = 5000;

async function fetchJson(path, timeoutMs = REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`${path} returned HTTP ${response.status}.`);
    }
    return await response.json();
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error(`${path} timed out after ${timeoutMs} ms.`);
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

async function fetchJsonWithRetry(path, attempts = 3) {
  let lastError = new Error(`No request was attempted for ${path}.`);
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await fetchJson(path);
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (attempt < attempts) {
        await new Promise((resolve) => window.setTimeout(resolve, attempt * 250));
      }
    }
  }
  throw lastError;
}

async function updateHealth() {
  const status = element("live-status");
  try {
    const health = await fetchJson("/health");
    if (health.status !== "ok" || health.mode !== "synthetic-local") {
      throw new Error("Unexpected demo service health response.");
    }
    status.classList.add("is-live");
    status.classList.remove("is-error");
    setText("live-status-copy", "Demo service reachable");
  } catch (_error) {
    status.classList.add("is-error");
    status.classList.remove("is-live");
    setText("live-status-copy", "Demo service unavailable");
  }
}

async function start() {
  void updateHealth();
  try {
    renderEvidence(await fetchJsonWithRetry("/v1/demo/evidence"));
  } catch (error) {
    renderFatalError(error);
  }
}

void start();
