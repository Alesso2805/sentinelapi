"use strict";

// The attack console (ADR-0010). No framework and no third-party code: a security demo
// should not ask its visitors to trust more than it has to.

const summary = document.getElementById("summary");
const table = document.getElementById("steps");
const rows = table.querySelector("tbody");
const events = document.getElementById("events");
const streamState = document.getElementById("stream-state");
const buttons = [...document.querySelectorAll("button[data-scenario]")];

const OUTCOMES = {
  allowed: "Allowed",
  warned: "Allowed, reported",
  rejected: "Rejected",
  blocked: "Blocked by SentinelAPI",
};

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text;
  return td;
}

function span(className, text) {
  const element = document.createElement("span");
  element.className = className;
  element.textContent = text;
  return element;
}

function renderStep(step) {
  const verdict = document.createElement("td");
  verdict.append(span(`badge badge-${step.outcome}`, OUTCOMES[step.outcome]));
  if (step.level) {
    verdict.append(` · ${step.level.toUpperCase()}`);
  }
  if (step.detail) {
    verdict.append(span("detail", step.detail));
  }
  const row = document.createElement("tr");
  row.append(cell(String(step.number)), cell(step.source), cell(step.request), cell(String(step.status)), verdict);
  rows.append(row);
}

async function run(button) {
  for (const each of buttons) each.disabled = true;
  summary.textContent = "Running…";
  rows.replaceChildren();
  table.hidden = true;
  try {
    const response = await fetch(`/demo/scenarios/${button.dataset.scenario}`, {
      method: "POST",
      headers: { Accept: "application/json" },
    });
    const result = await response.json();
    if (!response.ok) {
      summary.textContent = result.detail ?? `The server answered ${response.status}.`;
      return;
    }
    for (const step of result.steps) renderStep(step);
    table.hidden = false;
    summary.textContent = `${result.title}: ${result.summary}`;
  } catch {
    summary.textContent = "The server could not be reached. Try again in a moment.";
  } finally {
    for (const each of buttons) each.disabled = false;
    button.focus();
  }
}

for (const button of buttons) {
  button.addEventListener("click", () => run(button));
}

const stream = new EventSource("/demo/events");
stream.onopen = () => {
  streamState.textContent = "Live: new events appear at the top.";
};
stream.onerror = () => {
  streamState.textContent = "Reconnecting…";
};
stream.onmessage = (message) => {
  const event = JSON.parse(message.data);
  const item = document.createElement("li");
  item.className = `event event-${event.threat_level}`;
  const title = document.createElement("strong");
  title.textContent = `${event.threat_level.toUpperCase()} · ${event.threat_type.replaceAll("_", " ")}`;
  item.append(title, ` on ${event.path}: ${event.detail}`);
  events.prepend(item);
  while (events.children.length > 200) events.lastElementChild.remove();
};
