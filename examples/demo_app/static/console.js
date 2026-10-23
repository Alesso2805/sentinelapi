"use strict";

// The attack console (ADR-0010). No framework and no third-party code: a security demo
// should not ask its visitors to trust more than it has to.

const STRINGS = {
  en: {
    title: "SentinelAPI · attack console",
    skip: "Skip to the attacks",
    language: "Language",
    heading: "Launch an attack and watch it get caught",
    lede:
      "Each button runs one attack on the server, against SentinelAPI's real detectors, from simulated " +
      "addresses. Every request it makes and the verdict it gets appear below, with what SentinelAPI " +
      "reported to its audit trail.",
    attacks: "Attacks",
    "burst.title": "Burst",
    "burst.text": "Seventy requests in a moment from one address, against a limit of 60 per minute.",
    "burst.run": "Run the burst",
    "stuffing.title": "Credential stuffing",
    "stuffing.text":
      "One account, one wrong password from each of 20 addresses, so no address fails twice. " +
      "Then its owner signs in with the right password.",
    "stuffing.run": "Run credential stuffing",
    "replay.title": "Token replay",
    "replay.text": "The owner redeems a single-use refresh token; then a stolen copy is replayed from another address.",
    "replay.run": "Run the replay",
    result: "What happened",
    idle: "Run an attack to see each of its requests and their verdicts.",
    running: "Running…",
    unreachable: "The server could not be reached. Try again in a moment.",
    answered: (status) => `The server answered ${status}.`,
    caption: "The requests of the last attack and SentinelAPI's verdict on each",
    "column.from": "From",
    "column.request": "Request",
    "column.answer": "Answer",
    "column.verdict": "Verdict",
    audit: "Audit trail, live",
    "audit.hint": "What SentinelAPI reported for your runs, as it happened. Only you see these.",
    connecting: "Connecting…",
    live: "Live: new events appear at the top.",
    reconnecting: "Reconnecting…",
    "footer.open": "SentinelAPI is open source:",
    "footer.source": "source and documentation",
    "footer.addresses":
      "The addresses above come from the ranges reserved for documentation (RFC 5737). " +
      "Real visitors' addresses are kept only as keyed hashes.",
    outcomes: {
      allowed: "Allowed",
      warned: "Allowed, reported",
      rejected: "Rejected",
      blocked: "Blocked by SentinelAPI",
    },
    threats: {
      rate_limit_exceeded: "rate limit exceeded",
      brute_force: "brute force",
      jwt_replay: "jwt replay",
      jwt_invalid: "jwt invalid",
    },
    on: "on",
  },
  es: {
    title: "SentinelAPI · consola de ataques",
    skip: "Saltar a los ataques",
    language: "Idioma",
    heading: "Lanza un ataque y mira cómo lo detectan",
    lede:
      "Cada botón ejecuta un ataque en el servidor, contra los detectores reales de SentinelAPI, desde " +
      "direcciones simuladas. Abajo aparecen cada petición que hace y el veredicto que recibe, con lo que " +
      "SentinelAPI registró en su auditoría.",
    attacks: "Ataques",
    "burst.title": "Ráfaga",
    "burst.text": "Setenta peticiones seguidas desde una dirección, con un límite de 60 por minuto.",
    "burst.run": "Lanzar la ráfaga",
    "stuffing.title": "Credential stuffing",
    "stuffing.text":
      "Una cuenta y una contraseña incorrecta desde cada una de 20 direcciones, así que ninguna falla dos " +
      "veces. Después su dueño entra con la contraseña correcta.",
    "stuffing.run": "Lanzar el credential stuffing",
    "replay.title": "Reuso de token",
    "replay.text":
      "El dueño canjea un refresh token de un solo uso; después se reutiliza una copia robada desde otra dirección.",
    "replay.run": "Lanzar el reuso",
    result: "Qué pasó",
    idle: "Lanza un ataque para ver cada una de sus peticiones y su veredicto.",
    running: "Ejecutando…",
    unreachable: "No se pudo contactar con el servidor. Vuelve a intentarlo en un momento.",
    answered: (status) => `El servidor respondió ${status}.`,
    caption: "Las peticiones del último ataque y el veredicto de SentinelAPI sobre cada una",
    "column.from": "Desde",
    "column.request": "Petición",
    "column.answer": "Respuesta",
    "column.verdict": "Veredicto",
    audit: "Auditoría, en vivo",
    "audit.hint": "Lo que SentinelAPI registró de tus ataques, al momento. Solo tú lo ves.",
    connecting: "Conectando…",
    live: "En vivo: los eventos nuevos aparecen arriba.",
    reconnecting: "Reconectando…",
    "footer.open": "SentinelAPI es de código abierto:",
    "footer.source": "código y documentación",
    "footer.addresses":
      "Las direcciones de arriba vienen de los rangos reservados para documentación (RFC 5737). " +
      "Las de los visitantes reales solo se guardan como hashes con clave.",
    outcomes: {
      allowed: "Permitida",
      warned: "Permitida, reportada",
      rejected: "Rechazada",
      blocked: "Bloqueada por SentinelAPI",
    },
    threats: {
      rate_limit_exceeded: "límite de peticiones superado",
      brute_force: "fuerza bruta",
      jwt_replay: "reuso de JWT",
      jwt_invalid: "JWT inválido",
    },
    on: "en",
  },
};
const LANGUAGES = Object.keys(STRINGS);
const STORED = "sentinelapi.language";

const summary = document.getElementById("summary");
const table = document.getElementById("steps");
const rows = table.querySelector("tbody");
const events = document.getElementById("events");
const streamState = document.getElementById("stream-state");
const buttons = [...document.querySelectorAll("button[data-scenario]")];
const switches = [...document.querySelectorAll("button[data-language]")];

// What is on screen, kept so a change of language redraws it without asking the server again.
let language = "en";
let outcome = { kind: "idle" };
let stream = "connecting";
const received = [];

function t(key) {
  return STRINGS[language][key];
}

// A stored choice first; then the browser's languages in the person's order, the first one the
// console speaks; then English.
function initialLanguage() {
  try {
    const stored = localStorage.getItem(STORED);
    if (LANGUAGES.includes(stored)) return stored;
  } catch {
    // Storage can be blocked; the browser's languages still decide.
  }
  for (const each of navigator.languages ?? [navigator.language]) {
    const primary = String(each).toLowerCase().split("-")[0];
    if (LANGUAGES.includes(primary)) return primary;
  }
  return "en";
}

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

function inLanguage(text) {
  return typeof text === "object" && text !== null ? text[language] : text;
}

function renderStep(step) {
  const verdict = document.createElement("td");
  verdict.append(span(`badge badge-${step.outcome}`, t("outcomes")[step.outcome]));
  if (step.level) {
    verdict.append(` · ${step.level.toUpperCase()}`);
  }
  if (step.detail) {
    verdict.append(span("detail", inLanguage(step.detail)));
  }
  const row = document.createElement("tr");
  row.append(
    cell(String(step.number)),
    cell(step.source),
    cell(inLanguage(step.request)),
    cell(String(step.status)),
    verdict,
  );
  rows.append(row);
}

function renderOutcome() {
  rows.replaceChildren();
  table.hidden = outcome.kind !== "result";
  if (outcome.kind === "result") {
    for (const step of outcome.result.steps) renderStep(step);
    summary.textContent = `${inLanguage(outcome.result.title)}: ${inLanguage(outcome.result.summary)}`;
  } else if (outcome.kind === "refused") {
    summary.textContent = inLanguage(outcome.detail) ?? t("answered")(outcome.status);
  } else {
    summary.textContent = t(outcome.kind);
  }
}

function renderEvent(event) {
  const item = document.createElement("li");
  item.className = `event event-${event.threat_level}`;
  const title = document.createElement("strong");
  const threat = t("threats")[event.threat_type] ?? event.threat_type.replaceAll("_", " ");
  title.textContent = `${event.threat_level.toUpperCase()} · ${threat}`;
  item.append(title, ` ${t("on")} ${event.path}: ${inLanguage(event.detail)}`);
  return item;
}

function renderEvents() {
  events.replaceChildren(...received.map(renderEvent));
}

function use(next, remember) {
  language = next;
  document.documentElement.lang = next;
  document.title = t("title");
  for (const element of document.querySelectorAll("[data-i18n]")) {
    element.textContent = t(element.dataset.i18n);
  }
  for (const element of document.querySelectorAll("[data-i18n-label]")) {
    element.setAttribute("aria-label", t(element.dataset.i18nLabel));
  }
  for (const each of switches) {
    each.setAttribute("aria-pressed", String(each.dataset.language === next));
  }
  streamState.textContent = t(stream);
  renderOutcome();
  renderEvents();
  if (remember) {
    try {
      localStorage.setItem(STORED, next);
    } catch {
      // Not remembered across visits; this page still shows it.
    }
  }
}

async function run(button) {
  for (const each of buttons) each.disabled = true;
  outcome = { kind: "running" };
  renderOutcome();
  try {
    const response = await fetch(`/demo/scenarios/${button.dataset.scenario}`, {
      method: "POST",
      headers: { Accept: "application/json" },
    });
    const result = await response.json();
    outcome = response.ok
      ? { kind: "result", result }
      : { kind: "refused", detail: result.detail, status: response.status };
  } catch {
    outcome = { kind: "unreachable" };
  } finally {
    renderOutcome();
    for (const each of buttons) each.disabled = false;
    button.focus();
  }
}

for (const button of buttons) {
  button.addEventListener("click", () => run(button));
}
for (const each of switches) {
  each.addEventListener("click", () => use(each.dataset.language, true));
}

const source = new EventSource("/demo/events");
source.onopen = () => {
  stream = "live";
  streamState.textContent = t(stream);
};
source.onerror = () => {
  stream = "reconnecting";
  streamState.textContent = t(stream);
};
source.onmessage = (message) => {
  const event = JSON.parse(message.data);
  received.unshift(event);
  if (received.length > 200) received.pop();
  events.prepend(renderEvent(event));
  while (events.children.length > 200) events.lastElementChild.remove();
};

use(initialLanguage(), false);
