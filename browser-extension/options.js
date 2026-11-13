import { AppError, browserName, explain, forgetPairing, getPairing, ping, request, startPairing } from "./protocol.js";

const $ = (id) => document.getElementById(id);

function view(section) {
  for (const id of ["connected", "connect", "pairing"]) $(id).classList.toggle("hidden", id !== section);
}

function error(text) {
  $("error").className = "error";
  $("error").textContent = text || "";
}

async function refresh() {
  error("");
  $("test-result").textContent = "";
  const pairing = await getPairing();
  if (pairing) {
    const since = new Date(pairing.since || Date.now()).toLocaleDateString();
    $("connected-text").textContent = `Connected to Authenticator as "${pairing.name}" since ${since}.`;
    view("connected");
  } else {
    if (!$("name").value) $("name").value = browserName();
    view("connect");
  }
}

async function connect(event) {
  event.preventDefault();
  error("");
  const name = $("name").value.trim() || browserName();
  try {
    await ping();
  } catch (e) {
    error(explain(e));
    return;
  }
  try {
    const { code, done } = await startPairing(name);
    $("code").textContent = code;
    view("pairing");
    await done;
    await refresh();
    $("test-result").textContent = "Connected. You can now fill in logins on websites.";
    $("test-result").className = "ok";
  } catch (e) {
    await refresh();
    error(e instanceof AppError && e.code === "denied" ? "The connection was denied in Authenticator." : explain(e));
  }
}

async function test() {
  const result = $("test-result");
  result.className = "";
  result.textContent = "Testing…";
  try {
    await request("status", {}, false);
    result.className = "ok";
    result.textContent = "Works. Authenticator is unlocked.";
  } catch (e) {
    if (e instanceof AppError && e.code === "locked") {
      result.className = "ok";
      result.textContent = "Works. Authenticator is locked right now; it asks for the PIN when you fill in a login.";
    } else {
      result.className = "error";
      result.textContent = explain(e);
    }
  }
}

async function forget() {
  await forgetPairing();
  await refresh();
  $("test-result").textContent = "";
  error("");
  $("error").className = "dim";
  $("error").textContent = "Disconnected. You can also remove this browser in the app (Tools → Browser integration).";
}

$("connect").addEventListener("submit", connect);
$("test").addEventListener("click", test);
$("forget").addEventListener("click", forget);
refresh();
