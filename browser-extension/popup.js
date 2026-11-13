import { AppError, explain, getPairing, ping, readFields, request, webPage } from "./protocol.js";

const $ = (id) => document.getElementById(id);
let tab = null;

function show(section) {
  for (const id of ["message", "list", "save"]) $(id).classList.toggle("hidden", id !== section);
}

/** Shows a sentence with optional buttons: [[label, onClick, primary]]. */
function message(text, buttons = []) {
  $("message-text").textContent = text;
  const actions = $("message-actions");
  actions.replaceChildren();
  for (const [label, onClick, primary] of buttons) {
    const button = document.createElement("button");
    button.textContent = label;
    if (primary) button.className = "primary";
    button.addEventListener("click", onClick);
    actions.appendChild(button);
  }
  show("message");
}

function openOptions() {
  chrome.runtime.openOptionsPage();
  window.close();
}

function unlock() {
  // The app comes to the front for the PIN and this popup closes; the
  // extension opens it again once the app is unlocked.
  chrome.runtime.sendMessage({ cmd: "unlock" });
  message("Enter your PIN in the Authenticator window…");
}

function handleError(error) {
  const code = error instanceof AppError ? error.code : "";
  if (code === "locked") return message("Authenticator is locked.", [["Unlock", unlock, true]]);
  if (code === "not-paired" || code === "unknown-client")
    return message(explain(error), [["Connect…", openOptions, true]]);
  message(explain(error));
}

function showLogins(logins) {
  const list = $("list");
  list.replaceChildren();
  if (logins.length === 0) {
    message("No saved login for this website.", [["Save login from this page", openSave]]);
    return;
  }
  for (const login of logins) {
    const row = document.createElement("button");
    row.className = "login";
    row.title = "Fill in this login";
    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.textContent = (login.title.trim()[0] || "?").toUpperCase();
    const text = document.createElement("span");
    text.className = "text";
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = login.title;
    const user = document.createElement("div");
    user.className = "user";
    user.textContent = login.username || "(no user name)";
    text.append(title, user);
    row.append(avatar, text);
    if (login.otp) {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = "2FA";
      row.appendChild(badge);
    }
    row.addEventListener("click", () => {
      chrome.runtime.sendMessage({ cmd: "fill", tabId: tab.id, login: login.id });
      window.close();
    });
    list.appendChild(row);
  }
  show("list");
  list.querySelector("button")?.focus();
}

async function openSave() {
  $("save-error").textContent = "";
  let page = { username: "", password: "", title: "" };
  try {
    page = (await readFields(tab.id)) || page;
  } catch {
    // Empty form.
  }
  const host = new URL(tab.url).hostname.replace(/^www\./, "");
  $("save-title").value = host;
  $("save-user").value = page.username || "";
  $("save-password").value = page.password || "";
  show("save");
  ($("save-user").value ? $("save-password") : $("save-user")).focus();
}

async function submitSave(event) {
  event.preventDefault();
  const password = $("save-password").value;
  if (!password) {
    $("save-error").textContent = "Enter the password.";
    return;
  }
  try {
    const answer = await request(
      "save",
      { url: tab.url, title: $("save-title").value, username: $("save-user").value, password },
      false,
    );
    $("save-password").value = "";
    message(answer.updated ? "Password updated in Authenticator." : "Saved in Authenticator.");
  } catch (error) {
    if (error instanceof AppError && error.code === "locked") {
      $("save-error").textContent = "Authenticator is locked. Unlock it, then save again.";
      return;
    }
    $("save-error").textContent = explain(error);
  }
}

async function refresh() {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!webPage(tab)) {
    $("save-open").classList.add("hidden");
    message("Open a website to fill in a login.");
    return;
  }
  $("site").textContent = new URL(tab.url).hostname;
  message("Checking…");
  if (!(await getPairing())) {
    try {
      await ping();
    } catch (error) {
      return message(explain(error));
    }
    return message("Connect this browser to the Authenticator app to fill in your logins.", [
      ["Connect…", openOptions, true],
    ]);
  }
  try {
    const { logins } = await request("logins", { url: tab.url }, false);
    showLogins(logins);
  } catch (error) {
    handleError(error);
  }
}

$("options").addEventListener("click", openOptions);
$("save-open").addEventListener("click", openSave);
$("save").addEventListener("submit", submitSave);
$("save-cancel").addEventListener("click", () => refresh());
refresh();
