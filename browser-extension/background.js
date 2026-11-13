// Service worker: the Ctrl+Shift+U shortcut, and unlocking the app for the popup.
import { AppError, detectFields, explain, fillLogin, request, showMessage, webPage } from "./protocol.js";

/** Ctrl+Shift+U: fill the login (or only the 2FA code) on the current page. */
async function fillFromShortcut(tab) {
  if (!webPage(tab)) return;
  try {
    const fields = await detectFields(tab.id);
    if (!fields.username && !fields.password && !fields.otp) {
      await showMessage(tab.id, "no login fields found on this page.");
      return;
    }
    const { logins } = await request("logins", { url: tab.url }, true);
    const onlyCode = fields.otp && !fields.password && !fields.username;
    const candidates = onlyCode ? logins.filter((l) => l.otp) : logins;
    if (candidates.length === 0) {
      await showMessage(
        tab.id,
        onlyCode ? "no saved login with a 2FA code for this website." : "no saved login for this website.",
      );
      return;
    }
    if (candidates.length > 1) {
      try {
        await chrome.action.openPopup();
      } catch {
        await showMessage(tab.id, "several logins match. Click the Authenticator button to choose one.");
      }
      return;
    }
    await fillLogin(tab, candidates[0].id, fields);
  } catch (error) {
    if (error instanceof AppError && error.code === "no-page") return;
    await showMessage(tab.id, explain(error));
  }
}

chrome.commands.onCommand.addListener((command, tab) => {
  if (command === "fill-login") fillFromShortcut(tab);
});

// The popup closes when the app comes to the front for the PIN, so the
// worker waits for the unlock and opens the popup again afterwards.
async function unlockAndReopen() {
  try {
    await request("unlock", {}, true);
    await new Promise((r) => setTimeout(r, 300));
    await chrome.action.openPopup().catch(() => {});
  } catch {
    // The popup shows the state again when it is opened.
  }
}

/** Fill chosen in the popup (which closes as soon as the app shows up). */
async function fillChosen(tabId, loginId) {
  let tab;
  try {
    tab = await chrome.tabs.get(tabId);
    if (!webPage(tab)) return;
    const fields = await detectFields(tab.id);
    if (!fields.username && !fields.password && !fields.otp) {
      await showMessage(tab.id, "no login fields found on this page.");
      return;
    }
    await fillLogin(tab, loginId, fields);
  } catch (error) {
    if (tab && !(error instanceof AppError && error.code === "no-page")) await showMessage(tab.id, explain(error));
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only the extension's own pages, never web pages.
  if (sender.id !== chrome.runtime.id || !String(sender.url || "").startsWith(chrome.runtime.getURL(""))) return;
  if (message && message.cmd === "unlock") {
    unlockAndReopen();
    sendResponse({ ok: true });
  } else if (message && message.cmd === "fill" && Number.isInteger(message.tabId) && typeof message.login === "string") {
    fillChosen(message.tabId, message.login);
    sendResponse({ ok: true });
  }
});

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    const { pairing } = await chrome.storage.local.get("pairing");
    if (!pairing) chrome.runtime.openOptionsPage();
  }
});
