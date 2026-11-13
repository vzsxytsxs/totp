// Talking to the Authenticator app on this PC (see docs/browser-protocol.md).
//
// extension <-> native messaging host (started by the browser) <-> app
//
// After connecting once (pairing, confirmed in the app), every request and
// answer is encrypted with AES-256-GCM under a key only this extension and
// the app know. Nothing here uses the network.

export const HOST = "app.authenticator.browser";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class AppError extends Error {
  constructor(code, detail) {
    super(code);
    this.code = code;
    this.detail = detail;
  }
}

// ------------------------------------------------------------------ encoding

export function toBase64(bytes) {
  const array = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let text = "";
  for (const b of array) text += String.fromCharCode(b);
  return btoa(text);
}

export function fromBase64(text) {
  const raw = atob(text);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function randomId() {
  return hex(crypto.getRandomValues(new Uint8Array(16)));
}

/** Code shown in the extension and in the app while connecting: "1234-5678". */
export async function pairCode(keyBytes) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", keyBytes));
  const n = (((hash[0] << 24) >>> 0) + (hash[1] << 16) + (hash[2] << 8) + hash[3]) % 100000000;
  const digits = String(n).padStart(8, "0");
  return `${digits.slice(0, 4)}-${digits.slice(4)}`;
}

function aad(direction, client) {
  return encoder.encode(`authenticator-browser:v1:${direction}:${client}`);
}

async function importKey(base64) {
  return crypto.subtle.importKey("raw", fromBase64(base64), "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function seal(key, client, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad("req", client) },
    key,
    encoder.encode(JSON.stringify(value)),
  );
  return { nonce: toBase64(iv), data: toBase64(data) };
}

async function open(key, client, nonce, data) {
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(nonce), additionalData: aad("res", client) },
      key,
      fromBase64(data),
    );
    return JSON.parse(decoder.decode(plain));
  } catch {
    throw new AppError("bad-response");
  }
}

// ------------------------------------------------------------------ native messaging

// One port per page/worker; messages are answered in order, one at a time.
let port = null;
let current = null;
const queue = [];
let idleTimer = null;

function hostError(message) {
  const text = String(message || "");
  if (/not found/i.test(text)) return "host-missing";
  if (/forbidden/i.test(text)) return "host-forbidden";
  if (/exited/i.test(text)) return "app-closed";
  return "host-error";
}

function pump() {
  if (current || queue.length === 0) return;
  clearTimeout(idleTimer);
  if (!port) {
    try {
      port = chrome.runtime.connectNative(HOST);
    } catch (e) {
      failAll(hostError(e && e.message));
      return;
    }
    port.onMessage.addListener(onMessage);
    port.onDisconnect.addListener(onDisconnect);
  }
  current = queue.shift();
  port.postMessage(current.message);
}

function onMessage(message) {
  const done = current;
  current = null;
  if (done) done.resolve(message);
  pump();
  if (!current) {
    // Let the helper program exit when nothing is going on.
    idleTimer = setTimeout(() => {
      if (port && !current) {
        port.disconnect();
        port = null;
      }
    }, 20000);
  }
}

function failAll(code) {
  const pending = current ? [current, ...queue.splice(0)] : queue.splice(0);
  current = null;
  for (const item of pending) item.reject(new AppError(code));
}

function onDisconnect() {
  const error = chrome.runtime.lastError;
  port = null;
  failAll(hostError(error && error.message));
}

function nativeSend(message) {
  return new Promise((resolve, reject) => {
    queue.push({ message, resolve, reject });
    pump();
  });
}

/** Is the helper installed? Returns the app version or throws. */
export async function ping() {
  const reply = await nativeSend({ type: "ping" });
  if (reply.type !== "pong") throw new AppError("bad-response");
  return reply;
}

// ------------------------------------------------------------------ pairing

export async function getPairing() {
  const { pairing } = await chrome.storage.local.get("pairing");
  return pairing && pairing.client && pairing.key ? pairing : null;
}

export async function forgetPairing() {
  await chrome.storage.local.remove("pairing");
}

/** A name for this browser, shown in the app ("Thorium", "Microsoft Edge"…). */
export function browserName() {
  const brands = (navigator.userAgentData && navigator.userAgentData.brands) || [];
  const brand = brands.map((b) => b.brand).find((b) => !/not.?a.?brand|chromium/i.test(b));
  if (brand) return brand.replace(/^Google /, "");
  const match = navigator.userAgent.match(/\b(Thorium|Edg|OPR|Vivaldi|Brave)\//);
  if (match) return { Edg: "Microsoft Edge", OPR: "Opera" }[match[1]] || match[1];
  return "Chromium";
}

/**
 * Starts connecting: returns the code to show, and a promise that settles
 * when the user answers in the app.
 */
export async function startPairing(name) {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const client = randomId();
  const key = toBase64(keyBytes);
  const code = await pairCode(keyBytes);
  const done = nativeSend({ type: "pair", client, name, key }).then(async (reply) => {
    if (reply.type === "error") throw new AppError(reply.error);
    if (reply.type !== "paired") throw new AppError("bad-response");
    const pairing = { client, key, name, since: Date.now() };
    await chrome.storage.local.set({ pairing });
    return pairing;
  });
  return { code, done };
}

// ------------------------------------------------------------------ requests

/**
 * Sends an encrypted request. With `wait`, a locked app comes to the front
 * and asks for the PIN; the answer arrives once it is unlocked.
 */
export async function request(action, params = {}, wait = false) {
  const pairing = await getPairing();
  if (!pairing) throw new AppError("not-paired");
  const key = await importKey(pairing.key);
  const id = randomId();
  const body = { ...params, id, ts: Math.floor(Date.now() / 1000), action };
  const { nonce, data } = await seal(key, pairing.client, body);
  const reply = await nativeSend({ type: "request", client: pairing.client, nonce, data, wait });
  if (reply.type === "error") throw new AppError(reply.error);
  if (reply.type !== "response") throw new AppError("bad-response");
  const answer = await open(key, pairing.client, reply.nonce, reply.data);
  if (answer.id !== id) throw new AppError("bad-response");
  if (answer.ok === false) throw new AppError(answer.error || "failed", answer.message);
  return answer;
}

/** A sentence for the user about an error. */
export function explain(error) {
  const code = error instanceof AppError ? error.code : "";
  switch (code) {
    case "host-missing":
      return "The Authenticator app is not set up for browsers yet. In the app, open Tools → Browser integration and turn it on. Then restart the browser.";
    case "host-forbidden":
      return "The Authenticator app does not recognise this copy of the extension. Load the extension from the folder shown in the app (Tools → Browser integration).";
    case "disabled":
      return "Browser integration is turned off in the Authenticator app (Tools → Browser integration).";
    case "locked":
      return "Authenticator is locked.";
    case "not-paired":
      return "This browser is not connected to Authenticator yet.";
    case "unknown-client":
      return "Authenticator no longer knows this browser. Connect it again.";
    case "denied":
      return "The request was denied in Authenticator.";
    case "timeout":
    case "cancelled":
      return "Authenticator did not answer. Try again.";
    case "app-not-found":
    case "app-not-running":
    case "app-unavailable":
    case "app-closed":
      return "Could not reach the Authenticator app. Make sure it is installed and running.";
    case "not-allowed":
      return "That login is not saved for this website.";
    case "not-found":
      return "That login no longer exists in Authenticator.";
    case "expired":
      return "The request expired. Check the clock of this PC and try again.";
    case "busy":
      return "Authenticator is busy with another request. Try again.";
    case "no-page":
      return "This page cannot be filled in.";
    default:
      return `Something went wrong (${code || (error && error.message) || "unknown error"}).`;
  }
}

// ------------------------------------------------------------------ pages

/** Prepares the page: loads fill.js into the top frame (once). */
async function inject(tabId) {
  try {
    await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["fill.js"] });
  } catch {
    throw new AppError("no-page");
  }
}

async function run(tabId, func, args = []) {
  await inject(tabId);
  try {
    const [result] = await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, func, args });
    return result ? result.result : undefined;
  } catch {
    throw new AppError("no-page");
  }
}

/** Which login fields the page shows: { username, password, otp }. */
export function detectFields(tabId) {
  return run(tabId, () => globalThis.__authenticator.detect());
}

/** Values typed on the page, to save them: { username, password }. */
export function readFields(tabId) {
  return run(tabId, () => globalThis.__authenticator.read());
}

export function showMessage(tabId, text) {
  return run(tabId, (t) => globalThis.__authenticator.toast(t), [text]).catch(() => {});
}

/** Asks the app for the needed fields of a login and fills them in. */
export async function fillLogin(tab, loginId, fields, wait = true) {
  const wanted = ["username", "password", "otp"].filter((f) => fields[f]);
  if (wanted.length === 0) throw new AppError("no-fields");
  const answer = await request("fill", { url: tab.url, login: loginId, fields: wanted }, wait);
  const values = {};
  for (const f of wanted) if (typeof answer[f] === "string") values[f] = answer[f];
  const origin = new URL(tab.url).origin;
  const result = await run(tab.id, (o, v) => globalThis.__authenticator.fill(o, v), [origin, values]);
  if (!result || !result.ok) throw new AppError("no-page");
  return result.filled;
}

export function webPage(tab) {
  return !!tab && typeof tab.url === "string" && /^https?:\/\//i.test(tab.url);
}
