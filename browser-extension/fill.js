// Injected into the top frame of the current tab, only when the user asks
// (toolbar button or Ctrl+Shift+U). Runs in the extension's isolated world:
// the page cannot see or call these functions.
(() => {
  if (globalThis.__authenticator) return;

  const TEXT_TYPES = new Set(["text", "email", "tel", "number", "search", ""]);
  const OTP_WORDS =
    /one[-_ ]?time|\botp\b|totp|2fa|mfa|two[-_ ]?factor|two[-_ ]?step|verification[-_ ]?code|verify[-_ ]?code|auth(entication|enticator)?[-_ ]?code|security[-_ ]?code|passcode|sms[-_ ]?code|\bcode\b/i;
  const USER_WORDS = /user|login|e-?mail|account|identifier|\bid\b|signin|logon/i;

  function attributes(el) {
    return [el.name, el.id, el.placeholder, el.getAttribute("aria-label"), el.getAttribute("autocomplete")]
      .filter(Boolean)
      .join(" ");
  }

  function autocomplete(el) {
    return (el.getAttribute("autocomplete") || "").toLowerCase();
  }

  function visible(el) {
    if (el.disabled || el.type === "hidden") return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return false;
    const style = getComputedStyle(el);
    return style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity) > 0.05;
  }

  function inputs() {
    return Array.from(document.querySelectorAll("input")).filter(visible);
  }

  function otpLike(el) {
    return autocomplete(el).includes("one-time-code") || OTP_WORDS.test(attributes(el));
  }

  function findOtp(all, passwords) {
    // Codes split into one box per digit.
    const boxes = all.filter((el) => el.maxLength === 1 && (TEXT_TYPES.has(el.type) || el.type === "password"));
    if (boxes.length >= 4 && boxes.length <= 8) return boxes;
    const marked = all.find((el) => autocomplete(el).includes("one-time-code"));
    if (marked) return [marked];
    // On a page with a real password field, do not guess.
    if (passwords.length) return [];
    const guess = all.find((el) => TEXT_TYPES.has(el.type) && el.type !== "email" && otpLike(el));
    return guess ? [guess] : [];
  }

  function findFields() {
    const all = inputs();
    const passwords = all.filter((el) => el.type === "password" && !otpLike(el) && el.maxLength !== 1);
    const otp = findOtp(all, passwords);
    const password = passwords[0] || null;
    let username = null;
    const candidates = all.filter((el) => TEXT_TYPES.has(el.type) && !otp.includes(el));
    if (password) {
      const before = candidates.filter(
        (el) => el.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING,
      );
      const sameForm = before.filter((el) => el.form && el.form === password.form);
      username = (sameForm.length ? sameForm : before).at(-1) || null;
    } else {
      username =
        candidates.find((el) => /username|email/.test(autocomplete(el))) ||
        candidates.find((el) => el.type === "email") ||
        candidates.find((el) => USER_WORDS.test(attributes(el)) && !otpLike(el)) ||
        null;
    }
    return { username, password, otp };
  }

  function setValue(el, value) {
    el.focus({ preventScroll: true });
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function detect() {
    const f = findFields();
    return { username: !!f.username, password: !!f.password, otp: f.otp.length > 0 };
  }

  function read() {
    const f = findFields();
    return {
      username: f.username ? f.username.value : "",
      password: f.password ? f.password.value : "",
      title: document.title || "",
    };
  }

  function fill(expectedOrigin, values) {
    // The tab may have moved to another site since the app was asked.
    if (location.origin !== expectedOrigin) return { ok: false };
    const f = findFields();
    const filled = [];
    if (typeof values.username === "string" && values.username && f.username) {
      setValue(f.username, values.username);
      filled.push("username");
    }
    if (typeof values.password === "string" && f.password) {
      setValue(f.password, values.password);
      filled.push("password");
    }
    if (typeof values.otp === "string" && f.otp.length) {
      if (f.otp.length > 1) {
        const digits = values.otp.split("");
        f.otp.forEach((box, i) => setValue(box, digits[i] || ""));
      } else {
        setValue(f.otp[0], values.otp);
      }
      filled.push("otp");
    }
    return { ok: true, filled };
  }

  let toastTimer = null;
  function toast(text) {
    let host = document.getElementById("authenticator-extension-toast");
    if (!host) {
      host = document.createElement("div");
      host.id = "authenticator-extension-toast";
      host.style.cssText = "all:initial;";
      const shadow = host.attachShadow({ mode: "closed" });
      const box = document.createElement("div");
      box.style.cssText =
        "position:fixed;top:16px;right:16px;z-index:2147483647;max-width:360px;padding:10px 14px;border-radius:8px;" +
        "background:#1e293b;color:#fff;font:13px/1.4 system-ui,sans-serif;box-shadow:0 6px 24px #0005;" +
        "border-left:4px solid #2563eb;";
      shadow.appendChild(box);
      host.__box = box;
      document.documentElement.appendChild(host);
    }
    host.__box.textContent = "Authenticator: " + text;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => host.remove(), 4000);
  }

  Object.defineProperty(globalThis, "__authenticator", {
    value: Object.freeze({ detect, read, fill, toast }),
  });
})();
