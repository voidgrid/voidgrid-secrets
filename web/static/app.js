// "show" buttons fetch a secret's value only when clicked, so a value
// never reaches the browser (or the audit log) just by opening a page.
// Forms with data-confirm ask before submitting.
"use strict";

const MASK = "••••••••";

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-reveal-url]");
  if (!button) {
    return;
  }
  const target = document.getElementById(button.dataset.target);
  if (button.dataset.shown === "true") {
    target.textContent = MASK;
    button.textContent = "show";
    button.dataset.shown = "false";
    return;
  }
  button.disabled = true;
  try {
    const response = await fetch(button.dataset.revealUrl, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) {
      target.textContent = "could not load the value (" + response.status + ")";
      return;
    }
    const body = await response.json();
    target.textContent = body.value;
    button.textContent = "hide";
    button.dataset.shown = "true";
  } finally {
    button.disabled = false;
  }
});

document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});
