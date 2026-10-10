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

// Group quick-select on the token editor: ticking a group ticks its
// secrets, and a group shows ticked when all its secrets are (partly
// ticked when only some are). The server only ever receives the secrets.
function syncGroups() {
  document.querySelectorAll("[data-group-members]").forEach((box) => {
    const ids = box.dataset.groupMembers.split(",").filter(Boolean);
    const ticks = ids.map((id) => {
      const secret = document.querySelector('[data-secret="' + id + '"]');
      return secret ? secret.checked : false;
    });
    const on = ticks.filter(Boolean).length;
    box.checked = ids.length > 0 && on === ids.length;
    box.indeterminate = on > 0 && on < ids.length;
  });
}

document.addEventListener("change", (event) => {
  const box = event.target;
  if (box.matches("[data-group-members]")) {
    box.dataset.groupMembers.split(",").filter(Boolean).forEach((id) => {
      const secret = document.querySelector('[data-secret="' + id + '"]');
      if (secret) {
        secret.checked = box.checked;
      }
    });
    box.indeterminate = false;
  }
  if (box.matches("[data-secret], [data-group-members]")) {
    syncGroups();
  }
});

document.addEventListener("DOMContentLoaded", syncGroups);

document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});
