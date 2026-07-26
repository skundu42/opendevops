"use strict";

const revealButton = document.getElementById("reveal-token");
const tokenInput = document.getElementById("token");

if (revealButton && tokenInput) {
  revealButton.addEventListener("click", () => {
    const revealing = tokenInput.type === "password";
    tokenInput.type = revealing ? "text" : "password";
    revealButton.textContent = revealing ? "Hide" : "Show";
    revealButton.setAttribute("aria-label", revealing ? "Hide token" : "Show token");
    tokenInput.focus();
  });
}
