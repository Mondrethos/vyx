import { mountCommand } from "./command.js";
import { createArt } from "./vyx-art.js";

const art = document.querySelector(".v-art");
createArt(art, art.querySelector(".v-art-canvas"), art.querySelector(".v-art-slot"));

// "read the script first" swaps the one-liner for the inspect-first commands, without animation.
const oneLiner = document.getElementById("install-one-liner");
const inspect = document.getElementById("install-inspect");
const commands = [mountCommand(oneLiner), mountCommand(inspect)];
const toggle = document.querySelector(".l-toggle");
toggle.addEventListener("click", () => {
  const inspecting = toggle.getAttribute("aria-pressed") !== "true";
  toggle.setAttribute("aria-pressed", String(inspecting));
  toggle.textContent = inspecting ? "one-liner" : "read the script first";
  oneLiner.hidden = inspecting;
  inspect.hidden = !inspecting;
  for (const command of commands) command.reset();
});
