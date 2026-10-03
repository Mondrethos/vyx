import { mountScreenFrame } from "./screen-frame.js";

for (const figure of document.querySelectorAll(".v-frame[data-scene]")) mountScreenFrame(figure);
