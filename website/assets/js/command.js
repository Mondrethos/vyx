// A shell command with a yellow COPY button. Copying turns the frame and button green for 1.6 s;
// if the clipboard is blocked, the command text is selected for a manual copy instead.
const RESET_MS = 1600;
const TEXT = { idle: "Copy", copied: "Copied", selected: "Ctrl+C" };

/**
 * Wires the copy button inside a `.v-cmd` element. The button's initial aria-label names the
 * idle action. Returns `reset()`, which drops any pending copied or selected state.
 * @param {HTMLElement} element
 */
export function mountCommand(element) {
  const button = element.querySelector(".v-cmd-copy");
  const text = element.querySelector(".v-cmd-text");
  const label = { idle: button.getAttribute("aria-label"), copied: "Copied", selected: "Selected; press Ctrl+C" };
  let timer = 0;

  const show = (state) => {
    element.classList.toggle("is-copied", state === "copied");
    button.textContent = TEXT[state];
    button.setAttribute("aria-label", label[state]);
  };

  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text.innerText.trim());
      show("copied");
    } catch {
      const range = document.createRange();
      range.selectNodeContents(text);
      const selection = getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      show("selected");
    }
    clearTimeout(timer);
    timer = setTimeout(() => show("idle"), RESET_MS);
  });

  return {
    reset() {
      clearTimeout(timer);
      show("idle");
    },
  };
}
