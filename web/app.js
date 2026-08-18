import { inspectText, sanitizeText } from "./sanitizer.mjs";

const input = document.querySelector("#input");
const output = document.querySelector("#output");
const summary = document.querySelector("#summary");
const findings = document.querySelector("#findings");
const inputCount = document.querySelector("#input-count");

function setFindingItems(matches) {
  findings.replaceChildren();
  if (!matches.length) {
    const item = document.createElement("li");
    item.textContent = "No suspicious Unicode found.";
    findings.append(item);
    return;
  }
  for (const match of matches) {
    const item = document.createElement("li");
    const codepoint = document.createElement("code");
    codepoint.textContent = match.codepoint;
    item.append(codepoint);
    item.append(
      ` at code-point index ${match.index} — ${match.label} (${match.disposition}): ${match.context}`,
    );
    findings.append(item);
  }
}

function run() {
  const matches = inspectText(input.value);
  output.value = sanitizeText(input.value);
  const suspicious = matches.filter((item) => item.disposition !== "informational");
  const informational = matches.length - suspicious.length;
  inputCount.textContent = `${Array.from(input.value).length.toLocaleString()} characters`;
  summary.textContent = `${suspicious.length} actionable or contextual character${suspicious.length === 1 ? "" : "s"} found${informational ? `; ${informational} legitimate-context observation${informational === 1 ? "" : "s"} preserved` : ""}. Processing stays in this browser.`;
  setFindingItems(matches);
}

async function copyText(value, button) {
  try {
    await navigator.clipboard.writeText(value);
    const original = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = original; }, 1200);
  } catch (_error) {
    button.textContent = "Copy failed";
  }
}

document.querySelector("#clean").addEventListener("click", run);
document.querySelector("#copy").addEventListener("click", (event) => {
  copyText(output.value, event.currentTarget);
});
document.querySelector("#sample").addEventListener("click", () => {
  input.value = "This\u200b sentence\u{e0061}\u{e0069} looks normal, while 👩‍💻 stays intact.";
  run();
  input.focus();
});
for (const button of document.querySelectorAll("[data-copy-target]")) {
  button.addEventListener("click", () => {
    const target = document.querySelector(`#${button.dataset.copyTarget}`);
    copyText(target.textContent, button);
  });
}
input.addEventListener("input", run);
run();
