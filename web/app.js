import { inspectText, sanitizeText } from "./sanitizer.mjs";

const input = document.querySelector("#input");
const output = document.querySelector("#output");
const summary = document.querySelector("#summary");
const findings = document.querySelector("#findings");

function run() {
  const matches = inspectText(input.value);
  output.value = sanitizeText(input.value);
  const suspicious = matches.filter((item) => item.disposition !== "informational");
  const informational = matches.length - suspicious.length;
  summary.textContent = `${suspicious.length} actionable or contextual character${suspicious.length === 1 ? "" : "s"} found${informational ? `; ${informational} legitimate-context observation${informational === 1 ? "" : "s"} preserved` : ""}. Processing stays in this browser.`;
  findings.innerHTML = matches.length
    ? matches.map((item) => `<li><code>${item.codepoint}</code> at code-point index ${item.index} — ${item.label} (${item.disposition}): ${item.context}</li>`).join("")
    : "<li>No suspicious Unicode found.</li>";
}

document.querySelector("#clean").addEventListener("click", run);
document.querySelector("#copy").addEventListener("click", () => navigator.clipboard.writeText(output.value));
document.querySelector("#sample").addEventListener("click", () => { input.value = "This\u200b sentence\u{e0061}\u{e0069} looks normal."; run(); });
input.addEventListener("input", run);
run();
