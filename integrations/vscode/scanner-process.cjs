"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");
const { TextDecoder } = require("node:util");

const MAX_INPUT_BYTES = 2_000_000;
const MAX_OUTPUT_BYTES = 2_000_000;
const MAX_FINDINGS = 100_000;
const TIMEOUT_MS = 15_000;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const VALID_DISPOSITIONS = new Set(["actionable", "contextual", "informational"]);

function minimalEnvironment(environment = process.env) {
  const allowed = ["PATH", "Path", "SYSTEMROOT", "SystemRoot", "WINDIR", "PATHEXT"];
  const result = {};
  for (const key of allowed) {
    if (typeof environment[key] === "string") result[key] = environment[key];
  }
  result.PYTHONIOENCODING = "utf-8";
  result.PYTHONUTF8 = "1";
  return result;
}

function portablePath(value) {
  const normalized = String(value).replaceAll("\\", "/");
  return normalized.replace(/^([A-Z]):/, (_match, drive) => `${drive.toLowerCase()}:`);
}

function killProcessTree(child) {
  if (!child || !Number.isSafeInteger(child.pid) || child.pid <= 0) return;
  if (process.platform !== "win32") {
    try {
      process.kill(-child.pid, "SIGKILL");
      return;
    } catch (_error) {
      child.kill("SIGKILL");
      return;
    }
  }

  // Node does not expose Windows Job Objects. taskkill /T is the closest
  // process-tree primitive available without a native dependency.
  const systemRoot = process.env.SystemRoot || process.env.SYSTEMROOT;
  if (typeof systemRoot !== "string" || systemRoot.length === 0) {
    child.kill();
    return;
  }
  const taskkill = path.join(systemRoot, "System32", "taskkill.exe");
  try {
    const killer = spawn(taskkill, ["/pid", String(child.pid), "/t", "/f"], {
      shell: false,
      windowsHide: true,
      stdio: "ignore",
      env: minimalEnvironment(),
    });
    killer.once("error", () => child.kill());
  } catch (_error) {
    child.kill();
  }
}

function runLocalCli(executable, args, input, options = {}) {
  const timeoutMs = options.timeoutMs ?? TIMEOUT_MS;
  const maxInputBytes = options.maxInputBytes ?? MAX_INPUT_BYTES;
  const maxOutputBytes = options.maxOutputBytes ?? MAX_OUTPUT_BYTES;
  const signal = options.signal;
  const cwd = options.cwd;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    return Promise.reject(new Error("invalid local dewatermark timeout"));
  }
  if (!Number.isSafeInteger(maxInputBytes) || maxInputBytes < 1) {
    return Promise.reject(new Error("invalid local dewatermark input limit"));
  }
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1) {
    return Promise.reject(new Error("invalid local dewatermark output limit"));
  }
  if (typeof executable !== "string" || executable.length === 0 || executable.includes("\0")) {
    return Promise.reject(new Error("invalid local dewatermark executable"));
  }
  if (
    !Array.isArray(args) ||
    !args.every((value) => typeof value === "string" && !value.includes("\0"))
  ) {
    return Promise.reject(new Error("invalid local dewatermark arguments"));
  }
  if (cwd !== undefined && (typeof cwd !== "string" || cwd.length === 0 || cwd.includes("\0"))) {
    return Promise.reject(new Error("invalid local dewatermark working directory"));
  }
  if (typeof input !== "string" || Buffer.byteLength(input, "utf8") > maxInputBytes) {
    return Promise.reject(new Error("local dewatermark input exceeded limit"));
  }
  if (signal?.aborted) {
    return Promise.reject(new Error("local dewatermark process cancelled"));
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let child;
    let timer;
    const stdout = [];
    const onSignal = () => abort("local dewatermark process cancelled");
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onSignal);
      if (error && child) {
        child.stdin?.destroy();
        child.stdout?.destroy();
        child.stderr?.destroy();
      }
      if (error) reject(error);
      else resolve(value);
    };
    function abort(message = "local dewatermark process failed") {
      killProcessTree(child);
      finish(new Error(message));
    }

    try {
      child = spawn(executable, args, {
        shell: false,
        detached: process.platform !== "win32",
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
        env: minimalEnvironment(),
        ...(cwd === undefined ? {} : { cwd }),
      });
    } catch (_error) {
      finish(new Error("local dewatermark process failed"));
      return;
    }
    timer = setTimeout(() => abort("local dewatermark process timed out"), timeoutMs);
    signal?.addEventListener("abort", onSignal, { once: true });
    child.on("error", () => abort());
    child.stdout.on("error", () => abort());
    child.stderr.on("error", () => abort());
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maxOutputBytes) {
        abort("local dewatermark output exceeded limit");
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > maxOutputBytes) abort("local dewatermark output exceeded limit");
    });
    child.on("close", (code) => {
      if (code !== 0 && code !== 1) return abort();
      try {
        finish(null, UTF8_DECODER.decode(Buffer.concat(stdout)));
      } catch (_error) {
        abort("local dewatermark process returned invalid UTF-8");
      }
    });
    child.stdin.on("error", () => abort());
    child.stdin.end(input, "utf8");
  });
}

function validatedFinding(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  if (!Number.isSafeInteger(value.line) || value.line < 1) return null;
  if (!Number.isSafeInteger(value.column) || value.column < 1) return null;
  const limits = { category: 128, codepoint: 64, message: 2_000, disposition: 64 };
  for (const [field, limit] of Object.entries(limits)) {
    if (typeof value[field] !== "string" || value[field].length > limit) return null;
  }
  if (!/^[a-z][a-z0-9_]{0,127}$/u.test(value.category)) return null;
  if (!/^U\+[0-9A-F]{4,6}$/u.test(value.codepoint)) return null;
  if (!VALID_DISPOSITIONS.has(value.disposition)) return null;
  if (/\p{Cc}|\p{Bidi_Control}/u.test(value.message)) return null;
  return value;
}

function validatedReport(value) {
  if (!value || typeof value !== "object" || !Array.isArray(value.findings)) {
    throw new Error("local dewatermark process returned an invalid report");
  }
  if (
    !Number.isSafeInteger(value.files_scanned) ||
    value.files_scanned < 0 ||
    !Number.isSafeInteger(value.finding_count) ||
    value.finding_count !== value.findings.length
  ) {
    throw new Error("local dewatermark process returned an invalid report");
  }
  if (value.findings.length > MAX_FINDINGS) {
    throw new Error("local dewatermark process returned too many findings");
  }
  if (value.findings.some((finding) => validatedFinding(finding) === null)) {
    throw new Error("local dewatermark process returned an invalid finding");
  }
  return { ...value, findings: value.findings.map(validatedFinding) };
}

function codePointRange(lineText, oneBasedColumn) {
  if (typeof lineText !== "string" || !Number.isSafeInteger(oneBasedColumn)) return null;
  const characters = Array.from(lineText);
  const index = oneBasedColumn - 1;
  if (index < 0 || index >= characters.length) return null;
  const start = characters.slice(0, index).join("").length;
  return { start, end: start + characters[index].length };
}

async function scanBuffer(executable, text, includeContextual = false, options = {}) {
  const args = ["check", "--format", "json"];
  if (includeContextual) args.push("--all-findings");
  if (options.stdinPath !== undefined) {
    if (
      typeof options.stdinPath !== "string" ||
      options.stdinPath.length === 0 ||
      options.stdinPath.includes("\0")
    ) {
      throw new Error("invalid local dewatermark source path");
    }
    args.push("--stdin-path", options.stdinPath);
  }
  const output = await runLocalCli(executable, args, text, options);
  let value;
  try {
    value = JSON.parse(output);
  } catch (_error) {
    throw new Error("local dewatermark process returned invalid JSON");
  }
  return validatedReport(value);
}

async function sanitizeBuffer(executable, text, options = {}) {
  const output = await runLocalCli(executable, ["sanitize", "--format", "json"], text, options);
  let value;
  try {
    value = JSON.parse(output);
  } catch (_error) {
    throw new Error("local dewatermark process returned invalid JSON");
  }
  if (!value || typeof value.cleaned_text !== "string") {
    throw new Error("local dewatermark process returned an invalid result");
  }
  if (Buffer.byteLength(value.cleaned_text, "utf8") > MAX_INPUT_BYTES) {
    throw new Error("local dewatermark process returned an oversized result");
  }
  return value.cleaned_text;
}

module.exports = {
  MAX_INPUT_BYTES,
  MAX_OUTPUT_BYTES,
  TIMEOUT_MS,
  codePointRange,
  killProcessTree,
  minimalEnvironment,
  portablePath,
  runLocalCli,
  sanitizeBuffer,
  scanBuffer,
  validatedReport,
};
