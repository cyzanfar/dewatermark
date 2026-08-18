"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const {
  MAX_INPUT_BYTES,
  codePointRange,
  minimalEnvironment,
  portablePath,
  runLocalCli,
  sanitizeBuffer,
  scanBuffer,
  validatedReport,
} = require("../scanner-process.cjs");

test("normalizes Windows, macOS, and Linux paths deterministically", () => {
  assert.equal(portablePath("C:\\Users\\A\\file.txt"), "c:/Users/A/file.txt");
  assert.equal(portablePath("/Users/a/file.txt"), "/Users/a/file.txt");
  assert.equal(portablePath("/home/a/file.txt"), "/home/a/file.txt");
});

test("child environment excludes ambient credentials", () => {
  const value = minimalEnvironment({
    PATH: "/bin",
    API_KEY: "secret",
    DEWATERMARK_LLM_API_KEY: "secret",
    SYSTEMROOT: "C:\\Windows",
  });
  assert.deepEqual(value, {
    PATH: "/bin",
    PYTHONIOENCODING: "utf-8",
    PYTHONUTF8: "1",
    SYSTEMROOT: "C:\\Windows",
  });
});

test("maps code-point columns to VS Code UTF-16 ranges", () => {
  assert.deepEqual(codePointRange("a😀b", 2), { start: 1, end: 3 });
  assert.deepEqual(codePointRange("a😀b", 3), { start: 3, end: 4 });
  assert.equal(codePointRange("a", 2), null);
});

test("rejects malformed scanner findings", () => {
  assert.throws(
    () => validatedReport({ files_scanned: 1, finding_count: 1, findings: [{ line: 0 }] }),
    /invalid finding/,
  );
  assert.throws(() => validatedReport({ findings: "secret" }), /invalid report/);
  assert.doesNotThrow(() =>
    validatedReport({
      files_scanned: 1,
      finding_count: 1,
      findings: [
        {
          line: 1,
          column: 1,
          category: "zero_width",
          codepoint: "U+200B",
          message: "Suspicious character",
          disposition: "actionable",
        },
      ],
    }),
  );
});

test("bounds input before starting a process", async () => {
  await assert.rejects(
    runLocalCli(process.execPath, ["-e", "process.exit(0)"], "x".repeat(MAX_INPUT_BYTES + 1)),
    /input exceeded limit/,
  );
});

test("uses an explicit local working directory for scanner policy discovery", async () => {
  const output = await runLocalCli(
    process.execPath,
    ["-e", "process.stdout.write(process.cwd())"],
    "",
    { cwd: process.cwd() },
  );
  assert.equal(portablePath(output), portablePath(process.cwd()));
  await assert.rejects(
    runLocalCli(process.execPath, ["-e", ""], "", { cwd: "" }),
    /working directory/,
  );
});

test("rejects malformed UTF-8 and oversized process output", async () => {
  await assert.rejects(
    runLocalCli(process.execPath, ["-e", "process.stdout.write(Buffer.from([255]))"], ""),
    /invalid UTF-8/,
  );
  await assert.rejects(
    runLocalCli(process.execPath, ["-e", "process.stdout.write('abc')"], "", {
      maxOutputBytes: 2,
    }),
    /output exceeded limit/,
  );
});

test("honors cancellation and deadlines", async () => {
  await assert.rejects(
    runLocalCli(process.execPath, ["-e", "setInterval(() => {}, 1000)"], "", {
      timeoutMs: 50,
    }),
    /timed out/,
  );
  const controller = new AbortController();
  const running = runLocalCli(
    process.execPath,
    ["-e", "setInterval(() => {}, 1000)"],
    "",
    { signal: controller.signal },
  );
  controller.abort();
  await assert.rejects(running, /cancelled/);
});

test("scans and sanitizes through the local CLI", async () => {
  const executable = process.env.DEWATERMARK_TEST_EXECUTABLE || "dewatermark";
  const report = await scanBuffer(executable, "he\u200bllo");
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].line, 1);
  assert.equal(report.findings[0].column, 3);
  assert.equal(await sanitizeBuffer(executable, "he\u200bllo"), "hello");
});

test("applies the target repository policy to an unsaved editor buffer", async (t) => {
  const executable = process.env.DEWATERMARK_TEST_EXECUTABLE || "dewatermark";
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dewatermark-vscode-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const generated = path.join(root, "src", "generated");
  fs.mkdirSync(generated, { recursive: true });
  fs.writeFileSync(
    path.join(root, ".dewatermark.toml"),
    "[scan]\nexclude = ['src/generated/**']\nextensions = ['py']\n",
    "utf8",
  );
  const report = await scanBuffer(executable, "he\u200bllo", false, {
    cwd: generated,
    stdinPath: path.join(generated, "unsaved.py"),
  });
  assert.equal(report.findings.length, 0);
  assert.equal(report.files_scanned, 0);
});
