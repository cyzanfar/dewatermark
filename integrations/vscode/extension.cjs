"use strict";

const path = require("node:path");
const vscode = require("vscode");
const { codePointRange, sanitizeBuffer, scanBuffer } = require("./scanner-process.cjs");

const pending = new Map();
const activeScans = new Map();

function configuration() {
  const config = vscode.workspace.getConfiguration("dewatermark");
  return {
    executable: config.get("executable", "dewatermark"),
    scanOnChange: config.get("scanOnChange", true),
    includeContextual: config.get("includeContextual", false),
  };
}

function wholeDocumentRange(document) {
  const lastLine = Math.max(0, document.lineCount - 1);
  return new vscode.Range(new vscode.Position(0, 0), document.lineAt(lastLine).range.end);
}

function findingDiagnostic(document, finding) {
  const line = finding.line - 1;
  if (line < 0 || line >= document.lineCount) return null;
  const location = codePointRange(document.lineAt(line).text, finding.column);
  if (location === null) return null;
  const range = new vscode.Range(line, location.start, line, location.end);
  const diagnostic = new vscode.Diagnostic(
    range,
    `${finding.message} (${finding.codepoint})`,
    finding.disposition === "actionable"
      ? vscode.DiagnosticSeverity.Warning
      : vscode.DiagnosticSeverity.Information,
  );
  diagnostic.source = "dewatermark";
  diagnostic.code = `dewatermark/${finding.category}`;
  return diagnostic;
}

async function scanDocument(document, diagnostics) {
  if (!document || document.uri.scheme !== "file") return;
  const key = document.uri.toString();
  activeScans.get(key)?.abort();
  const controller = new AbortController();
  activeScans.set(key, controller);
  const version = document.version;
  const config = configuration();
  try {
    const report = await scanBuffer(
      config.executable,
      document.getText(),
      config.includeContextual,
      {
        signal: controller.signal,
        cwd: path.dirname(document.uri.fsPath),
        stdinPath: document.uri.fsPath,
      },
    );
    if (document.version !== version || controller.signal.aborted) return;
    diagnostics.set(
      document.uri,
      report.findings
        .map((finding) => findingDiagnostic(document, finding))
        .filter((finding) => finding !== null),
    );
  } catch (_error) {
    if (!controller.signal.aborted) diagnostics.delete(document.uri);
  } finally {
    if (activeScans.get(key) === controller) activeScans.delete(key);
  }
}

function scheduleScan(document, diagnostics) {
  const key = document.uri.toString();
  clearTimeout(pending.get(key));
  activeScans.get(key)?.abort();
  pending.set(
    key,
    setTimeout(() => {
      pending.delete(key);
      scanDocument(document, diagnostics);
    }, 250),
  );
}

async function applySafeFix(uri, expectedVersion, diagnostics) {
  if (!uri) {
    vscode.window.showInformationMessage("Dewatermark: open a local file before applying cleanup.");
    return;
  }
  const document = await vscode.workspace.openTextDocument(uri);
  if (expectedVersion !== undefined && document.version !== expectedVersion) {
    vscode.window.showWarningMessage("Dewatermark: the document changed; scan it again first.");
    return;
  }
  const source = document.getText();
  const sourceVersion = document.version;
  try {
    const cleaned = await sanitizeBuffer(configuration().executable, source, {
      cwd: path.dirname(document.uri.fsPath),
    });
    if (document.version !== sourceVersion) {
      vscode.window.showWarningMessage("Dewatermark: the document changed; cleanup was not applied.");
      return;
    }
    if (cleaned === source) return;
    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, wholeDocumentRange(document), cleaned);
    if (!(await vscode.workspace.applyEdit(edit))) {
      vscode.window.showErrorMessage("Dewatermark: the editor rejected the safe cleanup.");
      return;
    }
    await scanDocument(document, diagnostics);
  } catch (_error) {
    vscode.window.showErrorMessage("Dewatermark: local safe cleanup failed.");
  }
}

class SafeFixProvider {
  constructor(diagnostics) {
    this.diagnostics = diagnostics;
  }

  provideCodeActions(document, _range, context) {
    if (!context.diagnostics.some((item) => item.source === "dewatermark")) return [];
    const action = new vscode.CodeAction(
      "Apply dewatermark safe Unicode cleanup",
      vscode.CodeActionKind.QuickFix,
    );
    action.isPreferred = true;
    action.command = {
      command: "dewatermark.applySafeFix",
      title: "Apply safe Unicode cleanup",
      arguments: [document.uri, document.version],
    };
    return [action];
  }
}

function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection("dewatermark");
  context.subscriptions.push(diagnostics);
  context.subscriptions.push(
    vscode.commands.registerCommand("dewatermark.scanDocument", () =>
      scanDocument(vscode.window.activeTextEditor?.document, diagnostics),
    ),
    vscode.commands.registerCommand("dewatermark.applySafeFix", (uri, version) => {
      const activeDocument = vscode.window.activeTextEditor?.document;
      return applySafeFix(uri ?? activeDocument?.uri, version ?? activeDocument?.version, diagnostics);
    }),
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      new SafeFixProvider(diagnostics),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
    vscode.workspace.onDidOpenTextDocument((document) => scheduleScan(document, diagnostics)),
    vscode.workspace.onDidSaveTextDocument((document) => scheduleScan(document, diagnostics)),
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (configuration().scanOnChange) scheduleScan(event.document, diagnostics);
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (!event.affectsConfiguration("dewatermark")) return;
      for (const document of vscode.workspace.textDocuments) scheduleScan(document, diagnostics);
    }),
    vscode.workspace.onDidCloseTextDocument((document) => {
      const key = document.uri.toString();
      clearTimeout(pending.get(key));
      pending.delete(key);
      activeScans.get(key)?.abort();
      activeScans.delete(key);
      diagnostics.delete(document.uri);
    }),
  );
  for (const document of vscode.workspace.textDocuments) scheduleScan(document, diagnostics);
}

function deactivate() {
  for (const timer of pending.values()) clearTimeout(timer);
  for (const controller of activeScans.values()) controller.abort();
  pending.clear();
  activeScans.clear();
}

module.exports = { activate, deactivate };
