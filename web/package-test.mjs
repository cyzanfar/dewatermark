import assert from "node:assert/strict";

import { inspectText, sanitizeText, sanitizeTextWithReport } from "./sanitizer.mjs";

assert.equal(sanitizeText("he\u200bllo"), "hello");
assert.equal(sanitizeText("👩‍💻 فارسی‌نویسی"), "👩‍💻 فارسی‌نویسی");
assert.equal(inspectText("he\u200bllo")[0].codepoint, "U+200B");
const report = sanitizeTextWithReport("a\u{e0061}b");
assert.equal(report.changed, true);
assert.equal(report.edits.length, 1);
assert.match(report.policyVersion, /^\d{4}\.\d{2}$/);
const normalized = sanitizeTextWithReport("Cafe\u0301");
assert.equal(normalized.cleanedText, "Caf\u00e9");
assert.equal(normalized.changed, true);
assert.equal(normalized.edits.length, 1);
assert.equal(normalized.edits[0].category, "normalization");
assert.equal(normalized.edits[0].original, "e\u0301");
