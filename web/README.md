# `@cyzanfar/dewatermark-unicode`

Dependency-free, context-aware inspection and safe sanitation of suspicious
Unicode artifacts. All processing stays in the caller's JavaScript runtime.

```js
import {
  inspectText,
  sanitizeText,
  sanitizeTextWithReport,
} from "@cyzanfar/dewatermark-unicode";

const source = "he\u200bllo";
console.log(inspectText(source));
console.log(sanitizeText(source)); // "hello"
console.log(sanitizeTextWithReport(source).edits);
```

The safe profile preserves meaningful emoji joiners, script-shaping controls,
variation selectors, and bidirectional controls where recognized context makes
them legitimate. `inspectText()` reports every classification;
`sanitizeTextWithReport()` reports every edit it applies. This package does not
claim to detect or remove undisclosed or statistical model watermarks.

The policy is generated from the same canonical JSON used by the Python
`dewatermark` package. Cross-runtime golden tests prevent behavior drift.

After the first registry release:

```bash
npm install @cyzanfar/dewatermark-unicode
```

The package is ESM-only, requires Node 18 or a modern browser, has no runtime
dependencies, and never performs I/O. `inspectText()` returns code-point,
UTF-16, and UTF-8 offsets plus dispositions. `sanitizeTextWithReport()` returns
`cleanedText`, `changed`, category counts, the Unicode policy version, and an
edit list without retaining the whole source string.

Project documentation: <https://github.com/cyzanfar/text-watermark-remover>
