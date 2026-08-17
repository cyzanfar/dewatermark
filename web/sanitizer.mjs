const removable = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\u206a-\u206f\ufeff\ufff9-\ufffb\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/gu;

export function inspectText(text) {
  const findings = [];
  for (const match of text.matchAll(removable)) {
    const value = match[0].codePointAt(0);
    findings.push({
      index: match.index,
      codepoint: `U+${value.toString(16).toUpperCase().padStart(4, "0")}`,
      label: value >= 0xe0000 ? "Unicode tag or variation selector" : "Invisible Unicode control",
    });
  }
  return findings;
}

export function sanitizeText(text) {
  return text.replace(removable, "").replace(/[\u2000-\u200a\u202f\u205f\u3000]/g, " ");
}
