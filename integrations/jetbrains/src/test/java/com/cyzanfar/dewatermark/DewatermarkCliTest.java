package com.cyzanfar.dewatermark;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class DewatermarkCliTest {
    @Test
    void environmentExcludesCredentials() {
        assertEquals(
                Map.of(
                        "PATH", "/bin",
                        "SYSTEMROOT", "C:\\Windows",
                        "PYTHONIOENCODING", "utf-8",
                        "PYTHONUTF8", "1"),
                DewatermarkCli.minimalEnvironment(Map.of(
                        "PATH", "/bin",
                        "SYSTEMROOT", "C:\\Windows",
                        "API_KEY", "secret",
                        "DEWATERMARK_LLM_API_KEY", "secret")));
    }

    @Test
    void parsesStrictScannerContract() throws Exception {
        var findings = DewatermarkCli.parseScanReport("""
                {"files_scanned":1,"finding_count":1,
                "findings":[{"line":1,"column":2,"category":"zero_width",
                "codepoint":"U+200B","message":"Suspicious character",
                "disposition":"actionable"}]}
                """);
        assertEquals(1, findings.size());
        assertEquals(2, findings.getFirst().column());
        assertThrows(
                java.io.IOException.class,
                () -> DewatermarkCli.parseScanReport(
                        "{\"findings\":[{\"line\":0,\"column\":1}]}"));
        assertThrows(
                java.io.IOException.class,
                () -> DewatermarkCli.parseScanReport("{\"findings\":\"secret\"}"));
    }

    @Test
    void parsesStrictSanitizerContract() throws Exception {
        assertEquals("hello", DewatermarkCli.parseSanitizeResult("{\"cleaned_text\":\"hello\"}"));
        assertThrows(
                java.io.IOException.class,
                () -> DewatermarkCli.parseSanitizeResult("{\"cleaned_text\":7}"));
    }
}
