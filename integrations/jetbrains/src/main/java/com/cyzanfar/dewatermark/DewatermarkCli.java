package com.cyzanfar.dewatermark;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

final class DewatermarkCli {
    static final int MAX_INPUT_BYTES = 2_000_000;
    static final int MAX_OUTPUT_BYTES = 2_000_000;
    static final Duration TIMEOUT = Duration.ofSeconds(15);
    private static final int MAX_FINDINGS = 100_000;
    private static final Pattern CATEGORY = Pattern.compile("[a-z][a-z0-9_]{0,127}");
    private static final Pattern CODEPOINT = Pattern.compile("U\\+[0-9A-F]{4,6}");
    private static final Set<String> DISPOSITIONS =
            Set.of("actionable", "contextual", "informational");
    private static final AtomicInteger THREAD_NUMBER = new AtomicInteger();
    private static final ThreadFactory DAEMON_THREAD_FACTORY = runnable -> {
        Thread thread = new Thread(
                runnable, "dewatermark-cli-io-" + THREAD_NUMBER.incrementAndGet());
        thread.setDaemon(true);
        return thread;
    };
    private static final ExecutorService IO_EXECUTOR =
            Executors.newFixedThreadPool(4, DAEMON_THREAD_FACTORY);

    record Finding(int line, int column, String category, String codepoint, String message) {}

    private DewatermarkCli() {}

    static Map<String, String> minimalEnvironment(Map<String, String> source) {
        Map<String, String> result = new HashMap<>();
        for (String key : List.of("PATH", "Path", "SYSTEMROOT", "SystemRoot", "WINDIR", "PATHEXT")) {
            String value = source.get(key);
            if (value != null) result.put(key, value);
        }
        result.put("PYTHONIOENCODING", "utf-8");
        result.put("PYTHONUTF8", "1");
        return result;
    }

    static List<Finding> scan(String text) throws IOException {
        return scan(text, null);
    }

    static List<Finding> scan(String text, Path sourcePath) throws IOException {
        List<String> arguments = new ArrayList<>(List.of("check", "--format", "json"));
        if (sourcePath != null) {
            arguments.add("--stdin-path");
            arguments.add(sourcePath.toString());
        }
        return parseScanReport(
                run(arguments, text, sourcePath == null ? null : sourcePath.getParent()));
    }

    static String sanitize(String text) throws IOException {
        return sanitize(text, null);
    }

    static String sanitize(String text, Path sourcePath) throws IOException {
        return parseSanitizeResult(
                run(
                        List.of("sanitize", "--format", "json"),
                        text,
                        sourcePath == null ? null : sourcePath.getParent()));
    }

    static List<Finding> parseScanReport(String payload) throws IOException {
        try {
            JsonObject report = JsonParser.parseString(payload).getAsJsonObject();
            JsonArray findings = report.getAsJsonArray("findings");
            if (findings == null || findings.size() > MAX_FINDINGS) {
                throw new IOException("invalid local scanner response");
            }
            int filesScanned = requiredNonNegativeInt(report, "files_scanned");
            int findingCount = requiredNonNegativeInt(report, "finding_count");
            if (filesScanned > 1_000_000 || findingCount != findings.size()) {
                throw new IOException("invalid local scanner response");
            }
            List<Finding> result = new ArrayList<>(findings.size());
            for (var item : findings) {
                if (!item.isJsonObject()) throw new IOException("invalid local scanner response");
                JsonObject value = item.getAsJsonObject();
                String category = requiredString(value, "category", 128);
                String codepoint = requiredString(value, "codepoint", 64);
                String message = requiredString(value, "message", 2_000);
                String disposition = requiredString(value, "disposition", 64);
                if (!CATEGORY.matcher(category).matches()
                        || !CODEPOINT.matcher(codepoint).matches()
                        || !DISPOSITIONS.contains(disposition)
                        || containsUnsafeDiagnosticControl(message)) {
                    throw new IOException("invalid local scanner response");
                }
                result.add(new Finding(
                        requiredPositiveInt(value, "line"),
                        requiredPositiveInt(value, "column"),
                        category,
                        codepoint,
                        message));
            }
            return List.copyOf(result);
        } catch (RuntimeException error) {
            throw new IOException("invalid local scanner response");
        }
    }

    static String parseSanitizeResult(String payload) throws IOException {
        try {
            JsonObject result = JsonParser.parseString(payload).getAsJsonObject();
            String cleaned = requiredString(result, "cleaned_text", MAX_INPUT_BYTES);
            if (cleaned.getBytes(StandardCharsets.UTF_8).length > MAX_INPUT_BYTES) {
                throw new IOException("invalid local sanitizer response");
            }
            return cleaned;
        } catch (RuntimeException error) {
            throw new IOException("invalid local sanitizer response");
        }
    }

    private static int requiredPositiveInt(JsonObject value, String field) throws IOException {
        JsonPrimitive primitive = value.getAsJsonPrimitive(field);
        if (primitive == null || !primitive.isNumber()) {
            throw new IOException("invalid local scanner response");
        }
        int parsed = primitive.getAsBigDecimal().intValueExact();
        if (parsed < 1) throw new IOException("invalid local scanner response");
        return parsed;
    }

    private static int requiredNonNegativeInt(JsonObject value, String field) throws IOException {
        JsonPrimitive primitive = value.getAsJsonPrimitive(field);
        if (primitive == null || !primitive.isNumber()) {
            throw new IOException("invalid local scanner response");
        }
        int parsed = primitive.getAsBigDecimal().intValueExact();
        if (parsed < 0) throw new IOException("invalid local scanner response");
        return parsed;
    }

    private static String requiredString(JsonObject value, String field, int limit)
            throws IOException {
        JsonPrimitive primitive = value.getAsJsonPrimitive(field);
        if (primitive == null || !primitive.isString()) {
            throw new IOException("invalid local scanner response");
        }
        String parsed = primitive.getAsString();
        if (parsed.length() > limit) throw new IOException("invalid local scanner response");
        return parsed;
    }

    private static boolean containsUnsafeDiagnosticControl(String value) {
        return value.codePoints().anyMatch(codepoint ->
                Character.getType(codepoint) == Character.CONTROL
                        || codepoint == 0x061C
                        || (codepoint >= 0x200E && codepoint <= 0x200F)
                        || (codepoint >= 0x202A && codepoint <= 0x202E)
                        || (codepoint >= 0x2066 && codepoint <= 0x2069));
    }

    private static String run(List<String> arguments, String input, Path workingDirectory)
            throws IOException {
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        if (inputBytes.length > MAX_INPUT_BYTES) throw new IOException("local scanner input exceeded limit");

        List<String> command = new ArrayList<>();
        command.add("dewatermark");
        command.addAll(arguments);
        ProcessBuilder builder = new ProcessBuilder(command);
        if (workingDirectory != null) {
            if (!Files.isDirectory(workingDirectory)) {
                throw new IOException("local scanner working directory is unavailable");
            }
            builder.directory(workingDirectory.toFile());
        }
        builder.redirectError(ProcessBuilder.Redirect.DISCARD);
        Map<String, String> environment = minimalEnvironment(System.getenv());
        builder.environment().clear();
        builder.environment().putAll(environment);

        Process process = builder.start();
        Set<ProcessHandle> observedDescendants = ConcurrentHashMap.newKeySet();
        Future<byte[]> output;
        Future<?> writer;
        try {
            output = IO_EXECUTOR.submit(() -> readBounded(process));
            writer = IO_EXECUTOR.submit(() -> {
                try (var stdin = process.getOutputStream()) {
                    stdin.write(inputBytes);
                }
                return null;
            });
        } catch (RuntimeException error) {
            terminate(process, observedDescendants);
            throw new IOException("local scanner failed");
        }

        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        boolean completed = false;
        try {
            while (process.isAlive()) {
                process.descendants().forEach(observedDescendants::add);
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) throw new TimeoutException();
                long slice = Math.min(TimeUnit.NANOSECONDS.toMillis(remaining) + 1, 25);
                process.waitFor(slice, TimeUnit.MILLISECONDS);
            }
            process.descendants().forEach(observedDescendants::add);
            int code = process.exitValue();
            if (code != 0 && code != 1) throw new IOException("local scanner failed");
            await(writer, deadline);
            String value = decodeUtf8(await(output, deadline));
            completed = true;
            return value;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException("local scanner interrupted");
        } catch (ExecutionException | TimeoutException error) {
            throw new IOException("local scanner failed");
        } finally {
            if (!completed) terminate(process, observedDescendants);
            writer.cancel(true);
            output.cancel(true);
        }
    }

    private static <T> T await(Future<T> future, long deadline)
            throws InterruptedException, ExecutionException, TimeoutException {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) throw new TimeoutException();
        return future.get(remaining, TimeUnit.NANOSECONDS);
    }

    private static String decodeUtf8(byte[] value) throws IOException {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value))
                    .toString();
        } catch (CharacterCodingException error) {
            throw new IOException("invalid local scanner response");
        }
    }

    private static void terminate(Process process, Set<ProcessHandle> observedDescendants) {
        process.descendants().forEach(observedDescendants::add);
        observedDescendants.forEach(handle -> {
            if (handle.isAlive()) handle.destroyForcibly();
        });
        if (process.isAlive()) process.destroyForcibly();
    }

    private static byte[] readBounded(Process process) throws IOException {
        try (var stream = process.getInputStream(); var output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = stream.read(buffer)) >= 0) {
                if (output.size() + read > MAX_OUTPUT_BYTES) {
                    process.destroyForcibly();
                    throw new IOException("local scanner output exceeded limit");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }
}
