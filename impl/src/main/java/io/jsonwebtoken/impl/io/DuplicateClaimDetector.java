/*
 * Copyright (C) 2026 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.lang.Assert;

import java.util.HashSet;
import java.util.Set;

/**
 * A lightweight JSON scanner that detects duplicate JSON Object member names at any nesting
 * depth without building a result object graph.  It is used to implement
 * {@link io.jsonwebtoken.JwtParserBuilder#strictDuplicateClaimDetection()}: the raw JSON is
 * scanned <em>before</em> it is handed to the application's configured JSON {@code Deserializer},
 * so the default deserialization behavior (and its "last value wins" semantics) remains unchanged
 * when the strict option is not enabled.
 *
 * <p>When a duplicate member name is found within the same JSON Object, a
 * {@link DuplicateClaimException} is thrown whose message contains the member's full key path
 * (for example {@code nested.sub} or {@code list[1].sub}) and the 1-based line and column of the
 * duplicate name within the JSON document.</p>
 *
 * <p>This scanner is intentionally lenient with malformed JSON: if it encounters content it
 * cannot tokenize, it simply stops scanning and lets the configured JSON {@code Deserializer}
 * produce the canonical malformed-JSON error.  This keeps error behavior for problems unrelated
 * to duplicate names identical to the default parsing path.</p>
 *
 * @since 0.14.0
 */
public final class DuplicateClaimDetector {

    private static final String MSG = "Duplicate JSON name '%s' at path '%s' in %s JSON " +
            "(line %d, column %d). Duplicate JSON Object member names are not allowed by this parser.";

    /**
     * Scans the specified JSON for duplicate JSON Object member names.
     *
     * @param json the JSON document to scan
     * @param name the logical name of the JSON document (for example {@code "claims"} or
     *             {@code "protected header"}), used in exception messages
     * @throws DuplicateClaimException if any JSON Object contains the same member name more than once
     */
    public static void check(String json, String name) throws DuplicateClaimException {
        Assert.hasText(json, "JSON string cannot be null or empty.");
        Assert.hasText(name, "name cannot be null or empty.");
        new DuplicateClaimDetector(json, name).run();
    }

    // Internal control-flow signal used to abort scanning (without an error) when the JSON
    // cannot be tokenized; the real Deserializer will report malformed JSON later.
    private static final class Abort extends RuntimeException {
        private static final Abort INSTANCE = new Abort();

        private Abort() {
            super(null, null, false, false);
        }
    }

    private final String json;
    private final String name;
    private final int length;

    private int pos = 0;
    private int line = 1;
    private int col = 1;

    private DuplicateClaimDetector(String json, String name) {
        this.json = json;
        this.name = name;
        this.length = json.length();
    }

    private void run() {
        try {
            value("");
            // ignore any trailing content; the real Deserializer validates document structure
        } catch (Abort ignored) {
            // Not tokenizable by this scanner: stop checking and let the configured JSON
            // Deserializer produce the canonical malformed-JSON error.
        }
    }

    private void value(String path) {
        skipWhitespace();
        char c = peek();
        switch (c) {
            case '{':
                object(path);
                break;
            case '[':
                array(path);
                break;
            case '"':
                string();
                break;
            case 't':
                literal("true");
                break;
            case 'f':
                literal("false");
                break;
            case 'n':
                literal("null");
                break;
            default:
                number();
        }
    }

    private void object(String path) {
        advance(); // consume '{'
        Set<String> names = new HashSet<>();
        skipWhitespace();
        if (peek() == '}') {
            advance();
            return;
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"') {
                throw Abort.INSTANCE;
            }
            int keyLine = this.line;
            int keyCol = this.col;
            String key = string();
            if (!names.add(key)) {
                String keyPath = path.isEmpty() ? key : path + '.' + key;
                String msg = String.format(MSG, key, keyPath, this.name, keyLine, keyCol);
                throw new DuplicateClaimException(msg);
            }
            String childPath = path.isEmpty() ? key : path + '.' + key;
            skipWhitespace();
            if (peek() != ':') {
                throw Abort.INSTANCE;
            }
            advance(); // consume ':'
            value(childPath);
            skipWhitespace();
            char c = peek();
            if (c == ',') {
                advance();
            } else if (c == '}') {
                advance();
                return;
            } else {
                throw Abort.INSTANCE;
            }
        }
    }

    private void array(String path) {
        advance(); // consume '['
        skipWhitespace();
        if (peek() == ']') {
            advance();
            return;
        }
        int index = 0;
        while (true) {
            value(path + '[' + index + ']');
            index++;
            skipWhitespace();
            char c = peek();
            if (c == ',') {
                advance();
            } else if (c == ']') {
                advance();
                return;
            } else {
                throw Abort.INSTANCE;
            }
        }
    }

    /**
     * Consumes a JSON string, returning its decoded value (unicode and standard escapes resolved)
     * so that escaped duplicates (a plain name versus its unicode-escaped form) are detected.
     */
    private String string() {
        advance(); // consume opening '"'
        StringBuilder sb = new StringBuilder();
        while (this.pos < this.length) {
            char c = this.json.charAt(this.pos);
            if (c == '"') {
                advance(); // consume closing '"'
                return sb.toString();
            }
            if (c == '\\') {
                advance(); // consume backslash
                if (this.pos >= this.length) {
                    throw Abort.INSTANCE;
                }
                char esc = this.json.charAt(this.pos);
                advance(); // consume escape character
                switch (esc) {
                    case '"':
                        sb.append('"');
                        break;
                    case '\\':
                        sb.append('\\');
                        break;
                    case '/':
                        sb.append('/');
                        break;
                    case 'b':
                        sb.append('\b');
                        break;
                    case 'f':
                        sb.append('\f');
                        break;
                    case 'n':
                        sb.append('\n');
                        break;
                    case 'r':
                        sb.append('\r');
                        break;
                    case 't':
                        sb.append('\t');
                        break;
                    case 'u':
                        sb.append(unicode());
                        break;
                    default:
                        throw Abort.INSTANCE; // invalid escape; let the real Deserializer report it
                }
            } else {
                sb.append(c);
                advance();
            }
        }
        throw Abort.INSTANCE; // unterminated string
    }

    private char unicode() {
        if (this.pos + 4 > this.length) {
            throw Abort.INSTANCE;
        }
        int value = 0;
        for (int i = 0; i < 4; i++) {
            int digit = Character.digit(this.json.charAt(this.pos), 16);
            if (digit < 0) {
                throw Abort.INSTANCE;
            }
            value = (value << 4) + digit;
            advance();
        }
        return (char) value;
    }

    private void literal(String expected) {
        for (int i = 0; i < expected.length(); i++) {
            if (this.pos >= this.length || this.json.charAt(this.pos) != expected.charAt(i)) {
                throw Abort.INSTANCE;
            }
            advance();
        }
    }

    private void number() {
        int start = this.pos;
        while (this.pos < this.length) {
            char c = this.json.charAt(this.pos);
            if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') {
                advance();
            } else {
                break;
            }
        }
        if (this.pos == start) {
            throw Abort.INSTANCE; // not a tokenizable value
        }
    }

    private void skipWhitespace() {
        while (this.pos < this.length) {
            char c = this.json.charAt(this.pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                advance();
            } else {
                return;
            }
        }
    }

    private char peek() {
        if (this.pos >= this.length) {
            throw Abort.INSTANCE;
        }
        return this.json.charAt(this.pos);
    }

    private void advance() {
        char c = this.json.charAt(this.pos++);
        if (c == '\n') {
            this.line++;
            this.col = 1;
        } else {
            this.col++;
        }
    }
}
