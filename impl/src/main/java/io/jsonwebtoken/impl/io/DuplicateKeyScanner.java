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

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

/**
 * A minimal JSON scanner that detects duplicate keys within the same JSON object and reports the JSON path of
 * the first duplicate found.  It does not construct any value objects; it only tracks enough structure to
 * detect repeated object keys.
 *
 * <p>If the input is not standard JSON, scanning aborts quietly ({@code null} is returned) so the configured
 * {@link io.jsonwebtoken.io.Deserializer} remains responsible for reporting syntax errors.  This ensures the
 * scanner never changes malformed-input error handling and only adds duplicate-key detection for otherwise
 * well-formed JSON.</p>
 *
 * @since 0.14.0
 */
public final class DuplicateKeyScanner {

    private DuplicateKeyScanner() {
    }

    /**
     * Information about a duplicate JSON object key: the key itself, its full JSON path, and the
     * zero-based character offset of the duplicate key within the scanned input.
     */
    public static final class Duplicate {

        private final String key;
        private final String path;
        private final int offset;

        private Duplicate(String key, String path, int offset) {
            this.key = key;
            this.path = path;
            this.offset = offset;
        }

        /**
         * Returns the duplicate JSON object key (unescaped), for example {@code role}.
         *
         * @return the duplicate JSON object key (unescaped).
         */
        public String getKey() {
            return this.key;
        }

        /**
         * Returns the full JSON path of the duplicate key, for example {@code user.role} for a nested key,
         * {@code items[0].id} for a key within an array element, or {@code sub} for a top-level key.
         *
         * @return the full JSON path of the duplicate key.
         */
        public String getPath() {
            return this.path;
        }

        /**
         * Returns the zero-based character offset of the duplicate key's opening quote within the scanned input.
         *
         * @return the zero-based character offset of the duplicate key within the scanned input.
         */
        public int getOffset() {
            return this.offset;
        }

        @Override
        public String toString() {
            return "'" + this.path + "' (offset " + this.offset + ')';
        }
    }

    /**
     * Scans the specified JSON and returns information about the first duplicate object key found, or
     * {@code null} if no duplicates exist or the input is not standard JSON (in which case the configured
     * deserializer remains responsible for reporting syntax errors).
     *
     * @param json the JSON to scan
     * @return the first duplicate found, or {@code null} if none or the input is not standard JSON.
     */
    public static Duplicate findFirstDuplicate(CharSequence json) {
        if (json == null || json.length() == 0) {
            return null;
        }
        try {
            return new Scanner(json).scan();
        } catch (AbortException e) {
            // not standard JSON; let the configured Deserializer report any syntax errors:
            return null;
        } catch (StackOverflowError e) {
            // excessively nested; the configured Deserializer will report complexity errors:
            return null;
        }
    }

    /**
     * Internal control-flow exception used to abort scanning quietly when input is not standard JSON.
     * Pre-instantiated and stackless since it is not an error condition.
     */
    private static final class AbortException extends RuntimeException {
        private static final AbortException INSTANCE = new AbortException();

        private AbortException() {
            super(null, null, false, false);
        }
    }

    private static final class Scanner {

        private final CharSequence json;
        private final int length;
        private final Deque<String> segments = new ArrayDeque<>();
        private int i;

        private Scanner(CharSequence json) {
            this.json = json;
            this.length = json.length();
        }

        private Duplicate scan() {
            ws();
            return value();
        }

        private Duplicate value() {
            ws();
            if (this.i >= this.length) {
                throw AbortException.INSTANCE;
            }
            char c = this.json.charAt(this.i);
            switch (c) {
                case '{':
                    return object();
                case '[':
                    return array();
                case '"':
                    string();
                    return null;
                case 't':
                    literal("true");
                    return null;
                case 'f':
                    literal("false");
                    return null;
                case 'n':
                    literal("null");
                    return null;
                default:
                    if (c == '-' || isDigit(c)) {
                        number();
                        return null;
                    }
                    throw AbortException.INSTANCE;
            }
        }

        private Duplicate object() {
            this.i++; // consume '{'
            Set<String> keys = new HashSet<>();
            ws();
            if (consume('}')) {
                return null;
            }
            for (; ; ) {
                ws();
                if (this.i >= this.length || this.json.charAt(this.i) != '"') {
                    throw AbortException.INSTANCE;
                }
                int keyOffset = this.i;
                String key = string();
                if (!keys.add(key)) {
                    return new Duplicate(key, path(key), keyOffset);
                }
                ws();
                expect(':');
                this.segments.addLast(key);
                Duplicate duplicate = value();
                this.segments.removeLast();
                if (duplicate != null) {
                    return duplicate;
                }
                ws();
                if (consume(',')) {
                    continue;
                }
                if (consume('}')) {
                    return null;
                }
                throw AbortException.INSTANCE;
            }
        }

        private Duplicate array() {
            this.i++; // consume '['
            ws();
            if (consume(']')) {
                return null;
            }
            int index = 0;
            for (; ; ) {
                this.segments.addLast("[" + index++ + "]");
                Duplicate duplicate = value();
                this.segments.removeLast();
                if (duplicate != null) {
                    return duplicate;
                }
                ws();
                if (consume(',')) {
                    continue;
                }
                if (consume(']')) {
                    return null;
                }
                throw AbortException.INSTANCE;
            }
        }

        private String string() {
            // assumes this.json.charAt(this.i) == '"'
            this.i++;
            StringBuilder sb = new StringBuilder();
            while (this.i < this.length) {
                char c = this.json.charAt(this.i++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (this.i >= this.length) {
                        throw AbortException.INSTANCE;
                    }
                    char esc = this.json.charAt(this.i++);
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
                            throw AbortException.INSTANCE;
                    }
                } else {
                    sb.append(c);
                }
            }
            throw AbortException.INSTANCE; // unterminated string
        }

        private char unicode() {
            if (this.i + 4 > this.length) {
                throw AbortException.INSTANCE;
            }
            int cp = 0;
            for (int n = 0; n < 4; n++) {
                int digit = Character.digit(this.json.charAt(this.i++), 16);
                if (digit < 0) {
                    throw AbortException.INSTANCE;
                }
                cp = (cp << 4) | digit;
            }
            return (char) cp;
        }

        private void number() {
            consume('-');
            if (this.i >= this.length) {
                throw AbortException.INSTANCE;
            }
            char c = this.json.charAt(this.i);
            if (c == '0') {
                this.i++;
            } else if (isDigit(c)) {
                while (this.i < this.length && isDigit(this.json.charAt(this.i))) {
                    this.i++;
                }
            } else {
                throw AbortException.INSTANCE;
            }
            if (consume('.')) {
                digits();
            }
            if (this.i < this.length && (this.json.charAt(this.i) == 'e' || this.json.charAt(this.i) == 'E')) {
                this.i++;
                if (this.i < this.length && (this.json.charAt(this.i) == '+' || this.json.charAt(this.i) == '-')) {
                    this.i++;
                }
                digits();
            }
        }

        private void digits() {
            if (this.i >= this.length || !isDigit(this.json.charAt(this.i))) {
                throw AbortException.INSTANCE;
            }
            while (this.i < this.length && isDigit(this.json.charAt(this.i))) {
                this.i++;
            }
        }

        private void literal(String literal) {
            int end = this.i + literal.length();
            if (end > this.length) {
                throw AbortException.INSTANCE;
            }
            for (int n = 0; n < literal.length(); n++) {
                if (this.json.charAt(this.i + n) != literal.charAt(n)) {
                    throw AbortException.INSTANCE;
                }
            }
            this.i = end;
        }

        private void ws() {
            while (this.i < this.length) {
                char c = this.json.charAt(this.i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    this.i++;
                } else {
                    return;
                }
            }
        }

        private boolean consume(char c) {
            if (this.i < this.length && this.json.charAt(this.i) == c) {
                this.i++;
                return true;
            }
            return false;
        }

        private void expect(char c) {
            if (!consume(c)) {
                throw AbortException.INSTANCE;
            }
        }

        private String path(String lastKey) {
            StringBuilder sb = new StringBuilder();
            for (String segment : this.segments) {
                append(sb, segment);
            }
            append(sb, lastKey);
            return sb.toString();
        }

        private static void append(StringBuilder sb, String segment) {
            if (segment.charAt(0) == '[') { // array index segment
                sb.append(segment);
            } else {
                if (sb.length() > 0) {
                    sb.append('.');
                }
                sb.append(segment);
            }
        }

        private static boolean isDigit(char c) {
            return c >= '0' && c <= '9';
        }
    }
}
