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
package io.jsonwebtoken.impl.io

import org.junit.Test

import static org.junit.Assert.*

/**
 * Unit tests for {@link DuplicateKeyScanner}.
 *
 * @since 0.14.0
 */
class DuplicateKeyScannerTest {

    @Test
    void testNoDuplicates() {
        assertNull DuplicateKeyScanner.findFirstDuplicate('{"a":1,"b":{"c":2,"d":[1,2,{"e":3}]},"f":"g"}')
    }

    @Test
    void testNullAndEmptyInput() {
        assertNull DuplicateKeyScanner.findFirstDuplicate(null)
        assertNull DuplicateKeyScanner.findFirstDuplicate('')
    }

    @Test
    void testTopLevelDuplicate() {
        String json = '{"a":1,"b":2,"a":3}'
        def dup = DuplicateKeyScanner.findFirstDuplicate(json)
        assertNotNull dup
        assertEquals 'a', dup.key
        assertEquals 'a', dup.path // top-level path is just the key name
        assertEquals json.indexOf('"a":3'), dup.offset
    }

    @Test
    void testNestedDuplicatePath() {
        def dup = DuplicateKeyScanner.findFirstDuplicate('{"user":{"role":"a","role":"b"}}')
        assertNotNull dup
        assertEquals 'role', dup.key
        assertEquals 'user.role', dup.path
    }

    @Test
    void testDeeplyNestedDuplicatePath() {
        def dup = DuplicateKeyScanner.findFirstDuplicate('{"a":{"b":{"c":{"x":1,"x":2}}}}')
        assertNotNull dup
        assertEquals 'a.b.c.x', dup.path
    }

    @Test
    void testDuplicateWithinArrayElement() {
        def dup = DuplicateKeyScanner.findFirstDuplicate('{"items":[{"id":1,"id":2}]}')
        assertNotNull dup
        assertEquals 'items[0].id', dup.path
    }

    @Test
    void testDuplicateWithinSecondArrayElement() {
        def dup = DuplicateKeyScanner.findFirstDuplicate('{"items":[{"id":1},{"id":2,"id":3}]}')
        assertNotNull dup
        assertEquals 'items[1].id', dup.path
    }

    @Test
    void testSameKeyInDifferentObjectsIsNotDuplicate() {
        assertNull DuplicateKeyScanner.findFirstDuplicate('{"a":{"x":1},"b":{"x":2}}')
        assertNull DuplicateKeyScanner.findFirstDuplicate('[{"x":1},{"x":2}]')
    }

    @Test
    void testEscapedDuplicateKey() {
        // "a" and its unicode-escaped form are the same key after JSON unicode-unescaping:
        def dup = DuplicateKeyScanner.findFirstDuplicate('{"a":1,"\\u0061":2}')
        assertNotNull dup
        assertEquals 'a', dup.key
        assertEquals 'a', dup.path
    }

    @Test
    void testBracesAndQuotesInsideStringsAreIgnored() {
        assertNull DuplicateKeyScanner.findFirstDuplicate('{"a":"{\\"b\\":1}","b":2}')
        assertNull DuplicateKeyScanner.findFirstDuplicate('{"a":"}][{","b":"\\""}')
    }

    @Test
    void testLiteralsAndNumbers() {
        assertNull DuplicateKeyScanner.findFirstDuplicate(
                '{"a":true,"b":false,"c":null,"d":-1.5e+10,"e":[0,-2,3.14,1e-9]}')
    }

    @Test
    void testDuplicateWithIdenticalValues() {
        def dup = DuplicateKeyScanner.findFirstDuplicate('{"a":1,"a":1}')
        assertNotNull dup
        assertEquals 'a', dup.path
    }

    @Test
    void testMalformedJsonReturnsNull() {
        // not standard JSON: scanner aborts quietly so the configured deserializer reports syntax errors
        assertNull DuplicateKeyScanner.findFirstDuplicate('not json')
        assertNull DuplicateKeyScanner.findFirstDuplicate('{"a":')
        assertNull DuplicateKeyScanner.findFirstDuplicate('{"a":1,}')
        assertNull DuplicateKeyScanner.findFirstDuplicate('{"a" 1}')
        assertNull DuplicateKeyScanner.findFirstDuplicate('{"a":tru}')
        assertNull DuplicateKeyScanner.findFirstDuplicate('{"a":01x}')
        assertNull DuplicateKeyScanner.findFirstDuplicate('{unquoted:1}')
    }

    @Test
    void testDuplicateDetectedBeforeTrailingSyntaxError() {
        // a duplicate that occurs before any syntax problem is still reported:
        def dup = DuplicateKeyScanner.findFirstDuplicate('{"a":1,"a":2,}')
        assertNotNull dup
        assertEquals 'a', dup.path
    }

    @Test
    void testWhitespaceTolerance() {
        def dup = DuplicateKeyScanner.findFirstDuplicate("{\n  \"a\" : 1,\r\n\t\"a\" : 2\n}")
        assertNotNull dup
        assertEquals 'a', dup.path
    }

    @Test
    void testToStringContainsPathAndOffset() {
        def dup = DuplicateKeyScanner.findFirstDuplicate('{"a":1,"a":2}')
        assertTrue dup.toString().contains("'a'")
        assertTrue dup.toString().contains('offset')
    }
}
