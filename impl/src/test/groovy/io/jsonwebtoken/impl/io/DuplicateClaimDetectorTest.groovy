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

class DuplicateClaimDetectorTest {

    private static final String NAME = 'claims'

    private static DuplicateClaimException expectDuplicate(String json) {
        try {
            DuplicateClaimDetector.check(json, NAME)
            fail('Expected DuplicateClaimException for JSON: ' + json)
        } catch (DuplicateClaimException e) {
            return e
        }
        return null // unreachable
    }

    @Test
    void testValidJsonWithoutDuplicates() {
        // nested objects, arrays, all value types: no exception expected
        DuplicateClaimDetector.check('{"sub":"alice","nested":{"a":1,"b":[true,false,null,{"c":"x"}]},"n":-1.5e3}', NAME)
        DuplicateClaimDetector.check('{}', NAME)
        DuplicateClaimDetector.check('{"a":{},"b":[]}', NAME)
        // same name in sibling (different) objects is not a duplicate:
        DuplicateClaimDetector.check('{"a":{"k":1},"b":{"k":2}}', NAME)
        // same name at different nesting levels is not a duplicate:
        DuplicateClaimDetector.check('{"k":{"k":{"k":1}}}', NAME)
        // same name in different array elements is not a duplicate:
        DuplicateClaimDetector.check('[{"k":1},{"k":2}]', NAME)
    }

    @Test
    void testTopLevelDuplicate() {
        def e = expectDuplicate('{"a":1,"a":2}')
        assertEquals "Duplicate JSON name 'a' at path 'a' in claims JSON (line 1, column 8). " +
                'Duplicate JSON Object member names are not allowed by this parser.', e.message
    }

    @Test
    void testNestedDuplicateReportsFullPath() {
        def e = expectDuplicate('{"a":{"b":1,"b":2}}')
        assertTrue e.message, e.message.contains("at path 'a.b' in claims JSON (line 1, column 13)")
    }

    @Test
    void testDeeplyNestedDuplicate() {
        def e = expectDuplicate('{"a":{"b":{"c":{"x":1,"x":2}}}}')
        assertTrue e.message, e.message.contains("at path 'a.b.c.x'")
    }

    @Test
    void testDuplicateInArrayElementReportsIndexPath() {
        def e = expectDuplicate('{"items":[{"k":1},{"k":2,"k":3}]}')
        assertTrue e.message, e.message.contains("at path 'items[1].k'")
    }

    @Test
    void testMultilineJsonReportsRealPosition() {
        String json = '{\n  "sub": "alice",\n  "sub": "bob"\n}'
        def e = expectDuplicate(json)
        assertTrue e.message, e.message.contains("at path 'sub' in claims JSON (line 3, column 3)")
    }

    @Test
    void testUnicodeEscapedDuplicateKey() {
        // "a" and its unicode-escaped form are the same JSON member name:
        def e = expectDuplicate('{"a":1,"\\u0061":2}')
        assertTrue e.message, e.message.contains("Duplicate JSON name 'a' at path 'a'")
    }

    @Test
    void testEscapedCharactersInKeysAndValues() {
        // escaped quotes inside strings must not confuse the scanner:
        DuplicateClaimDetector.check('{"a\\"b":"c\\"d","e":"\n\t\\\\"}', NAME)
    }

    @Test
    void testMalformedJsonDoesNotThrowDuplicateClaimException() {
        // lenient by design: the real JSON Deserializer reports malformed JSON, this
        // scanner must not fail with its own error on non-tokenizable input:
        DuplicateClaimDetector.check('{"a":', NAME)
        DuplicateClaimDetector.check('not json at all', NAME)
        DuplicateClaimDetector.check('{"a":1,}', NAME)
        DuplicateClaimDetector.check('{"a" 1}', NAME)
    }

    @Test(expected = IllegalArgumentException)
    void testNullJson() {
        DuplicateClaimDetector.check(null, NAME)
    }

    @Test(expected = IllegalArgumentException)
    void testEmptyJson() {
        DuplicateClaimDetector.check('', NAME)
    }

    @Test(expected = IllegalArgumentException)
    void testNullName() {
        DuplicateClaimDetector.check('{}', null)
    }
}
