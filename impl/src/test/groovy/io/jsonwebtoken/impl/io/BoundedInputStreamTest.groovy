/*
 * Copyright © 2024 jsonwebtoken.io
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

import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.junit.Assert.*

class BoundedInputStreamTest {

    @Test
    void testNullInputStream() {
        try {
            new BoundedInputStream(null, 1)
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals 'InputStream cannot be null.', expected.getMessage()
        }
    }

    @Test
    void testNegativeMaxBytes() {
        try {
            new BoundedInputStream(Streams.of(Strings.utf8('a')), -1)
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals 'maxBytes must be greater than or equal to zero.', expected.getMessage()
        }
    }

    @Test
    void testExactBoundary() {
        // exactly maxBytes of data may be read without exception:
        def data = Strings.utf8('hello')
        def stream = new BoundedInputStream(Streams.of(data), data.length)
        def out = new ByteArrayOutputStream()
        Streams.copy(stream, out, new byte[2]) // small buffer to force multiple reads
        assertArrayEquals data, out.toByteArray()
        assertFalse stream.isLimitExceeded()
    }

    @Test
    void testLimitExceeded() {
        // one byte more than maxBytes must be rejected:
        def data = Strings.utf8('hello')
        def stream = new BoundedInputStream(Streams.of(data), data.length - 1)
        try {
            Streams.copy(stream, new ByteArrayOutputStream(), new byte[2])
            fail()
        } catch (IOException expected) {
            assertEquals 'Stream exceeds the maximum allowed 4 bytes.', expected.getMessage()
            assertTrue stream.isLimitExceeded()
        }
    }

    @Test
    void testRefusesFurtherReadsOnceExceeded() {
        // once the limit is reached, the stream refuses to produce any additional bytes:
        def data = Strings.utf8('hello')
        def stream = new BoundedInputStream(Streams.of(data), 1)
        int h = ('h' as char)
        assertEquals h, stream.read() // first byte is fine
        try {
            stream.read()
            fail()
        } catch (IOException expected) {
            assertTrue stream.isLimitExceeded()
        }
        // still refuses on subsequent attempts:
        try {
            stream.read()
            fail()
        } catch (IOException expected) {
            assertTrue stream.isLimitExceeded()
        }
    }
}
