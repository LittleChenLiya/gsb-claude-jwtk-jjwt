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
package io.jsonwebtoken.impl

import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.io.AbstractDeserializer
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import javax.crypto.Mac
import javax.crypto.SecretKey

import static org.junit.Assert.*

/**
 * Tests explicit crit (critical) header consumption registration via
 * JwtParserBuilder.criticalHandler(String, CriticalHandler).
 *
 * Three example protected headers are exercised:
 *   1. {"alg":"HS256","crit":["x"],"x":"1"}     - unknown extension (rejected before claims)
 *                                                 or registered handler (accepted)
 *   2. {"alg":"HS256","crit":["x","x"],"x":"1"} - duplicate crit entries: structural error
 *   3. {"alg":"HS256","crit":["x"]}             - crit name without associated header value
 *
 * All keys are generated in-memory by the test itself; no key files, key stores or
 * external providers are used.
 *
 * Run locally from the repository root with JUnit via:
 *   ./mvnw -pl impl -am test -Dtest=CriticalHeaderHandlerTest -Dsurefire.failIfNoSpecifiedTests=false
 */
class CriticalHeaderHandlerTest {

    /**
     * Counts claims deserialization callbacks.  The first deserialization during a parse is
     * always the protected header; anything after that is claims (business) processing.
     */
    private static class CountingDeserializer extends AbstractDeserializer<Map<String, ?>> {
        private final Deserializer<Map<String, ?>> delegate = Services.get(Deserializer)
        private int calls = 0
        int claimsCallbacks = 0

        @Override
        protected Map<String, ?> doDeserialize(Reader reader) {
            calls++
            Map<String, ?> result = delegate.deserialize(reader)
            if (calls > 1) {
                claimsCallbacks++
            }
            return result
        }
    }

    private static class RecordingHandler implements io.jsonwebtoken.CriticalHandler {
        int invocations = 0
        String name
        Object value

        @Override
        void validate(String name, Object value) {
            this.invocations++
            this.name = name
            this.value = value
        }
    }

    private static byte[] serialize(Map<String, ?> map) {
        def serializer = Services.get(Serializer)
        ByteArrayOutputStream out = new ByteArrayOutputStream(512)
        serializer.serialize(map, out)
        return out.toByteArray()
    }

    /** In-memory test key only; never read from or written to a file, key store or provider. */
    private static SecretKey newTestKey() {
        return Jwts.SIG.HS256.key().build()
    }

    private static String compact(Map<String, ?> header, String claimsJson, SecretKey key) {
        String h = Encoders.BASE64URL.encode(serialize(header))
        String p = Encoders.BASE64URL.encode(Strings.utf8(claimsJson))
        String data = h + '.' + p
        Mac mac = Mac.getInstance('HmacSHA256')
        mac.init(key)
        return data + '.' + Encoders.BASE64URL.encode(mac.doFinal(Strings.utf8(data)))
    }

    // Example header 1: {"alg":"HS256","crit":["x"],"x":"1"} with no registered handler
    @Test
    void testUnknownCritRejectedBeforeClaims() {
        SecretKey key = newTestKey()
        String jws = compact([alg: 'HS256', crit: ['x'], x: '1'], '{"sub":"joe"}', key)
        def deserializer = new CountingDeserializer()
        try {
            Jwts.parser().verifyWith(key).json(deserializer).build().parseSignedClaims(jws)
            fail()
        } catch (UnsupportedJwtException expected) {
            String msg = expected.message
            assertTrue msg.contains("'x'")
            // errors must not leak the raw token or key material:
            assertFalse msg.contains(jws)
            assertFalse msg.contains(Encoders.BASE64URL.encode(key.encoded))
        }
        assertEquals 0, deserializer.claimsCallbacks // claims were never processed
    }

    // Example header 1 with a registered handler: the extension is understood, parsing succeeds
    @Test
    void testRegisteredCritHandlerConsumesHeader() {
        SecretKey key = newTestKey()
        String jws = compact([alg: 'HS256', crit: ['x'], x: '1'], '{"sub":"joe"}', key)
        def deserializer = new CountingDeserializer()
        def handler = new RecordingHandler()
        def jwt = Jwts.parser().verifyWith(key).json(deserializer)
                .criticalHandler('x', handler)
                .build().parseSignedClaims(jws)
        assertEquals 1, handler.invocations
        assertEquals 'x', handler.name
        assertEquals '1', handler.value
        assertEquals 1, deserializer.claimsCallbacks
        assertEquals 'joe', jwt.payload.getSubject()
    }

    // Example header 2: {"alg":"HS256","crit":["x","x"],"x":"1"} - duplicate crit entries
    @Test
    void testDuplicateCritRejectedAsStructuralError() {
        SecretKey key = newTestKey()
        String jws = compact([alg: 'HS256', crit: ['x', 'x'], x: '1'], '{"sub":"joe"}', key)
        def deserializer = new CountingDeserializer()
        def handler = new RecordingHandler()
        try {
            Jwts.parser().verifyWith(key).json(deserializer)
                    .criticalHandler('x', handler)
                    .build().parseSignedClaims(jws)
            fail()
        } catch (MalformedJwtException expected) {
            assertTrue expected.message.contains('duplicate')
            assertFalse expected.message.contains(jws)
        }
        assertEquals 0, handler.invocations
        assertEquals 0, deserializer.claimsCallbacks
    }

    // Example header 3: {"alg":"HS256","crit":["x"]} - crit name without an associated header value
    @Test
    void testCritNameWithoutHeaderValueRejected() {
        SecretKey key = newTestKey()
        String jws = compact([alg: 'HS256', crit: ['x']], '{"sub":"joe"}', key)
        def deserializer = new CountingDeserializer()
        def handler = new RecordingHandler()
        try {
            Jwts.parser().verifyWith(key).json(deserializer)
                    .criticalHandler('x', handler)
                    .build().parseSignedClaims(jws)
            fail()
        } catch (MalformedJwtException expected) {
            assertTrue expected.message.contains("'x'")
            assertFalse expected.message.contains(jws)
        }
        assertEquals 0, handler.invocations
        assertEquals 0, deserializer.claimsCallbacks
    }

    // The original lenient name-only configuration is retained:
    @Test
    void testLenientCriticalConfigurationStillSupported() {
        SecretKey key = newTestKey()
        String jws = compact([alg: 'HS256', crit: ['x'], x: '1'], '{"sub":"joe"}', key)
        def jwt = Jwts.parser().verifyWith(key).critical().add('x').and().build().parseSignedClaims(jws)
        assertEquals 'joe', jwt.payload.getSubject()
        assertEquals '1', jwt.header.get('x')
    }

    @Test
    void testHandlerJwtExceptionPropagatesBeforeClaims() {
        SecretKey key = newTestKey()
        String jws = compact([alg: 'HS256', crit: ['x'], x: '1'], '{"sub":"joe"}', key)
        def deserializer = new CountingDeserializer()
        try {
            Jwts.parser().verifyWith(key).json(deserializer)
                    .criticalHandler('x', { name, value -> throw new JwtException('no') })
                    .build().parseSignedClaims(jws)
            fail()
        } catch (JwtException expected) {
            assertEquals 'no', expected.message
        }
        assertEquals 0, deserializer.claimsCallbacks
    }

    @Test
    void testHandlerRuntimeExceptionWrappedBeforeClaims() {
        SecretKey key = newTestKey()
        String jws = compact([alg: 'HS256', crit: ['x'], x: '1'], '{"sub":"joe"}', key)
        def deserializer = new CountingDeserializer()
        try {
            Jwts.parser().verifyWith(key).json(deserializer)
                    .criticalHandler('x', { name, value -> throw new IllegalStateException('boom') })
                    .build().parseSignedClaims(jws)
            fail()
        } catch (JwtException expected) {
            assertTrue expected.message.contains('boom')
            assertTrue expected.cause instanceof IllegalStateException
        }
        assertEquals 0, deserializer.claimsCallbacks
    }

    @Test
    void testCriticalHandlerBuilderValidation() {
        try {
            Jwts.parser().criticalHandler(' ', { name, value -> })
            fail()
        } catch (IllegalArgumentException expected) {
        }
        try {
            Jwts.parser().criticalHandler('x', null)
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }
}
