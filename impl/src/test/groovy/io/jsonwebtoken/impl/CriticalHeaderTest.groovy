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

import io.jsonwebtoken.Claims
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.SigningKeyResolverAdapter
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import javax.crypto.Mac
import javax.crypto.SecretKey
import java.security.Key
import java.util.concurrent.atomic.AtomicInteger

import static org.junit.Assert.*

/**
 * Tests the JwtParser's explicit critical header (crit) consumer registration:
 *
 * - every name listed in a JWT's crit header must have been explicitly registered as understood
 *   (via JwtParserBuilder.critical()); a name that merely exists in the header is not sufficient
 * - unknown, duplicate, and value-less crit names are each rejected, before any business claims
 *   are processed (claims callbacks remain at zero)
 * - rejection messages never contain the raw token, its header content, or any key material
 *
 * All keys are generated in-memory by the test provider; nothing is read from or written to disk.
 */
class CriticalHeaderTest {

    /** In-memory test key only (generated per test run, never persisted). */
    private static final SecretKey KEY = Jwts.SIG.HS256.key().build()

    // The three header examples under test:
    private static final String CRIT_X_HEADER = '{"alg":"HS256","crit":["x"],"x":42}'
    private static final String DUPLICATE_CRIT_HEADER = '{"alg":"HS256","crit":["x","x"],"x":42}'
    private static final String MISSING_VALUE_CRIT_HEADER = '{"alg":"HS256","crit":["y"]}'

    private static final String PAYLOAD = '{"sub":"joe"}'

    /** Creates a signed compact JWS from a raw header JSON string (allows structures builders cannot produce). */
    private static String jws(String headerJson, String payloadJson = PAYLOAD) {
        String input = Encoders.BASE64URL.encode(Strings.utf8(headerJson)) + '.' +
                Encoders.BASE64URL.encode(Strings.utf8(payloadJson))
        Mac mac = Mac.getInstance(KEY.getAlgorithm())
        mac.init(KEY)
        return input + '.' + Encoders.BASE64URL.encode(mac.doFinal(Strings.utf8(input)))
    }

    /** Counts key resolver callbacks to prove business claims are never processed when crit validation fails. */
    private static final class CountingKeyResolver extends SigningKeyResolverAdapter {
        private final AtomicInteger claimsCallbacks = new AtomicInteger()
        private final AtomicInteger contentCallbacks = new AtomicInteger()

        @Override
        Key resolveSigningKey(JwsHeader header, Claims claims) {
            claimsCallbacks.incrementAndGet()
            return KEY
        }

        @Override
        Key resolveSigningKey(JwsHeader header, byte[] content) {
            contentCallbacks.incrementAndGet()
            return KEY
        }
    }

    /** Asserts an error message does not leak the raw token, its header content, or any key material. */
    private static void assertNoLeak(String msg, String compact) {
        assertFalse msg.contains(compact)
        assertFalse msg.contains('x=42') // parsed header map content
        assertFalse msg.contains('"x":42') // raw header JSON content
        assertFalse msg.contains(Encoders.BASE64URL.encode(KEY.getEncoded()))
        assertFalse msg.contains(Encoders.BASE64.encode(KEY.getEncoded()))
    }

    @Test
    void testUnknownCriticalHeaderRejectedBeforeClaims() {
        // 'x' exists in the header, but has NOT been registered as understood: must be rejected
        def resolver = new CountingKeyResolver()
        String compact = jws(CRIT_X_HEADER)
        try {
            Jwts.parser().setSigningKeyResolver(resolver).build().parseSignedClaims(compact)
            fail()
        } catch (UnsupportedJwtException expected) {
            assertTrue expected.message.contains("'x'")
            assertNoLeak(expected.message, compact)
        }
        // rejected before claims processing: no claims (or any) key resolver callback fired
        assertEquals 0, resolver.claimsCallbacks.get()
        assertEquals 0, resolver.contentCallbacks.get()
    }

    @Test
    void testRegisteredCriticalHeaderAccepted() {
        // same header as above, but now 'x' is explicitly registered: must be accepted
        String compact = jws(CRIT_X_HEADER)
        def jwt = Jwts.parser().critical().add('x').and().verifyWith(KEY).build().parseSignedClaims(compact)
        assertEquals 42, jwt.getHeader().get('x')
        assertEquals(['x'] as Set, jwt.getHeader().getCritical() as Set)
        assertEquals 'joe', jwt.getPayload().getSubject()
    }

    @Test
    void testDuplicateCriticalHeaderNamesRejectedAsStructuralError() {
        // 'x' is registered, but the crit array contains it twice: structural error
        def resolver = new CountingKeyResolver()
        String compact = jws(DUPLICATE_CRIT_HEADER)
        try {
            Jwts.parser().critical().add('x').and().setSigningKeyResolver(resolver).build()
                    .parseSignedClaims(compact)
            fail()
        } catch (MalformedJwtException expected) {
            assertTrue expected.message.contains('duplicate')
            assertTrue expected.message.contains("'x'")
            assertNoLeak(expected.message, compact)
        }
        assertEquals 0, resolver.claimsCallbacks.get()
        assertEquals 0, resolver.contentCallbacks.get()
    }

    @Test
    void testCriticalHeaderNameWithoutValueRejected() {
        // 'y' is registered and listed in crit, but the header has no associated 'y' parameter
        def resolver = new CountingKeyResolver()
        String compact = jws(MISSING_VALUE_CRIT_HEADER)
        try {
            Jwts.parser().critical().add('y').and().setSigningKeyResolver(resolver).build()
                    .parseSignedClaims(compact)
            fail()
        } catch (MalformedJwtException expected) {
            assertTrue expected.message.contains("'y'")
            assertNoLeak(expected.message, compact)
        }
        assertEquals 0, resolver.claimsCallbacks.get()
        assertEquals 0, resolver.contentCallbacks.get()
    }

    @Test
    void testBlankCriticalHeaderNameRejectedAsStructuralError() {
        String compact = jws('{"alg":"HS256","crit":[""],"":1}')
        try {
            Jwts.parser().critical().add('x').and().verifyWith(KEY).build().parseSignedClaims(compact)
            fail()
        } catch (MalformedJwtException expected) {
            assertNoLeak(expected.message, compact)
        }
    }

    @Test
    void testHeaderValidatedBeforeBusinessClaims() {
        // token has both an unknown crit header AND expired claims; the header error must be reported first
        String compact = jws(CRIT_X_HEADER, '{"sub":"joe","exp":1}')
        try {
            Jwts.parser().verifyWith(KEY).build().parseSignedClaims(compact)
            fail()
        } catch (UnsupportedJwtException expected) {
            // expected: crit (header) validation occurs before claims (exp) validation
            assertNoLeak(expected.message, compact)
        }
    }
}
