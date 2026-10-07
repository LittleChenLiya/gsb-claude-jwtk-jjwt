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

import io.jsonwebtoken.JwtParser
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.gson.io.GsonDeserializer
import io.jsonwebtoken.impl.io.DuplicateClaimException
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import javax.crypto.Mac
import javax.crypto.SecretKey

import static org.junit.Assert.*

/**
 * Tests for {@link io.jsonwebtoken.JwtParserBuilder#strictDuplicateClaimDetection()}: signed JWTs
 * (HS256) with hand-crafted payloads containing duplicate top-level and nested JSON object member
 * names must be rejected with the duplicate key path and position reported, valid tokens must
 * continue to parse and verify, and parsers without the option must retain the default
 * "last value wins" behavior.
 */
class StrictDuplicateClaimDetectionTest {

    private static final SecretKey KEY = Jwts.SIG.HS256.key().build()

    private static final String HEADER = '{"alg":"HS256"}'

    private static final String DUP_TOP_LEVEL = '{"sub":"alice","iss":"jwt.io","sub":"bob"}'

    private static final String DUP_NESTED = '{"sub":"alice","nested":{"a":1,"a":2}}'

    private static final String DUP_IN_ARRAY = '{"items":[{"k":1},{"k":2,"k":3}]}'

    private static final String VALID =
            '{"sub":"alice","iss":"jwt.io","nested":{"a":1,"b":[true,{"c":"x"}]},"roles":["admin","user"]}'

    /**
     * Creates a compact JWS from the specified raw JSON documents, signing with HS256.  This is
     * necessary because {@link io.jsonwebtoken.JwtBuilder} (correctly) cannot produce duplicate
     * JSON object member names.
     */
    private static String jws(String headerJson, String payloadJson) {
        String header = Encoders.BASE64URL.encode(headerJson.getBytes(Strings.UTF_8))
        String body = Encoders.BASE64URL.encode(payloadJson.getBytes(Strings.UTF_8))
        String content = header + '.' + body // JWS Signing Input per RFC 7515, Section 5.1
        Mac mac = Mac.getInstance('HmacSHA256')
        mac.init(KEY)
        return content + '.' + Encoders.BASE64URL.encode(mac.doFinal(content.getBytes(Strings.UTF_8)))
    }

    private static JwtParser strictParser() {
        return Jwts.parser().verifyWith(KEY).strictDuplicateClaimDetection().build()
    }

    private static DuplicateClaimException expectDuplicate(String jws) {
        try {
            strictParser().parseSignedClaims(jws)
            fail('Expected DuplicateClaimException for JWS: ' + jws)
        } catch (DuplicateClaimException e) {
            return e
        }
        return null // unreachable
    }

    @Test
    void testValidSignedTokenParsesWithStrictOptionEnabled() {
        // a legal payload (nested objects and arrays, no duplicate names) must parse and
        // pass signature verification exactly as before:
        def jws = jws(HEADER, VALID)
        def parsed = strictParser().parseSignedClaims(jws) // verifies signature, no exception
        assertEquals 'HS256', parsed.header.alg
        assertEquals 'alice', parsed.payload.getSubject()
        assertEquals 'jwt.io', parsed.payload.getIssuer()
        assertEquals 1, parsed.payload.get('nested').a
        assertEquals 'x', parsed.payload.get('nested').b[1].c
        assertEquals(['admin', 'user'], parsed.payload.get('roles'))
    }

    @Test
    void testDuplicateTopLevelClaimRejected() {
        def e = expectDuplicate(jws(HEADER, DUP_TOP_LEVEL))
        assertTrue e instanceof MalformedJwtException // exposed as a standard JWT exception type
        assertEquals "Duplicate JSON name 'sub' at path 'sub' in claims JSON (line 1, column 31). " +
                'Duplicate JSON Object member names are not allowed by this parser.', e.message
    }

    @Test
    void testDuplicateNestedClaimRejected() {
        def e = expectDuplicate(jws(HEADER, DUP_NESTED))
        assertTrue e.message, e.message.contains(
                "Duplicate JSON name 'a' at path 'nested.a' in claims JSON (line 1, column 32).")
    }

    @Test
    void testDuplicateClaimInArrayElementRejected() {
        def e = expectDuplicate(jws(HEADER, DUP_IN_ARRAY))
        assertTrue e.message, e.message.contains("at path 'items[1].k' in claims JSON (line 1, column 26).")
    }

    @Test
    void testDuplicateProtectedHeaderNameRejected() {
        def e = expectDuplicate(jws('{"alg":"HS256","alg":"HS256"}', VALID))
        assertTrue e.message, e.message.contains(
                "Duplicate JSON name 'alg' at path 'alg' in protected header JSON (line 1, column 16).")
    }

    @Test
    void testStrictOptionDisabledRetainsLastValueWins() {
        // option not enabled: duplicate names are not detected by the parser and the configured
        // JSON deserializer's default behavior applies, exactly as before this option existed.
        // (Gson, like most JSON libraries, applies 'last value wins' for duplicate names):
        def parser = Jwts.parser().verifyWith(KEY).json(new GsonDeserializer()).build()
        def parsed = parser.parseSignedClaims(jws(HEADER, DUP_TOP_LEVEL))
        assertEquals 'bob', parsed.payload.getSubject()
        assertEquals 'jwt.io', parsed.payload.getIssuer()

        parsed = parser.parseSignedClaims(jws(HEADER, DUP_NESTED))
        assertEquals 2, parsed.payload.get('nested').a
    }

    @Test
    void testStrictOptionIsDeserializerIndependent() {
        // even with a lenient JSON deserializer (Gson applies 'last value wins' natively), the
        // strict option must still reject duplicates with the full key path reported:
        def parser = Jwts.parser().verifyWith(KEY).json(new GsonDeserializer())
                .strictDuplicateClaimDetection().build()
        try {
            parser.parseSignedClaims(jws(HEADER, DUP_NESTED))
            fail('Expected DuplicateClaimException')
        } catch (DuplicateClaimException e) {
            assertTrue e.message, e.message.contains("at path 'nested.a' in claims JSON")
        }
    }

    @Test
    void testBuilderMethodChaining() {
        def builder = Jwts.parser().strictDuplicateClaimDetection()
        assertNotNull builder
        assertNotNull builder.verifyWith(KEY).build()
    }
}
