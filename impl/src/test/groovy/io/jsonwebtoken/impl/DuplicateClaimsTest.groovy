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

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.gson.io.GsonDeserializer
import io.jsonwebtoken.impl.io.DuplicateClaimException
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

/**
 * Tests for the {@code JwtParserBuilder#requireUniqueClaims()} strict duplicate claim detection option.
 *
 * @since 0.14.0
 */
class DuplicateClaimsTest {

    private static final SecretKey KEY = new SecretKeySpec(
            '0123456789abcdef0123456789abcdef'.getBytes(StandardCharsets.UTF_8), 'HmacSHA256')

    private static String b64Url(byte[] bytes) {
        return Encoders.BASE64URL.encode(bytes)
    }

    /**
     * Creates a compact JWS (HS256) with the exact raw payload JSON specified, allowing test payloads
     * that contain duplicate JSON object keys (which a Map-based JWT builder cannot produce).
     */
    private static String jws(String payloadJson) {
        String header = b64Url('{"alg":"HS256"}'.getBytes(StandardCharsets.UTF_8))
        String payload = b64Url(payloadJson.getBytes(StandardCharsets.UTF_8))
        String signingInput = header + '.' + payload
        Mac mac = Mac.getInstance('HmacSHA256')
        mac.init(KEY)
        String sig = b64Url(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)))
        return signingInput + '.' + sig
    }

    private static MalformedJwtException expectDuplicate(String jwt) {
        try {
            Jwts.parser().verifyWith(KEY).requireUniqueClaims().build().parseSignedClaims(jwt)
            fail('Expected a MalformedJwtException due to duplicate claims')
        } catch (MalformedJwtException e) {
            return e
        }
        return null // not reached
    }

    @Test
    void testStrictRejectsDuplicateTopLevelClaim() {
        String jwt = jws('{"sub":"alice","sub":"bob","ok":{"x":1}}')
        MalformedJwtException e = expectDuplicate(jwt)
        assertTrue e instanceof DuplicateClaimException
        // top-level duplicate path is the claim name itself:
        assertTrue e.message, e.message.contains("Duplicate key 'sub'")
        assertTrue e.message, e.message.contains("at path 'sub'")
    }

    @Test
    void testStrictRejectsDuplicateNestedClaimKey() {
        String jwt = jws('{"sub":"alice","user":{"role":"admin","role":"user"}}')
        MalformedJwtException e = expectDuplicate(jwt)
        // nested duplicate reports the full JSON path:
        assertTrue e.message, e.message.contains("Duplicate key 'role'")
        assertTrue e.message, e.message.contains("at path 'user.role'")
    }

    @Test
    void testStrictRejectsDuplicateKeyWithinArrayObject() {
        String jwt = jws('{"items":[{"id":1,"id":2}]}')
        MalformedJwtException e = expectDuplicate(jwt)
        assertTrue e.message, e.message.contains("at path 'items[0].id'")
    }

    @Test
    void testStrictAcceptsLegalSignedClaims() {
        // legal payload: nested objects and arrays, no duplicates; signature must verify as before:
        String jwt = jws('{"sub":"alice","user":{"role":"admin","tags":["a","b"]},"n":42,"ok":{"x":1}}')
        def jws = Jwts.parser().verifyWith(KEY).requireUniqueClaims().build().parseSignedClaims(jwt)
        assertEquals 'alice', jws.payload.getSubject()
        assertEquals 'admin', jws.payload.get('user').get('role')
        assertEquals 42, jws.payload.get('n')
    }

    @Test
    void testDefaultParserRetainsLastValueWins() {
        // strict option disabled (default): the configured deserializer's native behavior is preserved.
        // Gson applies 'last value wins' for duplicate keys, so parsing and signature verification
        // behave exactly as before this option existed:
        String jwt = jws('{"sub":"alice","sub":"bob","user":{"role":"a","role":"b"}}')
        def jws = Jwts.parser().verifyWith(KEY).json(new GsonDeserializer()).build().parseSignedClaims(jwt)
        assertEquals 'bob', jws.payload.getSubject()
        assertEquals 'b', jws.payload.get('user').get('role')
    }

    @Test
    void testDefaultParserBehaviorUnchanged() {
        // strict option disabled (default): JJWT's default Jackson deserializer already rejects duplicate
        // keys, and that failure is - as before - interpreted as 'payload is not claims JSON', so the JWS
        // is exposed as signed content rather than claims.  The strict option exists to reject such JWTs
        // explicitly with a useful key path instead:
        String jwt = jws('{"sub":"alice","sub":"bob"}')
        def jws = Jwts.parser().verifyWith(KEY).build().parseSignedContent(jwt)
        assertEquals '{"sub":"alice","sub":"bob"}', new String(jws.payload, StandardCharsets.UTF_8)
        try {
            Jwts.parser().verifyWith(KEY).build().parseSignedClaims(jwt)
            fail('Expected an UnsupportedJwtException for a content (non-claims) JWS')
        } catch (UnsupportedJwtException expected) {
            // default (non-strict) behavior is unchanged
        }
    }

    @Test
    void testStrictIgnoresNonJsonPayload() {
        // a non-JSON payload is opaque content, not claims; strict mode must not reject it:
        String jwt = jws('hello world')
        def jws = Jwts.parser().verifyWith(KEY).requireUniqueClaims().build().parseSignedContent(jwt)
        assertEquals 'hello world', new String(jws.payload, StandardCharsets.UTF_8)
    }

    @Test
    void testStrictStillVerifiesSignature() {
        // tampered payload (valid JSON, no duplicates) must still fail signature verification:
        String tampered = jws('{"sub":"alice"}')
        String payload = b64Url('{"sub":"mallory"}'.getBytes(StandardCharsets.UTF_8))
        tampered = tampered.substring(0, tampered.indexOf('.') + 1) + payload +
                tampered.substring(tampered.lastIndexOf('.'))
        try {
            Jwts.parser().verifyWith(KEY).requireUniqueClaims().build().parseSignedClaims(tampered)
            fail('Expected a SignatureException for a tampered payload')
        } catch (SignatureException expected) {
            // signature check is unchanged by the strict option
        }
    }

    @Test
    void testStrictRejectsDuplicateInUnsecuredJwt() {
        // duplicate detection applies to claims JSON regardless of whether the JWT is signed:
        String header = b64Url('{"alg":"none"}'.getBytes(StandardCharsets.UTF_8))
        String payload = b64Url('{"sub":"a","sub":"b"}'.getBytes(StandardCharsets.UTF_8))
        String jwt = header + '.' + payload + '.'
        try {
            Jwts.parser().unsecured().requireUniqueClaims().build().parseUnsecuredClaims(jwt)
            fail('Expected a MalformedJwtException due to duplicate claims')
        } catch (MalformedJwtException e) {
            assertTrue e.message, e.message.contains("at path 'sub'")
        }
    }
}
