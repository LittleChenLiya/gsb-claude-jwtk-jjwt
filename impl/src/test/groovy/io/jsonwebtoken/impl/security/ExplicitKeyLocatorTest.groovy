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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.Header
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Locator
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import javax.crypto.SecretKey
import java.security.Key
import java.util.concurrent.atomic.AtomicInteger

import static org.junit.Assert.*

/**
 * Tests the explicit key locator contract: kid is used for candidate location only, key type and
 * allowed algorithms must both match, ambiguity is rejected, disabled algorithms never reach
 * verification, verification failure never falls back to weaker algorithms, no disk key loading,
 * and receipts contain only the selection category.
 */
class ExplicitKeyLocatorTest {

    private static final SecretKey HMAC_KEY = Jwts.SIG.HS512.key().build()
    private static final RSA_PUB = TestKeys.RS256.pair.public
    private static final RSA_PRIV = TestKeys.RS256.pair.private
    private static final EC_PUB = TestKeys.ES256.pair.public
    private static final EC_PRIV = TestKeys.ES256.pair.private

    private static String hmacJwt(String kid, Object alg = Jwts.SIG.HS256) {
        def b = Jwts.builder().subject('joe')
        if (kid != null) b.header().keyId(kid).and()
        return b.signWith(HMAC_KEY, alg).compact()
    }

    private static String rsaJwt(String kid) {
        def b = Jwts.builder().subject('joe')
        if (kid != null) b.header().keyId(kid).and()
        return b.signWith(RSA_PRIV, Jwts.SIG.RS256).compact()
    }

    private static void assertTokenNotLeaked(String jwt, Throwable t) {
        while (t != null) {
            assertFalse("Exception message must not contain the JWT: ${t.message}",
                    t.message != null && t.message.contains(jwt))
            t = t.cause
        }
    }

    @Test
    void validInMemoryKeyVerifies() {
        def locator = ExplicitKeyLocator.of(HMAC_KEY, 'HS256')
        String jwt = hmacJwt(null)
        def jws = Jwts.parser().keyLocator(locator).build().parseSignedClaims(jwt)
        assertEquals 'joe', jws.payload.getSubject()
        // receipt contains only the selection category:
        assertEquals KeySelection.Category.HMAC, locator.lastSelection.category
        assertEquals 'KeySelection[category=HMAC]', locator.lastSelection.toString()
        assertFalse locator.lastSelection.toString().contains(jwt)
    }

    @Test
    void validAsymmetricInMemoryKeyVerifiesByKid() {
        def locator = ExplicitKeyLocator.builder()
                .add('rsa-1', RSA_PUB, 'RS256')
                .add('ec-1', EC_PUB, 'ES256')
                .build()
        String jwt = Jwts.builder().subject('joe').header().keyId('ec-1').and()
                .signWith(EC_PRIV, Jwts.SIG.ES256).compact()
        def jws = Jwts.parser().keyLocator(locator).build().parseSignedClaims(jwt)
        assertEquals 'joe', jws.payload.getSubject()
        assertEquals KeySelection.Category.EC, locator.lastSelection.category
    }

    @Test
    void sameKidDifferentKeyTypesRejected() {
        def locator = ExplicitKeyLocator.builder()
                .add('shared', HMAC_KEY, 'HS256')
                .add('shared', RSA_PUB, 'RS256')
                .build()
        // An RSA token and an HMAC token both naming the ambiguous kid must both be rejected:
        [rsaJwt('shared'), hmacJwt('shared')].each { jwt ->
            try {
                Jwts.parser().keyLocator(locator).build().parseSignedClaims(jwt)
                fail('Ambiguous kid must be rejected')
            } catch (InvalidKeyException e) {
                assertTrue e.message.contains('Ambiguous')
                assertTokenNotLeaked(jwt, e)
            }
        }
        assertNull locator.lastSelection
    }

    @Test
    void disabledAlgorithmNeverReachesVerification() {
        // Only HS256 is allowed for this key:
        def locator = ExplicitKeyLocator.builder().add('h', HMAC_KEY, 'HS256').build()
        // The token carries a *valid* HS384 signature for the same key; if the disabled
        // algorithm were allowed to reach verification, parsing would succeed:
        String jwt = hmacJwt('h', Jwts.SIG.HS384)
        try {
            Jwts.parser().keyLocator(locator).build().parseSignedClaims(jwt)
            fail('Disabled algorithm must not enter verification')
        } catch (InvalidKeyException e) {
            assertTrue e.message.contains('not permitted')
            assertTokenNotLeaked(jwt, e)
        }
        assertNull locator.lastSelection
    }

    @Test
    void keyTypeMustMatchAlgorithmFamily() {
        // Candidate is an HMAC secret (mis)registered with an RSA algorithm in its allow-list;
        // the allow-list matches but the key type does not, so selection must still fail:
        def locator = ExplicitKeyLocator.builder().add('k', HMAC_KEY, 'RS256').build()
        String jwt = rsaJwt('k')
        try {
            Jwts.parser().keyLocator(locator).build().parseSignedClaims(jwt)
            fail('Key type / algorithm family mismatch must be rejected')
        } catch (InvalidKeyException e) {
            assertTrue e.message.contains('does not match')
            assertTokenNotLeaked(jwt, e)
        }
        assertNull locator.lastSelection
    }

    @Test
    void unknownKidRejected() {
        def locator = ExplicitKeyLocator.builder().add('known', HMAC_KEY, 'HS256').build()
        String jwt = hmacJwt('unknown')
        try {
            Jwts.parser().keyLocator(locator).build().parseSignedClaims(jwt)
            fail('Unknown kid must be rejected')
        } catch (InvalidKeyException e) {
            assertTrue e.message.contains('No key candidate')
            assertTokenNotLeaked(jwt, e)
        }
    }

    @Test
    void verificationFailureDoesNotRetryOrFallback() {
        def locator = ExplicitKeyLocator.builder().add('h', HMAC_KEY, 'HS256', 'HS384', 'HS512').build()
        def calls = new AtomicInteger(0)
        Locator<Key> counting = new Locator<Key>() {
            @Override
            Key locate(Header header) {
                calls.incrementAndGet()
                return locator.locate(header)
            }
        }
        String jwt = hmacJwt('h')
        // Corrupt the signature (keep it valid base64url so decoding still works):
        int i = jwt.lastIndexOf('.')
        char last = jwt.charAt(jwt.length() - 1)
        String tampered = jwt.substring(0, jwt.length() - 1) + (last == 'a' ? 'b' : 'a')
        assert i > 0 && tampered != jwt
        try {
            Jwts.parser().keyLocator(counting).build().parseSignedClaims(tampered)
            fail('Tampered signature must be rejected')
        } catch (SignatureException e) {
            assertTokenNotLeaked(tampered, e)
        }
        // Exactly one key location and exactly one verification attempt with the header alg;
        // no guessing of other (weaker) algorithms:
        assertEquals 1, calls.get()
    }

    @Test
    void defaultSingleKeyInterfacesRetained() {
        String jwt = hmacJwt(null)
        // The parser default single-key verifyWith API is unaffected:
        def jws = Jwts.parser().verifyWith(HMAC_KEY).build().parseSignedClaims(jwt)
        assertEquals 'joe', jws.payload.getSubject()
        // The locator default single-key factory works without any kid:
        def locator = ExplicitKeyLocator.of(HMAC_KEY, 'HS256')
        jws = Jwts.parser().keyLocator(locator).build().parseSignedClaims(jwt)
        assertEquals 'joe', jws.payload.getSubject()
        assertEquals KeySelection.Category.HMAC, locator.lastSelection.category
    }

    @Test
    void privateKeysRejected() {
        try {
            ExplicitKeyLocator.builder().add('k', RSA_PRIV, 'RS256')
            fail('Private keys must not be registrable as verification keys')
        } catch (InvalidKeyException expected) {
        }
    }

    @Test
    void noDiskKeyLoadingApi() {
        // Parsing must not read key files from disk: the locator only accepts in-memory
        // java.security.Key instances and exposes no file/path/stream/URL based API.
        def forbidden = [java.io.File, java.nio.file.Path, java.io.InputStream,
                         java.io.Reader, java.net.URL, java.net.URI]
        [ExplicitKeyLocator, ExplicitKeyLocator.Builder].each { clazz ->
            clazz.declaredMethods.each { m ->
                m.parameterTypes.each { p ->
                    assertFalse("No disk/stream API allowed: ${m}", forbidden.contains(p))
                }
            }
            clazz.declaredConstructors.each { c ->
                c.parameterTypes.each { p ->
                    assertFalse("No disk/stream API allowed: ${c}", forbidden.contains(p))
                }
            }
        }
    }
}
