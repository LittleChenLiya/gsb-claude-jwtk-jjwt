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

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.SignatureException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.DefaultJwsHeader
import io.jsonwebtoken.security.SecurityException
import org.junit.Test

import static org.junit.Assert.*

/**
 * Tests the explicit key locator contract: kid only locates candidates, key type and allowed
 * algorithms must both match, ambiguity is rejected, disabled algorithms never reach verification,
 * failures never fall back to weaker/other algorithms, and receipts contain only the selection category.
 */
class ExplicitKeyLocatorTest {

    // ==============================================================================================
    // Ambiguity: two candidates with the same kid (even of different types) must be rejected
    // ==============================================================================================

    @Test
    void testSameKidDifferentTypeCandidatesRejected() {
        def secret = Jwts.SIG.HS256.key().build()
        def rsaPair = Jwts.SIG.RS256.keyPair().build()
        def locator = ExplicitKeyLocator.builder()
                .add('shared', secret, 'HS256')
                .add('shared', rsaPair.public, 'RS256')
                .build()
        String jws = Jwts.builder().subject('joe').header().keyId('shared').and()
                .signWith(secret, Jwts.SIG.HS256).compact()
        try {
            Jwts.parser().keyLocator(locator).build().parseSignedClaims(jws)
            fail('Ambiguous kid must be rejected')
        } catch (SecurityException expected) {
            assertTrue expected.message.contains('Ambiguous')
            assertTrue expected.message.contains("'shared'")
            assertFalse 'token must not be printed', expected.message.contains(jws)
        }
        assertNull 'no selection receipt on rejection', locator.lastSelection
    }

    @Test
    void testSameKidAmbiguityRejectedAtLocateTime() {
        def secret = Jwts.SIG.HS256.key().build()
        def rsaPair = Jwts.SIG.RS256.keyPair().build()
        def locator = ExplicitKeyLocator.builder()
                .add('dup', secret, 'HS256')
                .add('dup', rsaPair.public, 'RS256')
                .build()
        try {
            locator.locate(new DefaultJwsHeader([alg: 'HS256', kid: 'dup']))
            fail('Ambiguous kid must be rejected')
        } catch (SecurityException expected) {
            assertTrue expected.message.contains('Ambiguous')
        }
    }

    // ==============================================================================================
    // Disabled algorithms never enter signature verification
    // ==============================================================================================

    @Test
    void testDisabledAlgorithmNeverVerified() {
        def key = Jwts.SIG.HS384.key().build() // strong enough for both HS256 and HS384
        def locator = ExplicitKeyLocator.of('k1', key, 'HS256') // HS384 intentionally NOT allowed
        String jws = Jwts.builder().subject('joe').header().keyId('k1').and()
                .signWith(key, Jwts.SIG.HS384).compact()
        try {
            Jwts.parser().keyLocator(locator).build().parseSignedClaims(jws)
            fail('A disabled algorithm must be rejected before verification')
        } catch (SecurityException expected) {
            assertTrue expected.message.contains('HS384')
            assertTrue expected.message.contains('not permitted')
            assertFalse 'token must not be printed', expected.message.contains(jws)
        }
        assertEquals 'locator consulted exactly once, no retries', 1, locator.locateCount
        assertNull 'rejected before any selection', locator.lastSelection
    }

    // ==============================================================================================
    // Happy path: valid in-memory key verifies; receipt contains only the selection category
    // ==============================================================================================

    @Test
    void testValidInMemoryKeyVerifies() {
        def key = Jwts.SIG.HS256.key().build()
        def locator = ExplicitKeyLocator.of('k1', key, 'HS256')
        String jws = Jwts.builder().subject('joe').header().keyId('k1').and()
                .signWith(key, Jwts.SIG.HS256).compact()
        def parsed = Jwts.parser().keyLocator(locator).build().parseSignedClaims(jws)
        assertEquals 'joe', parsed.payload.getSubject()
        assertEquals KeyCategory.OCT, locator.lastSelection.category
        assertEquals 'KeySelection{category=OCT}', locator.lastSelection.toString()
        assertFalse 'receipt must not contain the token', locator.lastSelection.toString().contains(jws)
        assertFalse 'receipt must not contain key material',
                locator.lastSelection.toString().contains(key.encoded.encodeBase64().toString())
    }

    @Test
    void testValidEcKeyVerifiesWithEcCategory() {
        def pair = Jwts.SIG.ES256.keyPair().build()
        def locator = ExplicitKeyLocator.of('ec1', pair.public, 'ES256')
        String jws = Jwts.builder().subject('joe').header().keyId('ec1').and()
                .signWith(pair.private, Jwts.SIG.ES256).compact()
        def parsed = Jwts.parser().keyLocator(locator).build().parseSignedClaims(jws)
        assertEquals 'joe', parsed.payload.getSubject()
        assertEquals KeyCategory.EC, locator.lastSelection.category
    }

    // ==============================================================================================
    // Verification failure: no guessing, no fallback to other (weaker) algorithms
    // ==============================================================================================

    @Test
    void testVerificationFailureDoesNotFallBack() {
        def expected = Jwts.SIG.HS256.key().build()
        def attacker = Jwts.SIG.HS256.key().build()
        // candidate allows two algorithms; a fallback implementation might try the other one:
        def locator = ExplicitKeyLocator.of('k1', expected, 'HS256', 'HS384')
        String jws = Jwts.builder().subject('joe').header().keyId('k1').and()
                .signWith(attacker, Jwts.SIG.HS256).compact()
        try {
            Jwts.parser().keyLocator(locator).build().parseSignedClaims(jws)
            fail('Invalid signature must be rejected')
        } catch (SignatureException expectedException) {
            // expected: signature invalid, and no other algorithm is attempted
        }
        assertEquals 'exactly one location attempt; no algorithm guessing or fallback', 1, locator.locateCount
    }

    @Test
    void testForgedHeaderAlgorithmDowngradeRejected() {
        // attacker forges the header to claim an algorithm the candidate does not allow:
        def key = Jwts.SIG.HS384.key().build()
        def locator = ExplicitKeyLocator.of('k1', key, 'HS384') // only HS384 allowed
        String jws = Jwts.builder().subject('joe').header().keyId('k1').and()
                .signWith(key, Jwts.SIG.HS256).compact()
        try {
            Jwts.parser().keyLocator(locator).build().parseSignedClaims(jws)
            fail('Header-declared downgrade algorithm must be rejected')
        } catch (SecurityException expected) {
            assertTrue expected.message.contains('HS256')
            assertTrue expected.message.contains('not permitted')
        }
        assertEquals 1, locator.locateCount
    }

    // ==============================================================================================
    // Key type and allowed algorithms must match together
    // ==============================================================================================

    @Test
    void testMismatchedKeyTypeAndAlgorithmRejectedAtRegistration() {
        def rsaPair = Jwts.SIG.RS256.keyPair().build()
        try {
            ExplicitKeyLocator.builder().add('k1', rsaPair.public, 'HS256').build()
            fail('An RSA key must not be registered for an HMAC algorithm')
        } catch (IllegalArgumentException expected) {
            assertTrue expected.message.contains('OCT')
            assertTrue expected.message.contains('RSA')
        }
    }

    @Test
    void testUnknownKidYieldsStandardUnableToLocateFailure() {
        def key = Jwts.SIG.HS256.key().build()
        def locator = ExplicitKeyLocator.of('k1', key, 'HS256')
        String jws = Jwts.builder().subject('joe').header().keyId('unknown').and()
                .signWith(key, Jwts.SIG.HS256).compact()
        try {
            Jwts.parser().keyLocator(locator).build().parseSignedClaims(jws)
            fail('Unknown kid must fail')
        } catch (UnsupportedJwtException expected) {
            assertTrue expected.message.contains('unable to locate')
        }
        assertNull locator.lastSelection
    }

    @Test
    void testMissingAlgRejected() {
        def key = Jwts.SIG.HS256.key().build()
        def locator = ExplicitKeyLocator.of('k1', key, 'HS256')
        try {
            locator.locate(new DefaultJwsHeader([kid: 'k1']))
            fail('Missing alg must be rejected')
        } catch (MalformedJwtException expected) {
            assertTrue expected.message.contains('alg')
        }
    }

    // ==============================================================================================
    // Default single-key interfaces remain intact
    // ==============================================================================================

    @Test
    void testDefaultSingleKeyInterfacesPreserved() {
        def key = Jwts.SIG.HS256.key().build()
        String jws = Jwts.builder().subject('joe').signWith(key, Jwts.SIG.HS256).compact()

        // the parser's existing single-key API is untouched:
        assertEquals 'joe', Jwts.parser().verifyWith(key).build().parseSignedClaims(jws).payload.getSubject()

        // and the locator's own single-key convenience works for tokens without a kid:
        def locator = ExplicitKeyLocator.of(key, 'HS256')
        assertEquals 'joe', Jwts.parser().keyLocator(locator).build().parseSignedClaims(jws).payload.getSubject()
        assertEquals KeyCategory.OCT, locator.lastSelection.category
    }

    // ==============================================================================================
    // KeyCategory mapping
    // ==============================================================================================

    @Test
    void testKeyCategoryMapping() {
        assertSame KeyCategory.OCT, KeyCategory.forJwsAlgorithm('HS256')
        assertSame KeyCategory.RSA, KeyCategory.forJwsAlgorithm('RS256')
        assertSame KeyCategory.RSA, KeyCategory.forJwsAlgorithm('PS256')
        assertSame KeyCategory.EC, KeyCategory.forJwsAlgorithm('ES256')
        assertSame KeyCategory.OKP, KeyCategory.forJwsAlgorithm('EdDSA')
        try {
            KeyCategory.forJwsAlgorithm('none')
            fail('Unrecognized algorithms must be rejected, not guessed')
        } catch (SecurityException expected) {
            assertTrue expected.message.contains('none')
        }
    }
}
