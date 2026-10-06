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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.UnsupportedKeyException;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Locale;

/**
 * Classification of a {@link Key} (or a JWS algorithm's required key) into a JOSE key family
 * (<a href="https://www.rfc-editor.org/rfc/rfc7518#section-6.1">RFC 7518, Section 6.1</a> {@code kty} value).
 * Used by the {@link ExplicitKeyLocator} to ensure a JWT header's {@code alg} value and the final located
 * key are of the same family; a header can never force a key to be used with an algorithm family it does
 * not belong to (no algorithm downgrade or confusion).
 *
 * @since 0.14.0
 */
public enum KeyCategory {

    /**
     * Symmetric (secret) keys, JOSE {@code kty} value {@code oct}. Required by {@code HS*} JWS algorithms.
     */
    OCT,

    /**
     * RSA asymmetric keys, JOSE {@code kty} value {@code RSA}. Required by {@code RS*} and {@code PS*} JWS algorithms.
     */
    RSA,

    /**
     * Elliptic Curve asymmetric keys, JOSE {@code kty} value {@code EC}. Required by {@code ES*} JWS algorithms.
     */
    EC,

    /**
     * Edwards-curve / Octet Key Pair asymmetric keys, JOSE {@code kty} value {@code OKP}. Required by the
     * {@code EdDSA} JWS algorithm.
     */
    OKP;

    /**
     * Returns the category of the specified key, never {@code null}.
     *
     * @param key the key to classify
     * @return the key's category
     * @throws UnsupportedKeyException if the key's category cannot be determined
     */
    public static KeyCategory of(Key key) {
        Assert.notNull(key, "Key cannot be null.");
        if (key instanceof SecretKey) {
            return OCT;
        }
        if (key instanceof RSAKey) {
            return RSA;
        }
        if (key instanceof ECKey) {
            return EC;
        }
        String jca = key.getAlgorithm();
        if (Strings.hasText(jca)) {
            String name = jca.toUpperCase(Locale.ENGLISH);
            if (name.startsWith("ED")) { // EdDSA, Ed25519, Ed448
                return OKP;
            }
        }
        throw new UnsupportedKeyException("Unable to determine key category for key of type " +
                key.getClass().getName() + " with algorithm '" + jca + "'.");
    }

    /**
     * Returns the key category required by the specified JWS {@code alg} header value.  This is an explicit
     * allow-list mapping; unrecognized algorithms are rejected instead of being guessed.
     *
     * @param jwsAlgorithm the JWS {@code alg} header value (for example {@code HS256}, {@code RS256},
     *                     {@code ES256} or {@code EdDSA})
     * @return the key category required by the specified algorithm
     * @throws SecurityException if the algorithm is null, empty, or not a recognized JWS algorithm family
     */
    public static KeyCategory forJwsAlgorithm(String jwsAlgorithm) throws SecurityException {
        if (Strings.hasText(jwsAlgorithm)) {
            String alg = jwsAlgorithm.trim();
            if (alg.startsWith("HS")) {
                return OCT;
            }
            if (alg.startsWith("RS") || alg.startsWith("PS")) {
                return RSA;
            }
            if (alg.startsWith("ES")) {
                return EC;
            }
            if ("EdDSA".equals(alg)) {
                return OKP;
            }
        }
        throw new SecurityException("Unrecognized JWS algorithm '" + jwsAlgorithm +
                "': unable to determine the required key category. Refusing to guess an algorithm family.");
    }
}
