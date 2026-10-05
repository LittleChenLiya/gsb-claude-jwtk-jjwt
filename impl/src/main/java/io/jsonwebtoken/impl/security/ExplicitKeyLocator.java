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

import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * An explicit key locator contract for JWS signature verification.
 *
 * <p>This locator enforces a strict, non-negotiable selection contract:</p>
 * <ul>
 *     <li><b>{@code kid} is used for candidate location only.</b>  A {@code kid} header value can only
 *     <em>find</em> candidate keys; it never authorizes a key or an algorithm by itself.</li>
 *     <li><b>Key type and allowed algorithms must match together.</b>  After a single candidate is found,
 *     the JWS {@code alg} header value must be in that candidate allow-list <em>and</em> the candidate
 *     key {@link KeySelection.Category type category} must match the {@code alg} family.  A JWT header
 *     can never force an arbitrary or downgraded algorithm onto a key.</li>
 *     <li><b>Ambiguity is rejected.</b>  If a {@code kid} resolves to more than one candidate (for example
 *     two keys of different types registered with the same {@code kid}), location fails instead of
 *     guessing.</li>
 *     <li><b>No algorithm fallback.</b>  Exactly one key is returned for exactly the {@code alg} named in
 *     the header.  If signature verification fails, neither this locator nor the parser retries with
 *     another (weaker) algorithm.</li>
 *     <li><b>In-memory keys only.</b>  Candidates are registered as {@link Key} instances.  This locator
 *     has no file, path, stream, or URL based API and never reads key material from disk while
 *     parsing.</li>
 *     <li><b>Category-only receipt.</b>  Each successful selection is recorded as a {@link KeySelection}
 *     receipt that exposes only the selection {@link KeySelection.Category category}, never key
 *     material, a {@code kid}, or token content.  Exception messages likewise never contain the JWT
 *     compact string.</li>
 * </ul>
 *
 * <p>The default single-key interface remains available via {@link #of(Key, String...)} (and the
 * parser {@code verifyWith} methods are unaffected).</p>
 *
 * @since 0.14.0
 */
public final class ExplicitKeyLocator extends LocatorAdapter<Key> {

    private static final String NONE = "none";

    /**
     * A registered key candidate: an in-memory key, its optional {@code kid}, and the exact set of
     * JWS algorithms it may be used with.
     */
    private static final class Candidate {
        private final String kid; // may be null
        private final Key key;
        private final KeySelection.Category category;
        private final Set<String> allowedAlgorithms;

        private Candidate(String kid, Key key, Set<String> allowedAlgorithms) {
            this.kid = kid;
            this.key = key;
            this.category = categoryOf(key);
            this.allowedAlgorithms = allowedAlgorithms;
        }
    }

    private final List<Candidate> candidates;
    private final AtomicReference<KeySelection> lastSelection = new AtomicReference<>();

    private ExplicitKeyLocator(List<Candidate> candidates) {
        Assert.notEmpty(candidates, "At least one key candidate is required.");
        this.candidates = Collections.unmodifiableList(new ArrayList<>(candidates));
    }

    /**
     * Creates the default single-key locator: one in-memory {@code key} usable only with the specified
     * allowed JWS algorithms.  The key has no {@code kid}; it is the only candidate, so it is selected
     * whenever its type and allow-list match the JWS {@code alg} header.
     *
     * @param key               the single in-memory verification key
     * @param allowedAlgorithms the exact JWS {@code alg} values permitted for the key
     * @return a new locator containing only the specified key
     */
    public static ExplicitKeyLocator of(Key key, String... allowedAlgorithms) {
        return builder().add(key, allowedAlgorithms).build();
    }

    /**
     * Returns a builder for registering multiple explicitly-typed key candidates.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the receipt of the most recent successful selection, or {@code null} if no selection has
     * been made yet.  The receipt contains only the selection {@link KeySelection.Category category}.
     *
     * @return the most recent selection receipt, or {@code null} if none has occurred.
     */
    public KeySelection getLastSelection() {
        return this.lastSelection.get();
    }

    @Override
    protected Key locate(JwsHeader header) {

        String alg = header.getAlgorithm();
        if (!Strings.hasText(alg) || NONE.equals(alg)) {
            throw new InvalidKeyException("JWS alg header is missing or not a signature algorithm; " +
                    "a key cannot be selected.");
        }
        KeySelection.Category algCategory = categoryOfAlg(alg);
        if (algCategory == null) {
            // Unknown algorithm family: never allowed to reach verification.
            throw new InvalidKeyException("JWS alg " + alg + " is not a supported signature algorithm.");
        }

        // 1. kid is used for candidate location ONLY:
        String kid = Strings.hasText(header.getKeyId()) ? header.getKeyId() : null;
        List<Candidate> matches = new ArrayList<>(1);
        for (Candidate c : this.candidates) {
            if (kid == null || kid.equals(c.kid)) {
                matches.add(c);
            }
        }

        // 2. Ambiguity (including the same kid registered for different key types) is rejected:
        if (matches.isEmpty()) {
            throw new InvalidKeyException("No key candidate found" +
                    (kid != null ? " for the specified kid" : "") +
                    "; signature verification cannot proceed.");
        }
        if (matches.size() > 1) {
            throw new InvalidKeyException("Ambiguous key location: more than one key candidate matches" +
                    (kid != null ? " the specified kid" : "") + "; refusing to select a key.");
        }

        // 3. Final selection requires BOTH the allow-list and the key type to match the header alg:
        Candidate candidate = matches.get(0);
        if (!candidate.allowedAlgorithms.contains(alg)) {
            // Disabled algorithm: rejected here, before any verification is attempted.
            throw new InvalidKeyException("JWS alg " + alg + " is not permitted for the located key.");
        }
        if (candidate.category != algCategory) {
            throw new InvalidKeyException("Located key type " + candidate.category +
                    " does not match JWS alg " + alg + " (" + algCategory + ").");
        }

        this.lastSelection.set(new KeySelection(candidate.category));
        return candidate.key;
    }

    private static KeySelection.Category categoryOfAlg(String alg) {
        if (alg.startsWith("HS")) return KeySelection.Category.HMAC;
        if (alg.startsWith("RS") || alg.startsWith("PS")) return KeySelection.Category.RSA;
        if (alg.startsWith("ES")) return KeySelection.Category.EC;
        if ("EdDSA".equals(alg)) return KeySelection.Category.EDWARDS;
        return null;
    }

    private static KeySelection.Category categoryOf(Key key) {
        Assert.notNull(key, "Key cannot be null.");
        if (key instanceof PrivateKey) {
            throw new InvalidKeyException("Private keys cannot be used for signature verification.");
        }
        if (key instanceof SecretKey) return KeySelection.Category.HMAC;
        if (key instanceof RSAPublicKey) return KeySelection.Category.RSA;
        if (key instanceof ECPublicKey) return KeySelection.Category.EC;
        String keyAlg = key.getAlgorithm();
        if (keyAlg != null) {
            if ("RSA".equals(keyAlg)) return KeySelection.Category.RSA;
            if ("EC".equals(keyAlg) || "ECDSA".equals(keyAlg)) return KeySelection.Category.EC;
            // EdDSA, Ed25519, Ed448 (EdECPublicKey cannot be referenced directly on Java 8):
            if (keyAlg.startsWith("Ed")) return KeySelection.Category.EDWARDS;
        }
        throw new InvalidKeyException("Unsupported verification key type: " + key.getClass().getName());
    }

    /**
     * Builds an {@link ExplicitKeyLocator} with explicitly registered in-memory key candidates.
     */
    public static final class Builder {

        private final List<Candidate> candidates = new ArrayList<>();

        private Builder() {
        }

        /**
         * Adds a candidate with no {@code kid}.  It participates in selection only when a JWS has no
         * {@code kid} header (or when it is the only candidate).
         *
         * @param key               the in-memory verification key
         * @param allowedAlgorithms the exact JWS {@code alg} values permitted for the key
         * @return this builder
         */
        public Builder add(Key key, String... allowedAlgorithms) {
            return add(null, key, allowedAlgorithms);
        }

        /**
         * Adds a candidate addressable by the specified {@code kid}.
         *
         * @param kid               the key id used for candidate location only; may be {@code null}
         * @param key               the in-memory verification key
         * @param allowedAlgorithms the exact JWS {@code alg} values permitted for the key
         * @return this builder
         */
        public Builder add(String kid, Key key, String... allowedAlgorithms) {
            Assert.notNull(key, "Key cannot be null.");
            Assert.notEmpty(allowedAlgorithms, "At least one allowed algorithm is required.");
            Set<String> allowed = new LinkedHashSet<>();
            for (String alg : allowedAlgorithms) {
                Assert.hasText(alg, "Allowed algorithm cannot be null or empty.");
                if (NONE.equals(alg) || categoryOfAlg(alg) == null) {
                    throw new InvalidKeyException("Unsupported allowed algorithm: " + alg);
                }
                allowed.add(alg);
            }
            this.candidates.add(new Candidate(Strings.hasText(kid) ? kid : null, key,
                    Collections.unmodifiableSet(allowed)));
            return this;
        }

        /**
         * @return a new immutable {@link ExplicitKeyLocator} with the registered candidates.
         */
        public ExplicitKeyLocator build() {
            return new ExplicitKeyLocator(this.candidates);
        }
    }
}
