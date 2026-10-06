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

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.SecurityException;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A {@code Locator<Key>} with an explicit, fail-closed key selection contract for JWS signature
 * verification:
 *
 * <ol>
 *     <li><b>{@code kid} is only a locator.</b> The JWT header's {@code kid} value is used exclusively to
 *     find candidate keys; it never influences which algorithm is used.</li>
 *     <li><b>Type and algorithm must both match.</b> The header's {@code alg} value must be in the located
 *     candidate's explicitly configured allowed-algorithm set <em>and</em> the candidate key's
 *     {@link KeyCategory} must equal the algorithm's required category. A JWT header can never select an
 *     arbitrary or weaker (downgrade) algorithm for a key.</li>
 *     <li><b>Ambiguity is rejected.</b> If more than one candidate matches the header's {@code kid}, location
 *     fails immediately instead of picking one arbitrarily.</li>
 *     <li><b>No algorithm guessing.</b> Exactly one candidate is ever returned per header. If signature
 *     verification fails, neither this locator nor the parser retries with another algorithm or key.</li>
 *     <li><b>In-memory keys only.</b> All candidates are supplied as in-memory {@link Key} instances; this
 *     locator performs no file-system, network, or keystore I/O of any kind.</li>
 *     <li><b>Category-only receipt.</b> {@link #getLastSelection()} returns a {@link KeySelection} that
 *     exposes only the selected key's category, never the key, key material, or the JWT itself.</li>
 * </ol>
 *
 * <p>The default single-key parser configuration (for example
 * {@code Jwts.parser().verifyWith(key)}) remains fully supported and unchanged; this locator is an opt-in
 * alternative for multi-key or policy-enforcing scenarios. A single-key locator without a {@code kid}
 * requirement is available via {@link #of(Key, String...)}.</p>
 *
 * <p>This locator supports JWS signature verification only; it does not locate JWE decryption keys.</p>
 *
 * @since 0.14.0
 */
public final class ExplicitKeyLocator extends LocatorAdapter<Key> {

    private final List<KeyCandidate> candidates;
    private final AtomicLong locateCount = new AtomicLong();
    private volatile KeySelection lastSelection;

    private ExplicitKeyLocator(List<KeyCandidate> candidates) {
        Assert.notEmpty(candidates, "At least one key candidate is required.");
        this.candidates = Collections.unmodifiableList(new ArrayList<>(candidates));
    }

    /**
     * Creates a locator with a single default candidate (no {@code kid}), used when a JWT has no
     * {@code kid} header.
     *
     * @param key               the in-memory key
     * @param allowedAlgorithms the explicit set of JWS {@code alg} values the key may be used with
     * @return a new single-candidate locator
     */
    public static ExplicitKeyLocator of(Key key, String... allowedAlgorithms) {
        return builder().add(key, allowedAlgorithms).build();
    }

    /**
     * Creates a locator with a single candidate located by the specified {@code kid}.
     *
     * @param kid               the {@code kid} used to locate the candidate
     * @param key               the in-memory key
     * @param allowedAlgorithms the explicit set of JWS {@code alg} values the key may be used with
     * @return a new single-candidate locator
     */
    public static ExplicitKeyLocator of(String kid, Key key, String... allowedAlgorithms) {
        return builder().add(kid, key, allowedAlgorithms).build();
    }

    /**
     * Returns a new builder for registering multiple key candidates.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    @Override
    protected Key locate(JwsHeader header) {
        this.locateCount.incrementAndGet();
        String alg = header.getAlgorithm();
        if (!Strings.hasText(alg)) {
            throw new MalformedJwtException("JWS header does not contain an 'alg' value; a key cannot be " +
                    "located without a declared algorithm.");
        }
        alg = alg.trim();
        String kid = header.getKeyId();

        // 1. kid is used ONLY to find candidates:
        List<KeyCandidate> matches = new ArrayList<>(2);
        for (KeyCandidate candidate : this.candidates) {
            if (Objects.equals(candidate.getKid(), Strings.hasText(kid) ? kid : null)) {
                matches.add(candidate);
            }
        }
        if (matches.isEmpty()) {
            return null; // standard parser behavior: reports it cannot locate a verification key
        }
        // 2. ambiguity is rejected, never resolved arbitrarily:
        if (matches.size() > 1) {
            throw new SecurityException("Ambiguous key location: " + matches.size() + " key candidates match " +
                    describe(kid) + ". A 'kid' value must resolve to at most one key candidate.");
        }
        KeyCandidate candidate = matches.get(0);

        // 3. the header-declared algorithm must be explicitly allowed for the candidate; a disabled
        //    algorithm is rejected here and never reaches signature verification:
        if (!candidate.getAllowedAlgorithms().contains(alg)) {
            throw new SecurityException("JWS algorithm '" + alg + "' is not permitted for the key candidate " +
                    describe(kid) + ". A JWT header cannot select algorithms outside the candidate's " +
                    "explicitly configured set.");
        }

        // 4. the candidate's key category must match the algorithm's required category:
        KeyCategory required = KeyCategory.forJwsAlgorithm(alg);
        if (candidate.getCategory() != required) {
            String msg = "JWS algorithm '" + alg + "' requires a " + required + " key, but the located " +
                    "candidate " + describe(kid) + " is a " + candidate.getCategory() + " key.";
            throw new InvalidKeyException(msg);
        }

        // 5. record a category-only receipt and return exactly one key; the parser verifies with the
        //    header's algorithm only and never falls back to another algorithm on failure:
        this.lastSelection = new KeySelection(candidate.getCategory());
        return candidate.getKey();
    }

    @Override
    protected Key locate(JweHeader header) {
        return null; // JWS signature verification only; JWE decryption keys are out of scope
    }

    /**
     * Returns the receipt of the most recent successful key selection, containing only the selected key's
     * category, or {@code null} if no selection has completed yet.
     *
     * @return the receipt of the most recent successful key selection, or {@code null} if none
     */
    public KeySelection getLastSelection() {
        return this.lastSelection;
    }

    /**
     * Returns the total number of times this locator has been asked to locate a JWS key. Because the
     * contract never guesses or retries algorithms, this count increases by exactly one per parsed JWS.
     *
     * @return the total number of JWS key location attempts
     */
    public long getLocateCount() {
        return this.locateCount.get();
    }

    private static String describe(String kid) {
        return Strings.hasText(kid) ? "with kid '" + kid + "'" : "without a kid";
    }

    /**
     * Builder for an {@link ExplicitKeyLocator}.
     */
    public static final class Builder {

        private final List<KeyCandidate> candidates = new ArrayList<>();

        private Builder() {
        }

        /**
         * Adds a candidate located by the specified {@code kid}.
         *
         * @param kid               the {@code kid} used to locate the candidate
         * @param key               the in-memory key
         * @param allowedAlgorithms the explicit set of JWS {@code alg} values the key may be used with
         * @return this builder
         */
        public Builder add(String kid, Key key, String... allowedAlgorithms) {
            return add(new KeyCandidate(kid, key, Arrays.asList(allowedAlgorithms)));
        }

        /**
         * Adds a default candidate (no {@code kid}), used when a JWT has no {@code kid} header.
         *
         * @param key               the in-memory key
         * @param allowedAlgorithms the explicit set of JWS {@code alg} values the key may be used with
         * @return this builder
         */
        public Builder add(Key key, String... allowedAlgorithms) {
            return add(null, key, allowedAlgorithms);
        }

        /**
         * Adds a pre-built candidate.
         *
         * @param candidate the candidate to add
         * @return this builder
         */
        public Builder add(KeyCandidate candidate) {
            this.candidates.add(Assert.notNull(candidate, "KeyCandidate cannot be null."));
            return this;
        }

        /**
         * Builds the locator. At least one candidate is required.
         *
         * @return the new locator
         */
        public ExplicitKeyLocator build() {
            return new ExplicitKeyLocator(this.candidates);
        }
    }
}
