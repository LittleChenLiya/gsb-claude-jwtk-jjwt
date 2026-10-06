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

import java.security.Key;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A single immutable key candidate for an {@link ExplicitKeyLocator}: an in-memory {@link Key}, the optional
 * {@code kid} used <em>only</em> to locate the candidate, and the explicit set of JWS algorithms the key may
 * be used with.  A candidate is only valid when its key's {@link KeyCategory} and every allowed algorithm's
 * required category match; mismatched combinations are rejected at construction time.
 *
 * <p>Instances never read key material from the file system or network; the key is held in memory only.
 * {@link #toString()} intentionally omits all key material.</p>
 *
 * @since 0.14.0
 */
public final class KeyCandidate {

    private final String kid;
    private final Key key;
    private final Set<String> allowedAlgorithms;
    private final KeyCategory category;

    /**
     * Creates a new candidate.
     *
     * @param kid               the JWS {@code kid} header value used to locate this candidate, or {@code null}
     *                          if this is the default candidate used when a JWT has no {@code kid} header
     * @param key               the in-memory key
     * @param allowedAlgorithms the explicit non-empty set of JWS {@code alg} values this key may be used with
     * @throws IllegalArgumentException if the key is null, the algorithm set is null/empty/contains blank
     *                                  values, or any allowed algorithm's required {@link KeyCategory} does not
     *                                  match the key's category
     */
    public KeyCandidate(String kid, Key key, Collection<String> allowedAlgorithms) {
        this.kid = Strings.hasText(kid) ? kid.trim() : null;
        this.key = Assert.notNull(key, "Key cannot be null.");
        Assert.notEmpty(allowedAlgorithms, "Allowed algorithms collection cannot be null or empty.");
        Set<String> algs = new LinkedHashSet<>();
        for (String alg : allowedAlgorithms) {
            Assert.hasText(alg, "Allowed algorithm values cannot be null or empty.");
            algs.add(alg.trim());
        }
        this.category = KeyCategory.of(key);
        for (String alg : algs) {
            KeyCategory required = KeyCategory.forJwsAlgorithm(alg);
            if (required != this.category) {
                String msg = "JWS algorithm '" + alg + "' requires a " + required + " key, but this candidate's " +
                        "key is " + this.category + ". A key may only be registered with algorithms of its own " +
                        "category.";
                throw new IllegalArgumentException(msg);
            }
        }
        this.allowedAlgorithms = Collections.unmodifiableSet(algs);
    }

    /**
     * Returns the {@code kid} used to locate this candidate, or {@code null} if this is the default candidate.
     *
     * @return the {@code kid} used to locate this candidate, or {@code null} if this is the default candidate.
     */
    public String getKid() {
        return this.kid;
    }

    /**
     * Returns the candidate's in-memory key.
     *
     * @return the candidate's in-memory key.
     */
    public Key getKey() {
        return this.key;
    }

    /**
     * Returns the immutable explicit set of JWS {@code alg} values the key may be used with.
     *
     * @return the immutable explicit set of JWS {@code alg} values the key may be used with.
     */
    public Set<String> getAllowedAlgorithms() {
        return this.allowedAlgorithms;
    }

    /**
     * Returns the key's category.
     *
     * @return the key's category.
     */
    public KeyCategory getCategory() {
        return this.category;
    }

    @Override
    public String toString() {
        // intentionally no key material:
        return "KeyCandidate{kid='" + this.kid + "', category=" + this.category +
                ", allowedAlgorithms=" + this.allowedAlgorithms + '}';
    }
}
