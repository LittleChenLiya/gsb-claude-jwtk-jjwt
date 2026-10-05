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

/**
 * Receipt emitted by an {@link ExplicitKeyLocator} after it selects a verification key.
 *
 * <p>The receipt intentionally contains <em>only</em> the {@link Category selection category}.  It never
 * contains key material, a {@code kid} value, a JWT header, or any part of a JWT compact string, so it is
 * always safe to log or return to callers without leaking token or key content.</p>
 *
 * @since 0.14.0
 */
public final class KeySelection {

    /**
     * The category of key that was selected.  The category is derived from the key's type and must match
     * the JWS {@code alg} header's algorithm family before a key may be selected.
     */
    public enum Category {
        /** HMAC shared-secret keys ({@code HS256}, {@code HS384}, {@code HS512}). */
        HMAC,
        /** RSA keys ({@code RS256}, {@code RS384}, {@code RS512}, {@code PS256}, {@code PS384}, {@code PS512}). */
        RSA,
        /** Elliptic Curve keys ({@code ES256}, {@code ES384}, {@code ES512}, {@code ES256K}). */
        EC,
        /** Edwards-curve keys ({@code EdDSA}, {@code Ed25519}, {@code Ed448}). */
        EDWARDS
    }

    private final Category category;

    public KeySelection(Category category) {
        this.category = Assert.notNull(category, "Category cannot be null.");
    }

    /**
     * Returns the category of the selected key.  This is the only information the receipt exposes.
     *
     * @return the category of the selected key.
     */
    public Category getCategory() {
        return this.category;
    }

    @Override
    public String toString() {
        // Deliberately only the category: no key material, no kid, no token content.
        return "KeySelection[category=" + this.category + ']';
    }
}
