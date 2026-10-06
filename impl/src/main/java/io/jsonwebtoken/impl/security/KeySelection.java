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

import java.util.Objects;

/**
 * A receipt describing the outcome of an {@link ExplicitKeyLocator} key selection.  It deliberately exposes
 * <em>only</em> the selected key's {@link KeyCategory category}: it never contains the located key, any key
 * material, the JWT, or any token content, so it is always safe to log or return to callers.
 *
 * @since 0.14.0
 */
public final class KeySelection {

    private final KeyCategory category;

    /**
     * Creates a new receipt for the specified category.
     *
     * @param category the selected key's category
     */
    public KeySelection(KeyCategory category) {
        this.category = Assert.notNull(category, "KeyCategory cannot be null.");
    }

    /**
     * Returns the selected key's category.
     *
     * @return the selected key's category.
     */
    public KeyCategory getCategory() {
        return this.category;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof KeySelection)) {
            return false;
        }
        return this.category == ((KeySelection) o).category;
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.category);
    }

    @Override
    public String toString() {
        // category only, by contract:
        return "KeySelection{category=" + this.category + '}';
    }
}
