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
package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.MalformedJwtException;

/**
 * Exception thrown when a JWT's JSON (protected header or claims payload) contains a duplicate
 * JSON Object member name and the parser has been configured with
 * {@link io.jsonwebtoken.JwtParserBuilder#strictDuplicateClaimDetection()}.
 *
 * <p>The exception message reports the duplicate member's full key path (for example
 * {@code nested.sub}) and its line/column position within the JSON document.</p>
 *
 * @since 0.14.0
 */
public class DuplicateClaimException extends MalformedJwtException {

    public DuplicateClaimException(String message) {
        super(message);
    }
}
