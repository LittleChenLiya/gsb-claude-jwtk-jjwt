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
 * A {@link MalformedJwtException} that indicates a JWT Claims JSON payload contains a duplicate JSON object
 * key and the parser has been configured to require unique claims via
 * {@link io.jsonwebtoken.JwtParserBuilder#requireUniqueClaims()}.
 *
 * <p>Unlike other malformed-payload failures, this exception is never suppressed in favor of treating the
 * payload as opaque (non-JSON) content: a duplicate-key violation always rejects the JWT.</p>
 *
 * @since 0.14.0
 */
public class DuplicateClaimException extends MalformedJwtException {

    public DuplicateClaimException(String message) {
        super(message);
    }
}
