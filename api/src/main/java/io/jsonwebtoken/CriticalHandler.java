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
package io.jsonwebtoken;

/**
 * A {@code CriticalHandler} consumes (validates) a single JWT {@code crit} (critical) header parameter
 * encountered during JWT parsing.
 *
 * <p><a href="https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11">RFC 7515, Section 4.1.11</a> requires
 * that any header parameter name listed in a JWT's {@code crit} (critical) set be understood and processed by the
 * application.  Registering a {@code CriticalHandler} via
 * {@link JwtParserBuilder#criticalHandler(String, CriticalHandler)} explicitly declares which extension header
 * parameter the application understands <em>and</em> the code that consumes it: when a JWT's {@code crit} set
 * references a registered name, the parser invokes the associated handler with that header parameter's value
 * <b>before any claims are processed</b>.  If a {@code crit} name has no registered handler (and is not otherwise
 * declared via {@link JwtParserBuilder#critical()}), the JWT is rejected.</p>
 *
 * <p><b>Security Note</b></p>
 *
 * <p>Handlers are application-provided code references only.  JJWT never instantiates handler classes by name,
 * never loads handler classes reflectively, and never executes any code discovered in a JWT itself.  Only
 * handlers explicitly registered on the {@link JwtParserBuilder} by application code are ever invoked.</p>
 *
 * <p><b>Exceptions</b></p>
 *
 * <p>Implementations should throw a {@link JwtException} (or subclass) if the header parameter value is not
 * acceptable; the parser will propagate it and reject the JWT.  Any other {@code RuntimeException} thrown by a
 * handler is wrapped in a {@link JwtException} and the JWT is rejected.  Implementations should not include
 * sensitive material (raw tokens, key material, etc.) in exception messages.</p>
 *
 * @see JwtParserBuilder#criticalHandler(String, CriticalHandler)
 * @see ProtectedHeader#getCritical()
 * @since 0.14.0
 */
@FunctionalInterface
public interface CriticalHandler {

    /**
     * Validates/consumes a critical header parameter found in a JWT's protected header.
     *
     * @param name  the critical header parameter name, as referenced by the JWT's {@code crit} set.
     * @param value the header parameter value associated with {@code name}.
     * @throws JwtException if the header parameter value is not acceptable, causing the JWT to be rejected.
     */
    void validate(String name, Object value) throws JwtException;
}
