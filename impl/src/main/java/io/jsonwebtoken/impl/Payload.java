/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodec;
import io.jsonwebtoken.CompressionException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.io.BoundedInputStream;
import io.jsonwebtoken.impl.io.StreamLimitExceededException;
import io.jsonwebtoken.impl.io.Streams;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.io.CompressionAlgorithm;
import io.jsonwebtoken.io.IOException;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;

import java.io.InputStream;
import java.io.OutputStream;

class Payload {

    static final Payload EMPTY = new Payload(Bytes.EMPTY, null);

    private final CharSequence string;
    private final byte[] bytes;
    private final Claims claims;
    private final InputStream inputStream;
    private final boolean inputStreamEmpty;
    private final String contentType;
    private CompressionAlgorithm zip;
    private boolean claimsExpected;

    Payload(Claims claims) {
        this(claims, null, null, null, null);
    }

    Payload(CharSequence content, String contentType) {
        this(null, content, null, null, contentType);
    }

    Payload(byte[] content, String contentType) {
        this(null, null, content, null, contentType);
    }

    Payload(InputStream inputStream, String contentType) {
        this(null, null, null, inputStream, contentType);
    }

    private Payload(Claims claims, CharSequence string, byte[] bytes, InputStream inputStream, String contentType) {
        this.claims = claims;
        this.string = Strings.clean(string);
        this.contentType = Strings.clean(contentType);
        InputStream in = inputStream;
        byte[] data = Bytes.nullSafe(bytes);
        if (Strings.hasText(this.string)) {
            data = Strings.utf8(this.string);
        }
        this.bytes = data;
        if (in == null && !Bytes.isEmpty(this.bytes)) {
            in = Streams.of(data);
        }
        this.inputStreamEmpty = in == null;
        this.inputStream = this.inputStreamEmpty ? Streams.of(Bytes.EMPTY) : in;
    }

    boolean isClaims() {
        return !Collections.isEmpty(this.claims);
    }

    Claims getRequiredClaims() {
        return Assert.notEmpty(this.claims, "Claims cannot be null or empty when calling this method.");
    }

    boolean isString() {
        return Strings.hasText(this.string);
    }

    String getContentType() {
        return this.contentType;
    }

    public void setZip(CompressionAlgorithm zip) {
        this.zip = zip;
    }

    boolean isCompressed() {
        return this.zip != null;
    }

    public void setClaimsExpected(boolean claimsExpected) {
        this.claimsExpected = claimsExpected;
    }

    /**
     * Returns {@code true} if the payload may be fully consumed and retained in memory, {@code false} if empty,
     * already extracted, or a potentially too-large InputStream.
     *
     * @return {@code true} if the payload may be fully consumed and retained in memory, {@code false} if empty,
     * already extracted, or a potentially too-large InputStream.
     */
    boolean isConsumable() {
        return !isClaims() && (isString() || !Bytes.isEmpty(this.bytes) || (inputStream != null && claimsExpected));
    }

    boolean isEmpty() {
        return !isClaims() && !isString() && Bytes.isEmpty(this.bytes) && this.inputStreamEmpty;
    }

    public OutputStream compress(OutputStream out) {
        return this.zip != null ? zip.compress(out) : out;
    }

    public Payload decompress(CompressionAlgorithm alg, long maxBytes) {
        Assert.notNull(alg, "CompressionAlgorithm cannot be null.");
        Payload payload = this;
        if (!isString() && isConsumable()) {
            byte[] data;
            if (alg.equals(Jwts.ZIP.DEF) && !Bytes.isEmpty(this.bytes)) { // backwards compatibility
                data = deflateDecompress(alg, this.bytes, maxBytes);
            } else {
                data = toByteArray(alg.decompress(toInputStream()), maxBytes, alg);
            }
            payload = new Payload(claims, string, data, null, getContentType());
            payload.setClaimsExpected(claimsExpected);
        }
        // otherwise it's a String or b64/detached payload, in either case, we don't decompress since the caller is
        // providing the bytes necessary for signature verification as-is, and there's no conversion we need to perform
        return payload;
    }

    /**
     * Decompresses DEFLATEd bytes, refusing to read or allocate more than {@code maxBytes} decompressed bytes.
     * If the standard stream-based decompression fails due to a formatting problem, the
     * {@link CompressionCodec#decompress(byte[])} implementation is used as a fallback to retain backwards
     * compatibility with JWTs created by JJWT 0.10.6 and earlier (see
     * <a href="https://github.com/jwtk/jjwt/issues/536">Issue 536</a>).
     */
    private static byte[] deflateDecompress(CompressionAlgorithm alg, byte[] compressed, long maxBytes) {
        try {
            return toByteArray(alg.decompress(Streams.of(compressed)), maxBytes, alg);
        } catch (CompressionException e) { // size limit exceeded or decompression failure, do not fall back:
            throw e;
        } catch (IOException e) { // formatting problem, try the backwards-compatible fallback:
            byte[] data = ((CompressionCodec) alg).decompress(compressed);
            if (Bytes.length(data) > maxBytes) {
                throw sizeLimitExceeded(alg, maxBytes, null);
            }
            return data;
        }
    }

    /**
     * Reads the decompressed payload stream into a byte array, refusing to read or allocate more than
     * {@code maxBytes} bytes.
     *
     * @param in       the decompressed payload stream
     * @param maxBytes the maximum number of decompressed bytes allowed
     * @param alg      the compression algorithm used to produce the stream
     * @return the decompressed payload bytes
     * @throws CompressionException if the decompressed payload exceeds {@code maxBytes}, referencing the
     *                              compression algorithm and retaining the underlying cause
     */
    private static byte[] toByteArray(InputStream in, long maxBytes, CompressionAlgorithm alg) {
        try {
            return Streams.bytes(new BoundedInputStream(in, maxBytes), "Unable to decompress payload.");
        } catch (IOException e) {
            StreamLimitExceededException limitExceeded = findStreamLimitExceeded(e);
            if (limitExceeded != null) {
                throw sizeLimitExceeded(alg, maxBytes, limitExceeded);
            }
            throw e;
        }
    }

    private static CompressionException sizeLimitExceeded(CompressionAlgorithm alg, long maxBytes,
                                                          StreamLimitExceededException cause) {
        String msg = "Decompressed payload exceeds the maximum allowed " + maxBytes +
                " bytes for compression algorithm '" + alg.getId() + "'.";
        return new CompressionException(msg, cause);
    }

    private static StreamLimitExceededException findStreamLimitExceeded(Throwable t) {
        while (t != null) {
            if (t instanceof StreamLimitExceededException) {
                return (StreamLimitExceededException) t;
            }
            t = t.getCause();
        }
        return null;
    }

    public byte[] getBytes() {
        return this.bytes;
    }

    InputStream toInputStream() {
        // should only ever call this when claims don't exist:
        Assert.state(!isClaims(), "Claims exist, cannot convert to InputStream directly.");
        return this.inputStream;
    }
}
