/*
 * Copyright © 2024 jsonwebtoken.io
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

import io.jsonwebtoken.lang.Assert;

import java.io.IOException;
import java.io.InputStream;

/**
 * An {@link InputStream} that allows at most a configured maximum number of bytes to be read from the
 * delegate stream.  Once the number of bytes read exceeds that maximum, an {@link IOException} is thrown
 * immediately, refusing to produce (and thereby refusing to allocate or retain) any additional bytes.  This is
 * useful to protect against decompression bombs and other unbounded streams.
 *
 * @since 0.14.0
 */
public class BoundedInputStream extends FilteredInputStream {

    private final long maxBytes;

    private long count;

    private boolean limitExceeded;

    /**
     * Creates a new stream that allows at most {@code maxBytes} bytes to be read from the specified delegate.
     *
     * @param in       the delegate InputStream to read from
     * @param maxBytes the maximum number of bytes that may be read from the delegate
     */
    public BoundedInputStream(final InputStream in, final long maxBytes) {
        super(Assert.notNull(in, "InputStream cannot be null."));
        Assert.isTrue(maxBytes >= 0, "maxBytes must be greater than or equal to zero.");
        this.maxBytes = maxBytes;
    }

    /**
     * Returns {@code true} if an attempt was made to read more than the configured maximum number of bytes,
     * {@code false} otherwise.
     *
     * @return {@code true} if the maximum number of readable bytes has been exceeded, {@code false} otherwise.
     */
    public boolean isLimitExceeded() {
        return this.limitExceeded;
    }

    @Override
    protected void afterRead(final int n) throws IOException {
        if (n > 0) {
            this.count += n;
            if (this.count > this.maxBytes) {
                this.limitExceeded = true;
                throw new IOException("Stream exceeds the maximum allowed " + this.maxBytes + " bytes.");
            }
        }
    }
}
