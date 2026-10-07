/*
 * Copyright © 2026 jsonwebtoken.io
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

import java.io.InputStream;

/**
 * A {@link FilteredInputStream} that allows at most a configured maximum number of bytes to be read.  As soon as
 * the number of bytes read exceeds that maximum, a {@link StreamLimitExceededException} is thrown and no further
 * bytes are read, ensuring callers do not allocate memory for excessively large (for example, decompressed)
 * streams.
 *
 * @since 0.14.0
 */
public class BoundedInputStream extends FilteredInputStream {

    private final long maxBytes;

    private long count;

    public BoundedInputStream(final InputStream in, final long maxBytes) {
        super(Assert.notNull(in, "InputStream cannot be null."));
        Assert.isTrue(maxBytes >= 0, "maxBytes must be greater than or equal to zero.");
        this.maxBytes = maxBytes;
    }

    /**
     * Returns the maximum number of bytes that may be read before a {@link StreamLimitExceededException} is thrown.
     *
     * @return the maximum number of bytes that may be read before a {@link StreamLimitExceededException} is thrown.
     */
    public long getMaxBytes() {
        return this.maxBytes;
    }

    @Override
    protected void afterRead(final int n) throws StreamLimitExceededException {
        if (n > 0) {
            this.count += n;
            if (this.count > this.maxBytes) {
                String msg = "Stream exceeded the maximum allowed " + this.maxBytes + " bytes.";
                throw new StreamLimitExceededException(msg);
            }
        }
    }
}
