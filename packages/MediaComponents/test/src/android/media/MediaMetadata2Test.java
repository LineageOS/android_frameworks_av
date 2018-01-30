/*
 * Copyright 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.media;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

import android.content.Context;
import android.media.MediaMetadata2.Builder;
import android.os.Bundle;
import android.support.test.filters.SmallTest;
import android.support.test.runner.AndroidJUnit4;
import android.support.test.InstrumentationRegistry;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
@SmallTest
public class MediaMetadata2Test {
    private Context mContext;

    @Before
    public void setUp() throws Exception {
        mContext = InstrumentationRegistry.getTargetContext();
    }

    @Test
    public void testBuilder() {
        final Bundle extra = new Bundle();
        extra.putString("MediaMetadata2Test", "testBuilder");
        final String title = "title";
        final long discNumber = 10;
        final Rating2 rating = Rating2.newThumbRating(mContext, true);

        MediaMetadata2.Builder builder = new Builder(mContext);
        builder.setExtra(extra);
        builder.putString(MediaMetadata2.METADATA_KEY_DISPLAY_TITLE, title);
        builder.putLong(MediaMetadata2.METADATA_KEY_DISC_NUMBER, discNumber);
        builder.putRating(MediaMetadata2.METADATA_KEY_USER_RATING, rating);

        MediaMetadata2 metadata = builder.build();
        assertTrue(TestUtils.equals(extra, metadata.getExtra()));
        assertEquals(title, metadata.getString(MediaMetadata2.METADATA_KEY_DISPLAY_TITLE));
        assertEquals(discNumber, metadata.getLong(MediaMetadata2.METADATA_KEY_DISC_NUMBER));
        assertEquals(rating, metadata.getRating(MediaMetadata2.METADATA_KEY_USER_RATING));
    }
}
