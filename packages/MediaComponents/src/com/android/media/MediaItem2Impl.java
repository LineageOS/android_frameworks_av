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

package com.android.media;

import static android.media.MediaItem2.FLAG_BROWSABLE;
import static android.media.MediaItem2.FLAG_PLAYABLE;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.content.Context;
import android.media.DataSourceDesc;
import android.media.MediaItem2;
import android.media.MediaItem2.Builder;
import android.media.MediaItem2.Flags;
import android.media.MediaMetadata2;
import android.media.update.MediaItem2Provider;
import android.os.Bundle;
import android.text.TextUtils;

public class MediaItem2Impl implements MediaItem2Provider {
    private static final String KEY_ID = "android.media.mediaitem2.id";
    private static final String KEY_FLAGS = "android.media.mediaitem2.flags";
    private static final String KEY_METADATA = "android.media.mediaitem2.metadata";

    private final Context mContext;
    private final MediaItem2 mInstance;
    private final String mId;
    private final int mFlags;
    private MediaMetadata2 mMetadata;
    private DataSourceDesc mDataSourceDesc;

    // From the public API
    public MediaItem2Impl(@NonNull Context context, @NonNull String mediaId,
            @Nullable DataSourceDesc dsd, @Nullable MediaMetadata2 metadata, @Flags int flags) {
        if (mediaId == null) {
            throw new IllegalArgumentException("mediaId shouldn't be null");
        }
        if (metadata != null && !TextUtils.equals(mediaId, metadata.getMediaId())) {
            throw new IllegalArgumentException("metadata's id should be matched with the mediaid");
        }

        mContext = context;
        mId = mediaId;
        mDataSourceDesc = dsd;
        mMetadata = metadata;
        mFlags = flags;

        mInstance = new MediaItem2(this);
    }

    // Create anonymized version
    public MediaItem2Impl(Context context, String mediaId, MediaMetadata2 metadata,
            @Flags int flags) {
        if (mediaId == null) {
            throw new IllegalArgumentException("mediaId shouldn't be null");
        }
        if (metadata != null && !TextUtils.equals(mediaId, metadata.getMediaId())) {
            throw new IllegalArgumentException("metadata's id should be matched with the mediaid");
        }
        mContext = context;
        mId = mediaId;
        mMetadata = metadata;
        mFlags = flags;
        mInstance = new MediaItem2(this);
    }

    /**
     * Return this object as a bundle to share between processes.
     *
     * @return a new bundle instance
     */
    public Bundle toBundle_impl() {
        Bundle bundle = new Bundle();
        bundle.putString(KEY_ID, mId);
        bundle.putInt(KEY_FLAGS, mFlags);
        if (mMetadata != null) {
            bundle.putBundle(KEY_METADATA, mMetadata.toBundle());
        }
        return bundle;
    }

    public static MediaItem2 fromBundle(Context context, Bundle bundle) {
        if (bundle == null) {
            return null;
        }
        final String id = bundle.getString(KEY_ID);
        final Bundle metadataBundle = bundle.getBundle(KEY_METADATA);
        final MediaMetadata2 metadata = metadataBundle != null
                ? MediaMetadata2.fromBundle(context, metadataBundle) : null;
        final int flags = bundle.getInt(KEY_FLAGS);
        return new MediaItem2Impl(context, id, metadata, flags).getInstance();
    }

    private MediaItem2 getInstance() {
        return mInstance;
    }

    @Override
    public String toString_impl() {
        final StringBuilder sb = new StringBuilder("MediaItem2{");
        sb.append("mFlags=").append(mFlags);
        sb.append(", mMetadata=").append(mMetadata);
        sb.append('}');
        return sb.toString();
    }

    @Override
    public @Flags int getFlags_impl() {
        return mFlags;
    }

    @Override
    public boolean isBrowsable_impl() {
        return (mFlags & FLAG_BROWSABLE) != 0;
    }

    @Override
    public boolean isPlayable_impl() {
        return (mFlags & FLAG_PLAYABLE) != 0;
    }

    @Override
    public void setMetadata_impl(@Nullable MediaMetadata2 metadata) {
        if (metadata != null && !TextUtils.equals(mId, metadata.getMediaId())) {
            throw new IllegalArgumentException("metadata's id should be matched with the mediaId");
        }
        mMetadata = metadata;
    }

    @Override
    public @Nullable MediaMetadata2 getMetadata_impl() {
        return mMetadata;
    }

    @Override
    public @NonNull String getMediaId_impl() {
        return mId;
    }

    @Override
    public @Nullable DataSourceDesc getDataSourceDesc_impl() {
        return mDataSourceDesc;
    }

    public static class BuilderImpl implements MediaItem2Provider.BuilderProvider {
        private Context mContext;
        private Builder mInstance;
        private @Flags int mFlags;
        private String mMediaId;
        private MediaMetadata2 mMetadata;
        private DataSourceDesc mDataSourceDesc;

        public BuilderImpl(Context context, Builder instance, int flags) {
            mContext = context;
            mInstance = instance;
            mFlags = flags;
        }

        @Override
        public Builder setMediaId_impl(@Nullable String mediaId) {
            mMediaId = mediaId;
            return mInstance;
        }

        @Override
        public Builder setMetadata_impl(@Nullable MediaMetadata2 metadata) {
            mMetadata = metadata;
            return mInstance;
        }

        @Override
        public Builder setDataSourceDesc_impl(@Nullable DataSourceDesc dataSourceDesc) {
            mDataSourceDesc = dataSourceDesc;
            return mInstance;
        }

        @Override
        public MediaItem2 build_impl() {
            String id = (mMetadata != null)
                    ? mMetadata.getString(MediaMetadata2.METADATA_KEY_MEDIA_ID) : null;
            if (id == null) {
                //  TODO(jaewan): Double check if its sufficient (e.g. Use UUID instead?)
                id = (mMediaId != null) ? mMediaId : toString();
            }
            return new MediaItem2Impl(mContext, id, mDataSourceDesc, mMetadata, mFlags)
                    .getInstance();
        }
    }
}
