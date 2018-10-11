/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef MEDIA_EXTRACTOR_PLUGIN_HELPER_H_

#define MEDIA_EXTRACTOR_PLUGIN_HELPER_H_

#include <arpa/inet.h>
#include <stdio.h>
#include <vector>

#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/RefBase.h>
#include <media/MediaExtractorPluginApi.h>

namespace android {

class DataSourceBase;
class MetaDataBase;
struct MediaTrack;


class MediaTrackHelper {
public:
    virtual ~MediaTrackHelper() {};
    virtual status_t start() = 0;
    virtual status_t stop() = 0;
    virtual status_t getFormat(MetaDataBase& format) = 0;

    class ReadOptions {
    public:
        enum SeekMode : int32_t {
            SEEK_PREVIOUS_SYNC,
            SEEK_NEXT_SYNC,
            SEEK_CLOSEST_SYNC,
            SEEK_CLOSEST,
            SEEK_FRAME_INDEX,
        };

        ReadOptions(uint32_t options, int64_t seekPosUs) {
            mOptions = options;
            mSeekPosUs = seekPosUs;
        }
        bool getSeekTo(int64_t *time_us, SeekMode *mode) const {
            if ((mOptions & CMediaTrackReadOptions::SEEK) == 0) {
                return false;
            }
            *time_us = mSeekPosUs;
            *mode = (SeekMode) (mOptions & 7);
            return true;
        }
        bool getNonBlocking() const {
            return mOptions & CMediaTrackReadOptions::NONBLOCKING;
        }
    private:
        uint32_t mOptions;
        int64_t mSeekPosUs;
    };

    virtual status_t read(
            MediaBufferBase **buffer, const ReadOptions *options = NULL) = 0;
    virtual bool supportsNonBlockingRead() { return false; }
};

inline CMediaTrack *wrap(MediaTrackHelper *track) {
    CMediaTrack *wrapper = (CMediaTrack*) malloc(sizeof(CMediaTrack));
    wrapper->data = track;
    wrapper->free = [](void *data) -> void {
        delete (MediaTrackHelper*)(data);
    };
    wrapper->start = [](void *data) -> status_t {
        return ((MediaTrackHelper*)data)->start();
    };
    wrapper->stop = [](void *data) -> status_t {
        return ((MediaTrackHelper*)data)->stop();
    };
    wrapper->getFormat = [](void *data, MetaDataBase &meta) -> status_t {
        return ((MediaTrackHelper*)data)->getFormat(meta);
    };
    wrapper->read = [](void *data, MediaBufferBase **buffer,  uint32_t options, int64_t seekPosUs)
            -> status_t {
        MediaTrackHelper::ReadOptions opts(options, seekPosUs);
        return ((MediaTrackHelper*)data)->read(buffer, &opts);
    };
    wrapper->supportsNonBlockingRead = [](void *data) -> bool {
                return ((MediaTrackHelper*)data)->supportsNonBlockingRead();
    };
    return wrapper;
}


class MediaTrackHelperV2 {
public:
    virtual ~MediaTrackHelperV2() {};
    virtual media_status_t start() = 0;
    virtual media_status_t stop() = 0;
    virtual media_status_t getFormat(AMediaFormat *format) = 0;

    class ReadOptions {
    public:
        enum SeekMode : int32_t {
            SEEK_PREVIOUS_SYNC,
            SEEK_NEXT_SYNC,
            SEEK_CLOSEST_SYNC,
            SEEK_CLOSEST,
            SEEK_FRAME_INDEX,
        };

        ReadOptions(uint32_t options, int64_t seekPosUs) {
            mOptions = options;
            mSeekPosUs = seekPosUs;
        }
        bool getSeekTo(int64_t *time_us, SeekMode *mode) const {
            if ((mOptions & CMediaTrackReadOptions::SEEK) == 0) {
                return false;
            }
            *time_us = mSeekPosUs;
            *mode = (SeekMode) (mOptions & 7);
            return true;
        }
        bool getNonBlocking() const {
            return mOptions & CMediaTrackReadOptions::NONBLOCKING;
        }
    private:
        uint32_t mOptions;
        int64_t mSeekPosUs;
    };

    virtual media_status_t read(
            MediaBufferBase **buffer, const ReadOptions *options = NULL) = 0;
    virtual bool supportsNonBlockingRead() { return false; }
};

inline CMediaTrackV2 *wrapV2(MediaTrackHelperV2 *track) {
    CMediaTrackV2 *wrapper = (CMediaTrackV2*) malloc(sizeof(CMediaTrackV2));
    wrapper->data = track;
    wrapper->free = [](void *data) -> void {
        delete (MediaTrackHelperV2*)(data);
    };
    wrapper->start = [](void *data) -> media_status_t {
        return ((MediaTrackHelperV2*)data)->start();
    };
    wrapper->stop = [](void *data) -> media_status_t {
        return ((MediaTrackHelperV2*)data)->stop();
    };
    wrapper->getFormat = [](void *data, AMediaFormat *meta) -> media_status_t {
        return ((MediaTrackHelperV2*)data)->getFormat(meta);
    };
    wrapper->read = [](void *data, MediaBufferBase **buffer,  uint32_t options, int64_t seekPosUs)
            -> media_status_t {
        MediaTrackHelperV2::ReadOptions opts(options, seekPosUs);
        return ((MediaTrackHelperV2*)data)->read(buffer, &opts);
    };
    wrapper->supportsNonBlockingRead = [](void *data) -> bool {
                return ((MediaTrackHelperV2*)data)->supportsNonBlockingRead();
    };
    return wrapper;
}



// extractor plugins can derive from this class which looks remarkably
// like MediaExtractor and can be easily wrapped in the required C API
class MediaExtractorPluginHelper
{
public:
    virtual ~MediaExtractorPluginHelper() {}
    virtual size_t countTracks() = 0;
    virtual MediaTrackHelper *getTrack(size_t index) = 0;

    enum GetTrackMetaDataFlags {
        kIncludeExtensiveMetaData = 1
    };
    virtual status_t getTrackMetaData(
            MetaDataBase& meta,
            size_t index, uint32_t flags = 0) = 0;

    // Return container specific meta-data. The default implementation
    // returns an empty metadata object.
    virtual status_t getMetaData(MetaDataBase& meta) = 0;

    enum Flags {
        CAN_SEEK_BACKWARD  = 1,  // the "seek 10secs back button"
        CAN_SEEK_FORWARD   = 2,  // the "seek 10secs forward button"
        CAN_PAUSE          = 4,
        CAN_SEEK           = 8,  // the "seek bar"
    };

    // If subclasses do _not_ override this, the default is
    // CAN_SEEK_BACKWARD | CAN_SEEK_FORWARD | CAN_SEEK | CAN_PAUSE
    virtual uint32_t flags() const {
        return CAN_SEEK_BACKWARD | CAN_SEEK_FORWARD | CAN_SEEK | CAN_PAUSE;
    };

    virtual status_t setMediaCas(const uint8_t* /*casToken*/, size_t /*size*/) {
        return INVALID_OPERATION;
    }

    virtual const char * name() { return "<unspecified>"; }

protected:
    MediaExtractorPluginHelper() {}

private:
    MediaExtractorPluginHelper(const MediaExtractorPluginHelper &);
    MediaExtractorPluginHelper &operator=(const MediaExtractorPluginHelper &);
};

inline CMediaExtractor *wrap(MediaExtractorPluginHelper *extractor) {
    CMediaExtractor *wrapper = (CMediaExtractor*) malloc(sizeof(CMediaExtractor));
    wrapper->data = extractor;
    wrapper->free = [](void *data) -> void {
        delete (MediaExtractorPluginHelper*)(data);
    };
    wrapper->countTracks = [](void *data) -> size_t {
        return ((MediaExtractorPluginHelper*)data)->countTracks();
    };
    wrapper->getTrack = [](void *data, size_t index) -> CMediaTrack* {
        return wrap(((MediaExtractorPluginHelper*)data)->getTrack(index));
    };
    wrapper->getTrackMetaData = [](
            void *data,
            MetaDataBase& meta,
            size_t index, uint32_t flags) -> status_t {
        return ((MediaExtractorPluginHelper*)data)->getTrackMetaData(meta, index, flags);
    };
    wrapper->getMetaData = [](
            void *data,
            MetaDataBase& meta) -> status_t {
        return ((MediaExtractorPluginHelper*)data)->getMetaData(meta);
    };
    wrapper->flags = [](
            void *data) -> uint32_t {
        return ((MediaExtractorPluginHelper*)data)->flags();
    };
    wrapper->setMediaCas = [](
            void *data, const uint8_t *casToken, size_t size) -> status_t {
        return ((MediaExtractorPluginHelper*)data)->setMediaCas(casToken, size);
    };
    wrapper->name = [](
            void *data) -> const char * {
        return ((MediaExtractorPluginHelper*)data)->name();
    };
    return wrapper;
}

class MediaExtractorPluginHelperV2
{
public:
    virtual ~MediaExtractorPluginHelperV2() {}
    virtual size_t countTracks() = 0;
    virtual MediaTrackHelperV2 *getTrack(size_t index) = 0;

    enum GetTrackMetaDataFlags {
        kIncludeExtensiveMetaData = 1
    };
    virtual media_status_t getTrackMetaData(
            AMediaFormat *meta,
            size_t index, uint32_t flags = 0) = 0;

    // Return container specific meta-data. The default implementation
    // returns an empty metadata object.
    virtual media_status_t getMetaData(AMediaFormat *meta) = 0;

    enum Flags {
        CAN_SEEK_BACKWARD  = 1,  // the "seek 10secs back button"
        CAN_SEEK_FORWARD   = 2,  // the "seek 10secs forward button"
        CAN_PAUSE          = 4,
        CAN_SEEK           = 8,  // the "seek bar"
    };

    // If subclasses do _not_ override this, the default is
    // CAN_SEEK_BACKWARD | CAN_SEEK_FORWARD | CAN_SEEK | CAN_PAUSE
    virtual uint32_t flags() const {
        return CAN_SEEK_BACKWARD | CAN_SEEK_FORWARD | CAN_SEEK | CAN_PAUSE;
    };

    virtual media_status_t setMediaCas(const uint8_t* /*casToken*/, size_t /*size*/) {
        return AMEDIA_ERROR_INVALID_OPERATION;
    }

    virtual const char * name() { return "<unspecified>"; }

protected:
    MediaExtractorPluginHelperV2() {}

private:
    MediaExtractorPluginHelperV2(const MediaExtractorPluginHelperV2 &);
    MediaExtractorPluginHelperV2 &operator=(const MediaExtractorPluginHelperV2 &);
};

inline CMediaExtractorV2 *wrapV2(MediaExtractorPluginHelperV2 *extractor) {
    CMediaExtractorV2 *wrapper = (CMediaExtractorV2*) malloc(sizeof(CMediaExtractorV2));
    wrapper->data = extractor;
    wrapper->free = [](void *data) -> void {
        delete (MediaExtractorPluginHelperV2*)(data);
    };
    wrapper->countTracks = [](void *data) -> size_t {
        return ((MediaExtractorPluginHelperV2*)data)->countTracks();
    };
    wrapper->getTrack = [](void *data, size_t index) -> CMediaTrackV2* {
        return wrapV2(((MediaExtractorPluginHelperV2*)data)->getTrack(index));
    };
    wrapper->getTrackMetaData = [](
            void *data,
            AMediaFormat *meta,
            size_t index, uint32_t flags) -> media_status_t {
        return ((MediaExtractorPluginHelperV2*)data)->getTrackMetaData(meta, index, flags);
    };
    wrapper->getMetaData = [](
            void *data,
            AMediaFormat *meta) -> media_status_t {
        return ((MediaExtractorPluginHelperV2*)data)->getMetaData(meta);
    };
    wrapper->flags = [](
            void *data) -> uint32_t {
        return ((MediaExtractorPluginHelperV2*)data)->flags();
    };
    wrapper->setMediaCas = [](
            void *data, const uint8_t *casToken, size_t size) -> media_status_t {
        return ((MediaExtractorPluginHelperV2*)data)->setMediaCas(casToken, size);
    };
    wrapper->name = [](
            void *data) -> const char * {
        return ((MediaExtractorPluginHelperV2*)data)->name();
    };
    return wrapper;
}

/* adds some convience methods */
class DataSourceHelper {
public:
    explicit DataSourceHelper(CDataSource *csource) {
        mSource = csource;
    }

    explicit DataSourceHelper(DataSourceHelper *source) {
        mSource = source->mSource;
    }

    virtual ~DataSourceHelper() {}

    virtual ssize_t readAt(off64_t offset, void *data, size_t size) {
        return mSource->readAt(mSource->handle, offset, data, size);
    }

    virtual status_t getSize(off64_t *size) {
        return mSource->getSize(mSource->handle, size);
    }

    bool getUri(char *uriString, size_t bufferSize) {
        return mSource->getUri(mSource->handle, uriString, bufferSize);
    }

    virtual uint32_t flags() {
        return mSource->flags(mSource->handle);
    }

    // Convenience methods:
    bool getUInt16(off64_t offset, uint16_t *x) {
        *x = 0;

        uint8_t byte[2];
        if (readAt(offset, byte, 2) != 2) {
            return false;
        }

        *x = (byte[0] << 8) | byte[1];

        return true;
    }

    // 3 byte int, returned as a 32-bit int
    bool getUInt24(off64_t offset, uint32_t *x) {
        *x = 0;

        uint8_t byte[3];
        if (readAt(offset, byte, 3) != 3) {
            return false;
        }

        *x = (byte[0] << 16) | (byte[1] << 8) | byte[2];

        return true;
    }

    bool getUInt32(off64_t offset, uint32_t *x) {
        *x = 0;

        uint32_t tmp;
        if (readAt(offset, &tmp, 4) != 4) {
            return false;
        }

        *x = ntohl(tmp);

        return true;
    }

    bool getUInt64(off64_t offset, uint64_t *x) {
        *x = 0;

        uint64_t tmp;
        if (readAt(offset, &tmp, 8) != 8) {
            return false;
        }

        *x = ((uint64_t)ntohl(tmp & 0xffffffff) << 32) | ntohl(tmp >> 32);

        return true;
    }

    // read either int<N> or int<2N> into a uint<2N>_t, size is the int size in bytes.
    bool getUInt16Var(off64_t offset, uint16_t *x, size_t size) {
        if (size == 2) {
            return getUInt16(offset, x);
        }
        if (size == 1) {
            uint8_t tmp;
            if (readAt(offset, &tmp, 1) == 1) {
                *x = tmp;
                return true;
            }
        }
        return false;
    }

    bool getUInt32Var(off64_t offset, uint32_t *x, size_t size) {
        if (size == 4) {
            return getUInt32(offset, x);
        }
        if (size == 2) {
            uint16_t tmp;
            if (getUInt16(offset, &tmp)) {
                *x = tmp;
                return true;
            }
        }
        return false;
    }

    bool getUInt64Var(off64_t offset, uint64_t *x, size_t size) {
        if (size == 8) {
            return getUInt64(offset, x);
        }
        if (size == 4) {
            uint32_t tmp;
            if (getUInt32(offset, &tmp)) {
                *x = tmp;
                return true;
            }
        }
        return false;
    }

protected:
    CDataSource *mSource;
};



// helpers to create a media_uuid_t from a string literal

// purposely not defined anywhere so that this will fail to link if
// expressions below are not evaluated at compile time
int invalid_uuid_string(const char *);

template <typename T, size_t N>
constexpr uint8_t _digitAt_(const T (&s)[N], const size_t n) {
    return s[n] >= '0' && s[n] <= '9' ? s[n] - '0'
            : s[n] >= 'a' && s[n] <= 'f' ? s[n] - 'a' + 10
                    : s[n] >= 'A' && s[n] <= 'F' ? s[n] - 'A' + 10
                            : invalid_uuid_string("uuid: bad digits");
}

template <typename T, size_t N>
constexpr uint8_t _hexByteAt_(const T (&s)[N], size_t n) {
    return (_digitAt_(s, n) << 4) + _digitAt_(s, n + 1);
}

constexpr bool _assertIsDash_(char c) {
    return c == '-' ? true : invalid_uuid_string("Wrong format");
}

template <size_t N>
constexpr media_uuid_t constUUID(const char (&s) [N]) {
    static_assert(N == 37, "uuid: wrong length");
    return
            _assertIsDash_(s[8]),
            _assertIsDash_(s[13]),
            _assertIsDash_(s[18]),
            _assertIsDash_(s[23]),
            media_uuid_t {{
                _hexByteAt_(s, 0),
                _hexByteAt_(s, 2),
                _hexByteAt_(s, 4),
                _hexByteAt_(s, 6),
                _hexByteAt_(s, 9),
                _hexByteAt_(s, 11),
                _hexByteAt_(s, 14),
                _hexByteAt_(s, 16),
                _hexByteAt_(s, 19),
                _hexByteAt_(s, 21),
                _hexByteAt_(s, 24),
                _hexByteAt_(s, 26),
                _hexByteAt_(s, 28),
                _hexByteAt_(s, 30),
                _hexByteAt_(s, 32),
                _hexByteAt_(s, 34),
            }};
}
// Convenience macro to create a media_uuid_t from a string literal, which should
// be formatted as "12345678-1234-1234-1234-123456789abc", as generated by
// e.g. https://www.uuidgenerator.net/ or the 'uuidgen' linux command.
// Hex digits may be upper or lower case.
//
// The macro call is otherwise equivalent to specifying the structure directly
// (e.g. UUID("7d613858-5837-4a38-84c5-332d1cddee27") is the same as
//       {{0x7d, 0x61, 0x38, 0x58, 0x58, 0x37, 0x4a, 0x38,
//         0x84, 0xc5, 0x33, 0x2d, 0x1c, 0xdd, 0xee, 0x27}})

#define UUID(str) []{ constexpr media_uuid_t uuid = constUUID(str); return uuid; }()

}  // namespace android

#endif  // MEDIA_EXTRACTOR_PLUGIN_HELPER_H_
