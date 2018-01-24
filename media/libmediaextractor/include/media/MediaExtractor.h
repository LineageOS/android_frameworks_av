/*
 * Copyright (C) 2009 The Android Open Source Project
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

#ifndef MEDIA_EXTRACTOR_H_

#define MEDIA_EXTRACTOR_H_

#include <stdio.h>
#include <vector>

#include <utils/Errors.h>
#include <utils/RefBase.h>

namespace android {

class DataSource;
class MetaData;
class String8;
struct AMessage;
struct MediaSource;
typedef std::vector<uint8_t> HInterfaceToken;

class MediaExtractor : public RefBase {
public:
    virtual size_t countTracks() = 0;
    virtual sp<MediaSource> getTrack(size_t index) = 0;

    enum GetTrackMetaDataFlags {
        kIncludeExtensiveMetaData = 1
    };
    virtual sp<MetaData> getTrackMetaData(
            size_t index, uint32_t flags = 0) = 0;

    // Return container specific meta-data. The default implementation
    // returns an empty metadata object.
    virtual sp<MetaData> getMetaData();

    enum Flags {
        CAN_SEEK_BACKWARD  = 1,  // the "seek 10secs back button"
        CAN_SEEK_FORWARD   = 2,  // the "seek 10secs forward button"
        CAN_PAUSE          = 4,
        CAN_SEEK           = 8,  // the "seek bar"
    };

    // If subclasses do _not_ override this, the default is
    // CAN_SEEK_BACKWARD | CAN_SEEK_FORWARD | CAN_SEEK | CAN_PAUSE
    virtual uint32_t flags() const;

    // for DRM
    virtual char* getDrmTrackInfo(size_t /*trackID*/, int * /*len*/) {
        return NULL;
    }
    virtual void setUID(uid_t /*uid*/) {
    }
    virtual status_t setMediaCas(const HInterfaceToken &/*casToken*/) {
        return INVALID_OPERATION;
    }

    virtual const char * name() { return "<unspecified>"; }

    virtual void release() {}
    typedef MediaExtractor* (*CreatorFunc)(
            const sp<DataSource> &source, const sp<AMessage> &meta);

    // The sniffer can optionally fill in "meta" with an AMessage containing
    // a dictionary of values that helps the corresponding extractor initialize
    // its state without duplicating effort already exerted by the sniffer.
    typedef CreatorFunc (*SnifferFunc)(
            const sp<DataSource> &source, String8 *mimeType,
            float *confidence, sp<AMessage> *meta);

    typedef struct {
        const uint8_t b[16];
    } uuid_t;

    typedef struct {
        // version number of this structure
        const uint32_t def_version;

        // A unique identifier for this extractor.
        // See below for a convenience macro to create this from a string.
        uuid_t extractor_uuid;

        // Version number of this extractor. When two extractors with the same
        // uuid are encountered, the one with the largest version number will
        // be used.
        const uint32_t extractor_version;

        // a human readable name
        const char *extractor_name;

        // the sniffer function
        const SnifferFunc sniff;
    } ExtractorDef;

    static const uint32_t EXTRACTORDEF_VERSION = 1;

    typedef ExtractorDef (*GetExtractorDef)();

protected:
    MediaExtractor();
    virtual ~MediaExtractor();

private:
    MediaExtractor(const MediaExtractor &);
    MediaExtractor &operator=(const MediaExtractor &);
};

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
constexpr MediaExtractor::uuid_t constUUID(const char (&s) [N]) {
    static_assert(N == 37, "uuid: wrong length");
    return
            _assertIsDash_(s[8]),
            _assertIsDash_(s[13]),
            _assertIsDash_(s[18]),
            _assertIsDash_(s[23]),
            MediaExtractor::uuid_t {{
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
// Convenience macro to create a uuid_t from a string literal, which should
// be formatted as "12345678-1234-1234-1234-123456789abc", as generated by
// e.g. https://www.uuidgenerator.net/ or the 'uuidgen' linux command.
// Hex digits may be upper or lower case.
//
// The macro call is otherwise equivalent to specifying the structure directly
// (e.g. UUID("7d613858-5837-4a38-84c5-332d1cddee27") is the same as
//       {{0x7d, 0x61, 0x38, 0x58, 0x58, 0x37, 0x4a, 0x38,
//         0x84, 0xc5, 0x33, 0x2d, 0x1c, 0xdd, 0xee, 0x27}})

#define UUID(str) []{ constexpr MediaExtractor::uuid_t uuid = constUUID(str); return uuid; }()



}  // namespace android

#endif  // MEDIA_EXTRACTOR_H_
