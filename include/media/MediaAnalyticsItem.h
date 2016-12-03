/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_MEDIA_MEDIAANALYTICSITEM_H
#define ANDROID_MEDIA_MEDIAANALYTICSITEM_H

#include <cutils/properties.h>
#include <sys/types.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/RefBase.h>
#include <utils/StrongPointer.h>
#include <utils/Timers.h>

#include <media/stagefright/foundation/AString.h>

namespace android {



class IMediaAnalyticsService;

// the class interface
//

class MediaAnalyticsItem : public RefBase {

    friend class MediaAnalyticsService;
    friend class IMediaAnalyticsService;

    public:

        // sessionid
        // unique within device, within boot,
        typedef int64_t SessionID_t;
        static constexpr SessionID_t SessionIDInvalid = -1;
        static constexpr SessionID_t SessionIDNone = 0;

        // Key: the record descriminator
        // values for the record discriminator
        // values can be "component/component"
        // basic values: "video", "audio", "drm"
        // XXX: need to better define the format
        typedef AString Key;
        static const Key kKeyNone;              // ""
        static const Key kKeyAny;               // "*"

        // Attr: names for attributes within a record
        // format "prop1" or "prop/subprop"
        // XXX: need to better define the format
        typedef AString Attr;


    public:

        // access functions for the class
        MediaAnalyticsItem();
        MediaAnalyticsItem(Key);
        ~MediaAnalyticsItem();

        // so clients can send intermediate values to be overlaid later
        MediaAnalyticsItem &setFinalized(bool);
        bool getFinalized() const;

        // SessionID ties multiple submissions for same key together
        // so that if video "height" and "width" are known at one point
        // and "framerate" is only known later, they can be be brought
        // together.
        MediaAnalyticsItem &setSessionID(SessionID_t);
        MediaAnalyticsItem &clearSessionID();
        SessionID_t getSessionID() const;
        // generates and stores a new ID iff mSessionID == SessionIDNone
        SessionID_t generateSessionID();

        // reset all contents, discarding any extra data
        void clear();

        // set the key discriminator for the record.
        // most often initialized as part of the constructor
        MediaAnalyticsItem &setKey(MediaAnalyticsItem::Key);
        MediaAnalyticsItem::Key getKey();

        // # of attributes in the record
        int32_t count() const;

        // set values appropriately
        // return values tell us whether we overwrote an existing value
        bool setInt32(Attr, int32_t value);
        bool setInt64(Attr, int64_t value);
        bool setDouble(Attr, double value);
        bool setCString(Attr, const char *value);

        // fused get/add/set; if attr wasn't there, it's a simple set.
        // type-mismatch counts as "wasn't there".
        // return value tells us whether we overwrote an existing value
        bool addInt32(Attr, int32_t value);
        bool addInt64(Attr, int64_t value);
        bool addDouble(Attr, double value);

        // find & extract values
        // return indicates whether attr exists (and thus value filled in)
        bool getInt32(Attr, int32_t *value);
        bool getInt64(Attr, int64_t *value);
        bool getDouble(Attr, double *value);
        bool getCString(Attr, char **value);

        // parameter indicates whether to close any existing open
        // record with same key before establishing a new record
        bool selfrecord(bool);
        bool selfrecord();

        // remove indicated attributes and their values
        // filterNot() could also be called keepOnly()
        // return value is # attributes removed
        // XXX: perhaps 'remove' instead of 'filter'
        // XXX: filterNot would become 'keep'
        int32_t filter(int count, Attr attrs[]);
        int32_t filterNot(int count, Attr attrs[]);
        int32_t filter(Attr attr);

        // below here are used on server side or to talk to server
        // clients need not worry about these.

        // timestamp, pid, and uid only used on server side
	// timestamp is in 'nanoseconds, unix time'
        MediaAnalyticsItem &setTimestamp(nsecs_t);
        nsecs_t getTimestamp() const;

        MediaAnalyticsItem &setPid(pid_t);
        pid_t getPid() const;

        MediaAnalyticsItem &setUid(uid_t);
        uid_t getUid() const;

        // our serialization code for binder calls
        int32_t writeToParcel(Parcel *);
        int32_t readFromParcel(const Parcel&);

        AString toString();

        // are we collecting analytics data
        static bool isEnabled();

    protected:

        // merge fields from arg into this
        // with rules for first/last/add, etc
        // XXX: document semantics and how they are indicated
        bool merge(sp<MediaAnalyticsItem> );

        // enabled 1, disabled 0
        static const char * const EnabledProperty;
        static const char * const EnabledPropertyPersist;
        static const int   EnabledProperty_default;

    private:

        // to help validate that A doesn't mess with B's records
        pid_t     mPid;
        uid_t     mUid;

        // let's reuse a binder connection
        static sp<IMediaAnalyticsService> sAnalyticsService;
        static sp<IMediaAnalyticsService> getInstance();

        // tracking information
        SessionID_t mSessionID;         // grouping similar records
        nsecs_t mTimestamp;             // ns, system_time_monotonic

        // will this record accept further updates
        bool mFinalized;

        Key mKey;

        class Item : public RefBase {

         public:

            enum Type {
                kTypeNone = 0,
                kTypeInt32 = 1,
                kTypeInt64 = 2,
                kTypeDouble = 3,
                kTypeCString = 4,
            };

            Item();
            ~Item();
            void clear();

            Type mType;
            union {
                    int32_t int32Value;
                    int64_t int64Value;
                    double doubleValue;
                    char *CStringValue;
            } u;
        };
        KeyedVector<Attr, sp<Item>> mItems;

};

} // namespace android

#endif
