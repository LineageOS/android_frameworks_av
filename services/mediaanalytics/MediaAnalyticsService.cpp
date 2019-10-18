/*
 * Copyright (C) 2017 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaAnalyticsService"
#include <utils/Log.h>

#include "MediaAnalyticsService.h"

#include <pwd.h> //getpwuid

#include <audio_utils/clock.h>                 // clock conversions
#include <android/content/pm/IPackageManagerNative.h>  // package info
#include <binder/IPCThreadState.h>             // get calling uid
#include <cutils/properties.h>                 // for property_get
#include <private/android_filesystem_config.h> // UID

namespace android {

// individual records kept in memory: age or count
// age: <= 28 hours (1 1/6 days)
// count: hard limit of # records
// (0 for either of these disables that threshold)
//
static constexpr nsecs_t kMaxRecordAgeNs = 28 * 3600 * NANOS_PER_SECOND;
// 2019/6: average daily per device is currently 375-ish;
// setting this to 2000 is large enough to catch most devices
// we'll lose some data on very very media-active devices, but only for
// the gms collection; statsd will have already covered those for us.
// This also retains enough information to help with bugreports
static constexpr size_t kMaxRecords = 2000;

// max we expire in a single call, to constrain how long we hold the
// mutex, which also constrains how long a client might wait.
static constexpr size_t kMaxExpiredAtOnce = 50;

// TODO: need to look at tuning kMaxRecords and friends for low-memory devices

MediaAnalyticsService::MediaAnalyticsService()
        : mMaxRecords(kMaxRecords),
          mMaxRecordAgeNs(kMaxRecordAgeNs),
          mMaxRecordsExpiredAtOnce(kMaxExpiredAtOnce),
          mDumpProtoDefault(MediaAnalyticsItem::PROTO_V1)
{
    ALOGD("%s", __func__);
}

MediaAnalyticsService::~MediaAnalyticsService()
{
    ALOGD("%s", __func__);
    // the class destructor clears anyhow, but we enforce clearing items first.
    mItemsDiscarded += mItems.size();
    mItems.clear();
}

status_t MediaAnalyticsService::submitInternal(MediaAnalyticsItem *item, bool release)
{
    // we control these, generally not trusting user input
    nsecs_t now = systemTime(SYSTEM_TIME_REALTIME);
    // round nsecs to seconds
    now = (now + NANOS_PER_SECOND / 2) / NANOS_PER_SECOND * NANOS_PER_SECOND;
    // TODO: if we convert to boot time, do we need to round timestamp?
    item->setTimestamp(now);

    const int pid = IPCThreadState::self()->getCallingPid();
    const int uid = IPCThreadState::self()->getCallingUid();
    const int uid_given = item->getUid();
    const int pid_given = item->getPid();

    ALOGV("%s: caller has uid=%d, embedded uid=%d", __func__, uid, uid_given);
    bool isTrusted;
    switch (uid) {
    case AID_DRM:
    case AID_MEDIA:
    case AID_MEDIA_CODEC:
    case AID_MEDIA_EX:
    case AID_MEDIA_DRM:
        // trusted source, only override default values
        isTrusted = true;
        if (uid_given == -1) {
            item->setUid(uid);
        }
        if (pid_given == -1) {
            item->setPid(pid);
        }
        break;
    default:
        isTrusted = false;
        item->setPid(pid);
        item->setUid(uid);
        break;
    }

    // Overwrite package name and version if the caller was untrusted.
    if (!isTrusted) {
        mUidInfo.setPkgInfo(item, item->getUid(), true, true);
    } else if (item->getPkgName().empty()) {
        // empty, so fill out both parts
        mUidInfo.setPkgInfo(item, item->getUid(), true, true);
    } else {
        // trusted, provided a package, do nothing
    }

    ALOGV("%s: given uid %d; sanitized uid: %d sanitized pkg: %s "
          "sanitized pkg version: %lld",
          __func__,
          uid_given, item->getUid(),
          item->getPkgName().c_str(),
          (long long)item->getPkgVersionCode());

    mItemsSubmitted++;

    // validate the record; we discard if we don't like it
    if (isContentValid(item, isTrusted) == false) {
        if (release) delete item;
        return PERMISSION_DENIED;
    }

    // XXX: if we have a sessionid in the new record, look to make
    // sure it doesn't appear in the finalized list.

    if (item->count() == 0) {
        ALOGV("%s: dropping empty record...", __func__);
        if (release) delete item;
        return BAD_VALUE;
    }

    // send to statsd
    extern bool dump2Statsd(MediaAnalyticsItem *item);  // extern hook
    (void)dump2Statsd(item);  // failure should be logged in function.

    if (!release) item = item->dup();
    saveItem(item);
    return NO_ERROR;
}

status_t MediaAnalyticsService::dump(int fd, const Vector<String16>& args)
{
    String8 result;

    if (checkCallingPermission(String16("android.permission.DUMP")) == false) {
        result.appendFormat("Permission Denial: "
                "can't dump MediaAnalyticsService from pid=%d, uid=%d\n",
                IPCThreadState::self()->getCallingPid(),
                IPCThreadState::self()->getCallingUid());
        write(fd, result.string(), result.size());
        return NO_ERROR;
    }

    // crack any parameters
    const String16 protoOption("-proto");
    int chosenProto = mDumpProtoDefault;
    const String16 clearOption("-clear");
    bool clear = false;
    const String16 sinceOption("-since");
    nsecs_t ts_since = 0;
    const String16 helpOption("-help");
    const String16 onlyOption("-only");
    std::string only;
    const int n = args.size();
    for (int i = 0; i < n; i++) {
        if (args[i] == clearOption) {
            clear = true;
        } else if (args[i] == protoOption) {
            i++;
            if (i < n) {
                String8 value(args[i]);
                int proto = MediaAnalyticsItem::PROTO_V0;
                char *endp;
                const char *p = value.string();
                proto = strtol(p, &endp, 10);
                if (endp != p || *endp == '\0') {
                    if (proto < MediaAnalyticsItem::PROTO_FIRST) {
                        proto = MediaAnalyticsItem::PROTO_FIRST;
                    } else if (proto > MediaAnalyticsItem::PROTO_LAST) {
                        proto = MediaAnalyticsItem::PROTO_LAST;
                    }
                    chosenProto = proto;
                } else {
                    result.append("unable to parse value for -proto\n\n");
                }
            } else {
                result.append("missing value for -proto\n\n");
            }
        } else if (args[i] == sinceOption) {
            i++;
            if (i < n) {
                String8 value(args[i]);
                char *endp;
                const char *p = value.string();
                ts_since = strtoll(p, &endp, 10);
                if (endp == p || *endp != '\0') {
                    ts_since = 0;
                }
            } else {
                ts_since = 0;
            }
            // command line is milliseconds; internal units are nano-seconds
            ts_since *= NANOS_PER_MILLISECOND;
        } else if (args[i] == onlyOption) {
            i++;
            if (i < n) {
                String8 value(args[i]);
                only = value.string();
            }
        } else if (args[i] == helpOption) {
            // TODO: consider function area dumping.
            // dumpsys media.metrics audiotrack,codec
            // or dumpsys media.metrics audiotrack codec

            result.append("Recognized parameters:\n");
            result.append("-help        this help message\n");
            result.append("-proto #     dump using protocol #");
            result.append("-clear       clears out saved records\n");
            result.append("-only X      process records for component X\n");
            result.append("-since X     include records since X\n");
            result.append("             (X is milliseconds since the UNIX epoch)\n");
            write(fd, result.string(), result.size());
            return NO_ERROR;
        }
    }

    {
        std::lock_guard _l(mLock);

        result.appendFormat("Dump of the %s process:\n", kServiceName);
        dumpHeaders_l(result, chosenProto, ts_since);
        dumpRecent_l(result, chosenProto, ts_since, only.c_str());

        if (clear) {
            mItemsDiscarded += mItems.size();
            mItems.clear();
            // shall we clear the summary data too?
        }
    }

    write(fd, result.string(), result.size());
    return NO_ERROR;
}

// dump headers
void MediaAnalyticsService::dumpHeaders_l(String8 &result, int dumpProto, nsecs_t ts_since)
{
    result.appendFormat("Protocol Version: %d\n", dumpProto);
    if (MediaAnalyticsItem::isEnabled()) {
        result.append("Metrics gathering: enabled\n");
    } else {
        result.append("Metrics gathering: DISABLED via property\n");
    }
    result.appendFormat(
            "Since Boot: Submissions: %lld Accepted: %lld\n",
            (long long)mItemsSubmitted.load(), (long long)mItemsFinalized);
    result.appendFormat(
            "Records Discarded: %lld (by Count: %lld by Expiration: %lld)\n",
            (long long)mItemsDiscarded, (long long)mItemsDiscardedCount,
            (long long)mItemsDiscardedExpire);
    if (ts_since != 0) {
        result.appendFormat(
            "Emitting Queue entries more recent than: %lld\n",
            (long long)ts_since);
    }
}

void MediaAnalyticsService::dumpRecent_l(
        String8 &result, int dumpProto, nsecs_t ts_since, const char * only)
{
    if (only != nullptr && *only == '\0') {
        only = nullptr;
    }
    result.append("\nFinalized Metrics (oldest first):\n");
    dumpQueue_l(result, dumpProto, ts_since, only);

    // show who is connected and injecting records?
    // talk about # records fed to the 'readers'
    // talk about # records we discarded, perhaps "discarded w/o reading" too
}

void MediaAnalyticsService::dumpQueue_l(String8 &result, int dumpProto) {
    dumpQueue_l(result, dumpProto, (nsecs_t) 0, nullptr /* only */);
}

void MediaAnalyticsService::dumpQueue_l(
        String8 &result, int dumpProto, nsecs_t ts_since, const char * only) {
    int slot = 0;

    if (mItems.empty()) {
        result.append("empty\n");
    } else {
        for (const auto &item : mItems) {
            nsecs_t when = item->getTimestamp();
            if (when < ts_since) {
                continue;
            }
            // TODO: Only should be a set<string>
            if (only != nullptr &&
                    item->getKey() /* std::string */ != only) {
                ALOGV("%s: omit '%s', it's not '%s'",
                        __func__, item->getKey().c_str(), only);
                continue;
            }
            result.appendFormat("%5d: %s\n",
                   slot, item->toString(dumpProto).c_str());
            slot++;
        }
    }
}

//
// Our Cheap in-core, non-persistent records management.

// if item != NULL, it's the item we just inserted
// true == more items eligible to be recovered
bool MediaAnalyticsService::expirations_l(MediaAnalyticsItem *item)
{
    bool more = false;

    // check queue size
    size_t overlimit = 0;
    if (mMaxRecords > 0 && mItems.size() > mMaxRecords) {
        overlimit = mItems.size() - mMaxRecords;
        if (overlimit > mMaxRecordsExpiredAtOnce) {
            more = true;
            overlimit = mMaxRecordsExpiredAtOnce;
        }
    }

    // check queue times
    size_t expired = 0;
    if (!more && mMaxRecordAgeNs > 0) {
        const nsecs_t now = systemTime(SYSTEM_TIME_REALTIME);
        // we check one at a time, skip search would be more efficient.
        size_t i = overlimit;
        for (; i < mItems.size(); ++i) {
            auto &oitem = mItems[i];
            nsecs_t when = oitem->getTimestamp();
            if (oitem.get() == item) {
                break;
            }
            if (now > when && (now - when) <= mMaxRecordAgeNs) {
                break;  // TODO: if we use BOOTTIME, should be monotonic.
            }
            if (i >= mMaxRecordsExpiredAtOnce) {
                // this represents "one too many"; tell caller there are
                // more to be reclaimed.
                more = true;
                break;
            }
        }
        expired = i - overlimit;
    }

    if (const size_t toErase = overlimit + expired;
            toErase > 0) {
        mItemsDiscardedCount += overlimit;
        mItemsDiscardedExpire += expired;
        mItemsDiscarded += toErase;
        mItems.erase(mItems.begin(), mItems.begin() + toErase); // erase from front
    }
    return more;
}

void MediaAnalyticsService::processExpirations()
{
    bool more;
    do {
        sleep(1);
        std::lock_guard _l(mLock);
        more = expirations_l(nullptr);
    } while (more);
}

void MediaAnalyticsService::saveItem(MediaAnalyticsItem *item)
{
    std::lock_guard _l(mLock);
    // we assume the items are roughly in time order.
    mItems.emplace_back(item);
    ++mItemsFinalized;
    if (expirations_l(item)
            && (!mExpireFuture.valid()
               || mExpireFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready)) {
        mExpireFuture = std::async(std::launch::async, [this] { processExpirations(); });
    }
}

/* static */
bool MediaAnalyticsService::isContentValid(const MediaAnalyticsItem *item, bool isTrusted)
{
    if (isTrusted) return true;
    // untrusted uids can only send us a limited set of keys
    const std::string &key = item->getKey();
    for (const char *allowedKey : {
                                     "audiopolicy",
                                     "audiorecord",
                                     "audiothread",
                                     "audiotrack",
                                     "codec",
                                     "extractor",
                                     "nuplayer",
                                 }) {
        if (key == allowedKey) {
            return true;
        }
    }
    ALOGD("%s: invalid key: %s", __func__, item->toString().c_str());
    return false;
}

// are we rate limited, normally false
bool MediaAnalyticsService::isRateLimited(MediaAnalyticsItem *) const
{
    return false;
}

// How long we hold package info before we re-fetch it
constexpr nsecs_t PKG_EXPIRATION_NS = 30 * 60 * NANOS_PER_SECOND; // 30 minutes

// give me the package name, perhaps going to find it
// manages its own mutex operations internally
void MediaAnalyticsService::UidInfo::setPkgInfo(
        MediaAnalyticsItem *item, uid_t uid, bool setName, bool setVersion)
{
    ALOGV("%s: uid=%d", __func__, uid);

    if (!setName && !setVersion) {
        return;  // setting nothing? strange
    }

    const nsecs_t now = systemTime(SYSTEM_TIME_REALTIME);
    struct UidToPkgInfo mapping;
    {
        std::lock_guard _l(mUidInfoLock);
        auto it = mPkgMappings.find(uid);
        if (it != mPkgMappings.end()) {
            mapping = it->second;
            ALOGV("%s: uid %d expiration %lld now %lld",
                    __func__, uid, (long long)mapping.expiration, (long long)now);
            if (mapping.expiration <= now) {
                // purge the stale entry and fall into re-fetching
                ALOGV("%s: entry for uid %d expired, now %lld",
                        __func__, uid, (long long)now);
                mPkgMappings.erase(it);
                mapping.uid = (uid_t)-1;  // this is always fully overwritten
            }
        }
    }

    // if we did not find it
    if (mapping.uid == (uid_t)(-1)) {
        std::string pkg;
        std::string installer;
        int64_t versionCode = 0;

        const struct passwd *pw = getpwuid(uid);
        if (pw) {
            pkg = pw->pw_name;
        }

        sp<IServiceManager> sm = defaultServiceManager();
        sp<content::pm::IPackageManagerNative> package_mgr;
        if (sm.get() == nullptr) {
            ALOGE("%s: Cannot find service manager", __func__);
        } else {
            sp<IBinder> binder = sm->getService(String16("package_native"));
            if (binder.get() == nullptr) {
                ALOGE("%s: Cannot find package_native", __func__);
            } else {
                package_mgr = interface_cast<content::pm::IPackageManagerNative>(binder);
            }
        }

        if (package_mgr != nullptr) {
            std::vector<int> uids;
            std::vector<std::string> names;
            uids.push_back(uid);
            binder::Status status = package_mgr->getNamesForUids(uids, &names);
            if (!status.isOk()) {
                ALOGE("%s: getNamesForUids failed: %s",
                        __func__, status.exceptionMessage().c_str());
            }
            if (!names[0].empty()) {
                pkg = names[0].c_str();
            }
        }

        // strip any leading "shared:" strings that came back
        if (pkg.compare(0, 7, "shared:") == 0) {
            pkg.erase(0, 7);
        }
        // determine how pkg was installed and the versionCode
        if (pkg.empty()) {
            pkg = std::to_string(uid); // no name for us to manage
        } else if (strchr(pkg.c_str(), '.') == NULL) {
            // not of form 'com.whatever...'; assume internal and ok
        } else if (strncmp(pkg.c_str(), "android.", 8) == 0) {
            // android.* packages are assumed fine
        } else if (package_mgr.get() != nullptr) {
            String16 pkgName16(pkg.c_str());
            binder::Status status = package_mgr->getInstallerForPackage(pkgName16, &installer);
            if (!status.isOk()) {
                ALOGE("%s: getInstallerForPackage failed: %s",
                        __func__, status.exceptionMessage().c_str());
            }

            // skip if we didn't get an installer
            if (status.isOk()) {
                status = package_mgr->getVersionCodeForPackage(pkgName16, &versionCode);
                if (!status.isOk()) {
                    ALOGE("%s: getVersionCodeForPackage failed: %s",
                            __func__, status.exceptionMessage().c_str());
                }
            }

            ALOGV("%s: package '%s' installed by '%s' versioncode %lld",
                    __func__, pkg.c_str(), installer.c_str(), (long long)versionCode);

            if (strncmp(installer.c_str(), "com.android.", 12) == 0) {
                // from play store, we keep info
            } else if (strncmp(installer.c_str(), "com.google.", 11) == 0) {
                // some google source, we keep info
            } else if (strcmp(installer.c_str(), "preload") == 0) {
                // preloads, we keep the info
            } else if (installer.c_str()[0] == '\0') {
                // sideload (no installer); report UID only
                pkg = std::to_string(uid);
                versionCode = 0;
            } else {
                // unknown installer; report UID only
                pkg = std::to_string(uid);
                versionCode = 0;
            }
        } else {
            // unvalidated by package_mgr just send uid.
            pkg = std::to_string(uid);
        }

        // add it to the map, to save a subsequent lookup
        std::lock_guard _l(mUidInfoLock);
        // always overwrite
        mapping.uid = uid;
        mapping.pkg = std::move(pkg);
        mapping.installer = std::move(installer);
        mapping.versionCode = versionCode;
        mapping.expiration = now + PKG_EXPIRATION_NS;
        ALOGV("%s: adding uid %d pkg '%s' expiration: %lld",
                __func__, uid, mapping.pkg.c_str(), (long long)mapping.expiration);
        mPkgMappings[uid] = mapping;
    }

    if (mapping.uid != (uid_t)(-1)) {
        if (setName) {
            item->setPkgName(mapping.pkg);
        }
        if (setVersion) {
            item->setPkgVersionCode(mapping.versionCode);
        }
    }
}

} // namespace android
