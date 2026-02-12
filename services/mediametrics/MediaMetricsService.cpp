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
#define LOG_TAG "MediaMetricsService"
#include <utils/Log.h>

#include "MediaMetricsService.h"
#include "ValidateId.h"
#include "iface_statsd.h"

#include <media/MediaMetricsInternal.h>

#include <dlfcn.h>
#include <pwd.h> //getpwuid
#include <stdio.h>

#include <android-base/stringprintf.h>
#include <audio_utils/clock.h>                 // clock conversions
#include <binder/IPCThreadState.h>             // get calling uid
#include <binder/IServiceManager.h>
#include <cutils/properties.h>                 // for property_get
#include <private/android_filesystem_config.h> // UID
#include <stats_media_metrics.h>

#ifdef METRICS_IN_MODULE

#include <aidl/android/media/BnMediaMetricsService.h>
#include <android/binder_auto_utils.h>  // for AIBinder stuff
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <android/permission_manager.h>

#else

#include <android/content/pm/IPackageManagerNative.h>  // package info
#include <mediautils/MemoryLeakTrackUtil.h>
#include <mediautils/ServiceUtilities.h>        // for mediautils::UidInfo::getInfo()
#include <memunreachable/memunreachable.h>

#endif

#include <set>
#include <unordered_map>

#include <dlfcn.h>

namespace android {

using base::StringPrintf;
using mediametrics::Item;
using mediametrics::startsWith;


/**
 * Submits the indicated record to the mediaanalytics service.
 *
 * \param item the item to submit.
 * \return status failure, which is negative on binder transaction failure.
 *         As the transaction is one-way, remote failures will not be reported.
 */

binder::Status
MediaMetricsService::submitStructuredItem(const StructuredItem& b) {
    status_t status = UNKNOWN_ERROR;
    std::shared_ptr<mediametrics::Item> item = nullptr;

    item = mediametrics::readFromStructuredItem(&b);
    if (item != nullptr) {
        status = submitInternal(item);
    }
    return binder::Status::fromStatusT(status);
}

// individual records kept in memory: age or count
// age: <= 28 hours (1 1/6 days)
// count: hard limit of # records
// (0 for either of these disables that threshold)
//
static constexpr nsecs_t kMaxRecordAgeNs = 28 * 3600 * NANOS_PER_SECOND;

// Max records to keep in queue which dump out for bugreports.
static constexpr size_t kMaxRecords = 2500;

// max we expire in a single call, to constrain how long we hold the
// mutex, which also constrains how long a client might wait.
static constexpr size_t kMaxExpiredAtOnce = 50;

// TODO: need to look at tuning kMaxRecords and friends for low-memory devices

/* static */
nsecs_t MediaMetricsService::roundTime(nsecs_t timeNs)
{
    return (timeNs + NANOS_PER_SECOND / 2) / NANOS_PER_SECOND * NANOS_PER_SECOND;
}

/* static */
bool MediaMetricsService::useUidForPackage(
        const std::string& package, const std::string& installer)
{
    // NOLINTBEGIN(bugprone-branch-clone)
    if (strchr(package.c_str(), '.') == nullptr) {
        return false;  // not of form 'com.whatever...'; assume internal and ok
    } else if (strncmp(package.c_str(), "android.", 8) == 0) {
        return false;  // android.* packages are assumed fine
    } else if (strncmp(installer.c_str(), "com.android.", 12) == 0) {
        return false;  // from play store
    } else if (strncmp(installer.c_str(), "com.google.", 11) == 0) {
        return false;  // some google source
    } else if (strcmp(installer.c_str(), "preload") == 0) {
        return false;  // preloads
    } else {
        return true;  // we're not sure where it came from, use uid only.
    }
    // NOLINTEND(bugprone-branch-clone)
}

static pid_t getClientPid() {
    pid_t pid;

#ifdef  METRICS_IN_MODULE
    pid = AIBinder_getCallingPid();
#else
    pid = IPCThreadState::self()->getCallingPid();
#endif
    return pid;
}

static int32_t getClientUid() {
    int32_t uid;

#ifdef METRICS_IN_MODULE
    // use an NDK supported call
    uid = AIBinder_getCallingUid();
#else
    // we can use internal calls
    uid = IPCThreadState::self()->getCallingUid();
#endif

    return uid;
}

// cache of uid -> packageinfo mapping
// static
std::mutex MediaMetricsService::sLock;
std::unordered_map<int, std::string> MediaMetricsService::sUid2Packages;
std::queue<int> MediaMetricsService::sCachedUids;

/* static */
std::pair<std::string, int64_t>
MediaMetricsService::getSanitizedPackageNameAndVersionCode(uid_t uid) {

#ifndef METRICS_IN_MODULE
        // in audio_utils, usese framework-only functions
    const std::shared_ptr<const mediautils::UidInfo::Info> info =
            mediautils::UidInfo::getInfo(uid);
    if (useUidForPackage(info->package, info->installer)) {
        return { std::to_string(uid), /* versionCode */ 0 };
    } else {
        return { info->package, info->versionCode };
    }
#else
    std::string pkg;

    // keep a cache of uid->packageName
    // start over on each reboot of the device
    //
    // Assumes:
    // (1) uid's are NOT reused without a reboot
    //     [so if an app is removed, we believe uid is not reused]

    // mutex between reading here and updating below
    {
        std::lock_guard _l(sLock);

        if (sUid2Packages.find(uid) != sUid2Packages.end()) {
            pkg = sUid2Packages[uid];
            // implement a cheap LRU algorithm
            int accessed = sCachedUids.front();
            sCachedUids.pop();
            sCachedUids.push(accessed);

            return { pkg, /* versionCode */ 0 };
        }
        // fall through to look it up the hard way
    }

    if (pkg.empty()) {
        ALOGV("Constructing from getpw() entries for uid %d", uid);
        struct passwd pw{}, *result;
        char buf[1024]; // extra buffer space - should exceed what is
                        // required in struct passwd_pw (tested),
                        // and even then this is only used in backup
                        // when the package manager is unavailable.
        if (getpwuid_r(uid, &pw, buf, sizeof(buf), &result) == 0
                && result != nullptr
                && result->pw_name != nullptr) {
            pkg = result->pw_name;
        }
    }

    if (pkg.empty()) {
        // last ditch fallback
        ALOGV("last ditch fallback for uid %d", uid);
        pkg = "fallback-" + std::to_string(uid);
    }

    ALOGV("we finish mapping uid %d to pkg: %s", uid, pkg.c_str());

    // mutex between updating here and reading above
    {
        std::lock_guard _l(sLock);

        // save whatever we generated, even if it wasn't our preferred getPackageInfo result
        if (sCachedUids.size() >= MAX_CACHED_UIDS) {
            int dropping = sCachedUids.front();
            sCachedUids.pop();
            sUid2Packages.erase(dropping);
        }
        sUid2Packages[uid] = pkg;
        sCachedUids.push(uid);
    }

    return { pkg, /* versionCode */ 0 };
#endif
}

MediaMetricsService::MediaMetricsService()
        : mMaxRecords(kMaxRecords),
          mMaxRecordAgeNs(kMaxRecordAgeNs),
          mMaxRecordsExpiredAtOnce(kMaxExpiredAtOnce)
{
    ALOGD("%s", __func__);
}

MediaMetricsService::~MediaMetricsService()
{
    ALOGD("%s", __func__);
    // the class destructor clears anyhow, but we enforce clearing items first.
    mItemsDiscarded += (int64_t)mItems.size();
    mItems.clear();
}

status_t MediaMetricsService::submitInternal(std::shared_ptr<mediametrics::Item>& item)
{
    // calling PID is 0 for one-way calls.
    const pid_t pid = getClientPid();
    const pid_t pid_given = item->getPid();
    const uid_t uid = getClientUid();
    const uid_t uid_given = item->getUid();

    //ALOGD("%s: caller pid=%d uid=%d,  item pid=%d uid=%d", __func__,
    //        (int)pid, (int)uid, (int) pid_given, (int)uid_given);

    bool isTrusted;
    switch (uid) {
    case AID_AUDIOSERVER:
    case AID_BLUETOOTH:
    case AID_CAMERA:
    case AID_DRM:
    case AID_MEDIA:
    case AID_MEDIA_CODEC:
    case AID_MEDIA_EX:
    case AID_MEDIA_DRM:
    // case AID_SHELL: // DEBUG ONLY - used for mediametrics_tests to add new keys
    case AID_SYSTEM:
        // trusted source, only override default values
        isTrusted = true;
        if (uid_given == (uid_t)-1) {
            item->setUid(uid);
        }
        if (pid_given == (pid_t)-1) {
            item->setPid(pid); // if one-way then this is 0.
        }
        break;
    default:
        isTrusted = false;
        item->setPid(pid); // always use calling pid, if one-way then this is 0.
        item->setUid(uid);
        break;
    }

    // Overwrite package name and version if the caller was untrusted or empty
    if (!isTrusted || item->getPkgName().empty()) {
        const uid_t uidItem = item->getUid();
        const auto [ pkgName, version ] =
                MediaMetricsService::getSanitizedPackageNameAndVersionCode(uidItem);
        item->setPkgName(pkgName);
        item->setPkgVersionCode(version);
    }

    ALOGV("%s: isTrusted:%d given uid %d; sanitized uid: %d sanitized pkg: %s "
          "sanitized pkg version: %lld",
          __func__,
          (int)isTrusted,
          uid_given, item->getUid(),
          item->getPkgName().c_str(),
          (long long)item->getPkgVersionCode());

    mItemsSubmitted++;

    // validate the record; we discard if we don't like it
    if (isContentValid(item, isTrusted) == false) {
        return PERMISSION_DENIED;
    }

    // XXX: if we have a sessionid in the new record, look to make
    // sure it doesn't appear in the finalized list.

    if (item->count() == 0) {
        return BAD_VALUE;
    }

    if (!isTrusted || item->getTimestamp() == 0) {
        // Statsd logs two times for events: ElapsedRealTimeNs (BOOTTIME) and
        // WallClockTimeNs (REALTIME), but currently logs REALTIME to cloud.
        //
        // For consistency and correlation with other logging mechanisms
        // we use REALTIME here.
        const int64_t now = systemTime(SYSTEM_TIME_REALTIME);
        item->setTimestamp(now);
    }

    // register log session ids with singleton.
    if (startsWith(item->getKey(), "metrics.manager")) {
        std::string logSessionId;
        if (item->get("logSessionId", &logSessionId)
                && mediametrics::stringutils::isLogSessionId(logSessionId.c_str())) {
            mediametrics::ValidateId::get()->registerId(logSessionId);
        }
    }

    (void)mAudioAnalytics.submit(item, isTrusted);

    (void)dump2Statsd(item, mStatsdLog);  // failure should be logged in function.
    saveItem(item);
    return NO_ERROR;
}

#ifdef  METRICS_IN_MODULE
status_t MediaMetricsService::dump(int fd, const char **argv, uint32_t argc) {

    // NDK can't use these before v33 (akd Android T)
    // we're going to let the older releases through
    // Note; these modifications (to run in module using NDK) are not used on
    // devices before SDK=36, so we should not encounter this issue
    // APermissionManager_checkPermission introduced in api 31
    if (__builtin_available(android 31, *)) {
        int32_t result_operation = PERMISSION_MANAGER_STATUS_ERROR_UNKNOWN;
        int32_t result_check = PERMISSION_MANAGER_PERMISSION_DENIED;
        const pid_t pid = getClientPid();
        const uid_t uid = getClientUid();

        ALOGV("module, did not actually attempt the permission check, granted anyway");
        result_operation = PERMISSION_MANAGER_STATUS_OK;
        result_check = PERMISSION_MANAGER_PERMISSION_GRANTED;

        if (result_operation != PERMISSION_MANAGER_STATUS_OK ||
            result_check != PERMISSION_MANAGER_PERMISSION_GRANTED) {
            const std::string result = StringPrintf("Permission Denial: "
                    "disallow MediaMetricsService dump from pid=%d, uid=%d\n",
                    pid, uid);
            write(fd, result.c_str(), result.size());
            return NO_ERROR;
        }
    }


    uint32_t i;
    Vector<String16> args;

    for (i = 0; i < argc; i++) {
        args.push_back(String16(argv[i]));
    }
    return ldump(fd, args);
}
#else
status_t MediaMetricsService::dump(int fd, const Vector<String16>& args)
{
    // permissions for framework side
    if (checkCallingPermission(String16("android.permission.DUMP")) == false) {
        const std::string result = StringPrintf("Permission Denial: "
                "can't dump MediaMetricsService from pid=%d, uid=%d\n",
                IPCThreadState::self()->getCallingPid(),
                IPCThreadState::self()->getCallingUid());
        write(fd, result.c_str(), result.size());
        return NO_ERROR;
    }

    return ldump(fd, args);
}
#endif

status_t MediaMetricsService::ldump(int fd, const Vector<String16>& args)
{
    static const String16 allOption("--all");
    static const String16 clearOption("--clear");
    static const String16 heapOption("--heap");
    static const String16 helpOption("--help");
    static const String16 prefixOption("--prefix");
    static const String16 sinceOption("--since");
    static const String16 unreachableOption("--unreachable");

    bool all = false;
    bool clear = false;
#ifndef METRICS_IN_MODULE
    bool heap = false;
    bool unreachable = false;
#endif
    int64_t sinceNs = 0;
    std::string prefix;

    const size_t n = args.size();
    for (size_t i = 0; i < n; i++) {
        String16 arg(args[i]);
        if (allOption == args[i]) {
            all = true;
        } else if (clearOption == args[i]) {
            clear = true;
        }
#ifndef METRICS_IN_MODULE
        else if (heapOption == args[i]) {
            heap = true;
        }
#endif
        else if (helpOption == args[i]) {
            // TODO: consider function area dumping.
            // dumpsys media.metrics audiotrack,codec
            // or dumpsys media.metrics audiotrack codec

            static constexpr char result[] =
                    "Recognized parameters:\n"
                    "--all         show all records\n"
                    "--clear       clear out saved records\n"
                    "--heap        show heap usage (top 100)\n"
                    "--help        display help\n"
                    "--prefix X    process records for component X\n"
                    "--since X     X < 0: records from -X seconds in the past\n"
                    "              X = 0: ignore\n"
                    "              X > 0: records from X seconds since Unix epoch\n"
                    "--unreachable show unreachable memory (leaks)\n";
            write(fd, result, std::size(result));
            return NO_ERROR;
        } else if (prefixOption == args[i]) {
            ++i;
            if (i < n) {
                prefix = String8(args[i]).c_str();
            }
        } else if (sinceOption == args[i]) {
            ++i;
            if (i < n) {
                String8 value(args[i]);
                char *endp;
                const char *p = value.c_str();
                const auto sec = (int64_t)strtoll(p, &endp, 10);
                if (endp == p || *endp != '\0' || sec == 0) {
                    sinceNs = 0;
                } else if (sec < 0) {
                    sinceNs = systemTime(SYSTEM_TIME_REALTIME) + sec * NANOS_PER_SECOND;
                } else {
                    sinceNs = sec * NANOS_PER_SECOND;
                }
            }
        }
#ifndef METRICS_IN_MODULE
        else if (unreachableOption == args[i]) {
            unreachable = true;
        }
#endif
    }
    std::stringstream result;
    {
        std::lock_guard _l(mLock);

        if (clear) {
            mItemsDiscarded += (int64_t)mItems.size();
            mItems.clear();
            mAudioAnalytics.clear();
        } else {
            result << StringPrintf("Dump of the %s process:\n", kServiceName);
            const char *prefixptr = prefix.size() > 0 ? prefix.c_str() : nullptr;
            result << dumpHeaders(sinceNs, prefixptr);
            result << dumpQueue(sinceNs, prefixptr);

            // TODO: maybe consider a better way of dumping audio analytics info.
            const int32_t linesToDump = all ? INT32_MAX : 1000;
            auto [ dumpString, lines ] = mAudioAnalytics.dump(
                    all, linesToDump, sinceNs, prefixptr);
            result << dumpString;
            if (lines == linesToDump) {
                result << "-- some lines may be truncated --\n";
            }

            const int32_t heatLinesToDump = all ? INT32_MAX : 20;
            const auto [ heatDumpString, heatLines] =
                    mAudioAnalytics.dumpHeatMap(heatLinesToDump);
            result << "\n" << heatDumpString;
            if (heatLines == heatLinesToDump) {
                result << "-- some lines may be truncated --\n";
            }

            const int32_t healthLinesToDump = all ? INT32_MAX : 15;
            result << "\nHealth Message Log:";
            const auto [ healthDumpString, healthLines ] =
                    mAudioAnalytics.dumpHealth(healthLinesToDump);
            result << "\n" << healthDumpString;
            if (healthLines == healthLinesToDump) {
                result << "-- some lines may be truncated --\n";
            }

            const int32_t spatializerLinesToDump = all ? INT32_MAX : 15;
            result << "\nSpatializer Message Log:";
            const auto [ spatializerDumpString, spatializerLines ] =
                    mAudioAnalytics.dumpSpatializer(spatializerLinesToDump);
            result << "\n" << spatializerDumpString;
            if (spatializerLines == spatializerLinesToDump) {
                result << "-- some lines may be truncated --\n";
            }

            result << "\nLogSessionId:\n"
                   << mediametrics::ValidateId::get()->dump();

            // Dump the statsd atoms we sent out.
            result << "\nStatsd atoms:\n"
                   << mStatsdLog->dumpToString("  " /* prefix */,
                           all ? STATSD_LOG_LINES_MAX : STATSD_LOG_LINES_DUMP);
        }
    }
    const std::string str = result.str();
    write(fd, str.c_str(), str.size());

    // Check heap and unreachable memory outside of lock.
#ifndef METRICS_IN_MODULE
    if (heap) {
        // appears to be unavailable in NDK.
        dprintf(fd, "\nDumping heap:\n");
        std::string s = dumpMemoryAddresses(100 /* limit */);
        write(fd, s.c_str(), s.size());
    }
    if (unreachable) {
        dprintf(fd, "\nDumping unreachable memory:\n");
        // TODO - should limit be an argument parameter?
        // GetUnreachableMemoryString appears to be platform-only
        std::string s = GetUnreachableMemoryString(true /* contents */, 100 /* limit */);
        write(fd, s.c_str(), s.size());
    }
#endif
    return NO_ERROR;
}

// dump headers
std::string MediaMetricsService::dumpHeaders(int64_t sinceNs, const char* prefix)
{
    std::stringstream result;
    if (mediametrics::Item::isEnabled()) {
        result << "Metrics gathering: enabled\n";
    } else {
        result << "Metrics gathering: DISABLED via property\n";
    }
    result << StringPrintf(
            "Since Boot: Submissions: %lld Accepted: %lld\n",
            (long long)mItemsSubmitted.load(), (long long)mItemsFinalized);
    result << StringPrintf(
            "Records Discarded: %lld (by Count: %lld by Expiration: %lld)\n",
            (long long)mItemsDiscarded, (long long)mItemsDiscardedCount,
            (long long)mItemsDiscardedExpire);
    if (prefix != nullptr) {
        result << "Restricting to prefix " << prefix << "\n";
    }
    if (sinceNs != 0) {
        result << "Emitting Queue entries more recent than: " << sinceNs << "\n";
    }
    return result.str();
}

// TODO: should prefix be a set<string>?
std::string MediaMetricsService::dumpQueue(int64_t sinceNs, const char* prefix)
{
    if (mItems.empty()) {
        return "empty\n";
    }
    std::stringstream result;
    int slot = 0;
    for (const auto &item : mItems) {         // TODO: consider std::lower_bound() on mItems
        if (item->getTimestamp() < sinceNs) { // sinceNs == 0 means all items shown
            continue;
        }
        if (prefix != nullptr && !startsWith(item->getKey(), prefix)) {
            ALOGV("%s: omit '%s', it's not '%s'",
                    __func__, item->getKey().c_str(), prefix);
            continue;
        }
        result << StringPrintf("%5d: %s\n", slot, item->toString().c_str());
        slot++;
    }
    return result.str();
}

//
// Our Cheap in-core, non-persistent records management.

// if item != NULL, it's the item we just inserted
// true == more items eligible to be recovered
bool MediaMetricsService::expirations(const std::shared_ptr<const mediametrics::Item>& item)
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
            if (oitem.get() == item.get()) {
                break;
            }
            if (now > when && (now - when) <= mMaxRecordAgeNs) {
                break; // Note SYSTEM_TIME_REALTIME may not be monotonic.
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
        mItemsDiscardedCount += (int64_t)overlimit;
        mItemsDiscardedExpire += (int64_t)expired;
        mItemsDiscarded += (int64_t)toErase;
        mItems.erase(mItems.begin(), mItems.begin() + (ptrdiff_t)toErase); // erase from front
    }
    return more;
}

void MediaMetricsService::processExpirations()
{
    bool more;
    do {
        sleep(1);
        std::lock_guard _l(mLock);
        more = expirations(nullptr);
    } while (more);
}

void MediaMetricsService::saveItem(const std::shared_ptr<const mediametrics::Item>& item)
{
    std::lock_guard _l(mLock);
    // we assume the items are roughly in time order.
    mItems.emplace_back(item);
    if (isPullable(item->getKey())) {
        registerStatsdCallbacksIfNeeded();
        mPullableItems[item->getKey()].emplace_back(item);
    }
    ++mItemsFinalized;
    if (expirations(item)
            && (!mExpireFuture.valid()
               || mExpireFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready)) {
        mExpireFuture = std::async(std::launch::async, [this] { processExpirations(); });
    }
}

/* static */
bool MediaMetricsService::isContentValid(const std::shared_ptr<mediametrics::Item>& item,
                                         bool isTrusted)
{
    if (isTrusted) return true;

    // untrusted uids can only send us a limited set of keys
    const std::string &key = item->getKey();

    if (startsWith(key, "audio.")) return true;
    if (startsWith(key, "drm.vendor.")) return true;
    if (startsWith(key, "mediadrm.")) return true;

    // the list of allowedKey uses statsd_handlers
    // in iface_statsd.cpp as reference
    // drmmanager is from a trusted uid, therefore not needed here
    for (const char *allowedKey : {
                                     // legacy audio
                                     "audiopolicy",
                                     "audiorecord",
                                     "audiothread",
                                     "audiotrack",
                                     // other media
                                     "codec",
                                     "videofreeze",
                                     "videojudder",
                                     "extractor",
                                     "mediadrm",
                                     "mediaparser",
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
bool MediaMetricsService::isRateLimited(mediametrics::Item *) const
{
    return false;
}

void MediaMetricsService::registerStatsdCallbacksIfNeeded()
{
    if (mStatsdRegistered.test_and_set()) {
        return;
    }
    auto tag = stats::media_metrics::MEDIA_DRM_ACTIVITY_INFO;
    auto cb = MediaMetricsService::pullAtomCallback;
    AStatsManager_setPullAtomCallback(tag, /* metadata */ nullptr, cb, this);
}

/* static */
bool MediaMetricsService::isPullable(const std::string &key)
{
    static const std::set<std::string> pullableKeys{
        "mediadrm",
    };
    return pullableKeys.count(key);
}

/* static */
std::string MediaMetricsService::atomTagToKey(int32_t atomTag)
{
    switch (atomTag) {
    case stats::media_metrics::MEDIA_DRM_ACTIVITY_INFO:
        return "mediadrm";
    }
    return {};
}

/* static */
AStatsManager_PullAtomCallbackReturn MediaMetricsService::pullAtomCallback(
        int32_t atomTag, AStatsEventList* data, void* cookie)
{
    MediaMetricsService* svc = reinterpret_cast<MediaMetricsService*>(cookie);
    return svc->pullItems(atomTag, data);
}

AStatsManager_PullAtomCallbackReturn MediaMetricsService::pullItems(
        int32_t atomTag, AStatsEventList* data)
{
    const std::string key(atomTagToKey(atomTag));
    if (key.empty()) {
        return AStatsManager_PULL_SKIP;
    }
    std::lock_guard _l(mLock);
    bool dumped = false;
    for (auto &item : mPullableItems[key]) {
        if (const auto sitem = item.lock()) {
            dumped |= dump2Statsd(sitem, data, mStatsdLog);
        }
    }
    mPullableItems[key].clear();
    return dumped ? AStatsManager_PULL_SUCCESS : AStatsManager_PULL_SKIP;
}
} // namespace android
