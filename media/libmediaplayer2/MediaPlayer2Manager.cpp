/*
**
** Copyright 2017, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

// Proxy for media player implementations

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaPlayer2Manager"
#include <utils/Log.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>

#include <string.h>

#include <cutils/atomic.h>
#include <cutils/properties.h> // for property_get

#include <utils/misc.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/MemoryHeapBase.h>
#include <binder/MemoryBase.h>
#include <utils/Errors.h>  // for status_t
#include <utils/String8.h>
#include <utils/SystemClock.h>
#include <utils/Timers.h>
#include <utils/Vector.h>

#include <media/AudioPolicyHelper.h>
#include <media/DataSourceDesc.h>
#include <media/MediaHTTPService.h>
#include <media/Metadata.h>
#include <media/AudioTrack.h>
#include <media/MemoryLeakTrackUtil.h>
#include <media/NdkWrapper.h>

#include <media/stagefright/InterfaceUtils.h>
#include <media/stagefright/MediaCodecList.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/Utils.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/ALooperRoster.h>
#include <media/stagefright/SurfaceUtils.h>
#include <mediautils/BatteryNotifier.h>

#include <mediaplayer2/MediaPlayer2EngineClient.h>
#include <mediaplayer2/MediaPlayer2Interface.h>

#include <memunreachable/memunreachable.h>
#include <system/audio.h>
#include <system/window.h>

#include <private/android_filesystem_config.h>

#include <nuplayer2/NuPlayer2Driver.h>
#include "MediaPlayer2Manager.h"

static const int kDumpLockRetries = 50;
static const int kDumpLockSleepUs = 20000;

namespace {
using android::media::Metadata;
using android::status_t;
using android::OK;
using android::BAD_VALUE;
using android::NOT_ENOUGH_DATA;
using android::Parcel;

// Max number of entries in the filter.
const int kMaxFilterSize = 64;  // I pulled that out of thin air.

const float kMaxRequiredSpeed = 8.0f; // for PCM tracks allow up to 8x speedup.

// FIXME: Move all the metadata related function in the Metadata.cpp


// Unmarshall a filter from a Parcel.
// Filter format in a parcel:
//
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       number of entries (n)                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       metadata type 1                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       metadata type 2                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  ....
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       metadata type n                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// @param p Parcel that should start with a filter.
// @param[out] filter On exit contains the list of metadata type to be
//                    filtered.
// @param[out] status On exit contains the status code to be returned.
// @return true if the parcel starts with a valid filter.
bool unmarshallFilter(const Parcel& p,
                      Metadata::Filter *filter,
                      status_t *status)
{
    int32_t val;
    if (p.readInt32(&val) != OK)
    {
        ALOGE("Failed to read filter's length");
        *status = NOT_ENOUGH_DATA;
        return false;
    }

    if( val > kMaxFilterSize || val < 0)
    {
        ALOGE("Invalid filter len %d", val);
        *status = BAD_VALUE;
        return false;
    }

    const size_t num = val;

    filter->clear();
    filter->setCapacity(num);

    size_t size = num * sizeof(Metadata::Type);


    if (p.dataAvail() < size)
    {
        ALOGE("Filter too short expected %zu but got %zu", size, p.dataAvail());
        *status = NOT_ENOUGH_DATA;
        return false;
    }

    const Metadata::Type *data =
            static_cast<const Metadata::Type*>(p.readInplace(size));

    if (NULL == data)
    {
        ALOGE("Filter had no data");
        *status = BAD_VALUE;
        return false;
    }

    // TODO: The stl impl of vector would be more efficient here
    // because it degenerates into a memcpy on pod types. Try to
    // replace later or use stl::set.
    for (size_t i = 0; i < num; ++i)
    {
        filter->add(*data);
        ++data;
    }
    *status = OK;
    return true;
}

// @param filter Of metadata type.
// @param val To be searched.
// @return true if a match was found.
bool findMetadata(const Metadata::Filter& filter, const int32_t val)
{
    // Deal with empty and ANY right away
    if (filter.isEmpty()) return false;
    if (filter[0] == Metadata::kAny) return true;

    return filter.indexOf(val) >= 0;
}

}  // anonymous namespace


namespace {
using android::Parcel;
using android::String16;

// marshalling tag indicating flattened utf16 tags
// keep in sync with frameworks/base/media/java/android/media/AudioAttributes.java
const int32_t kAudioAttributesMarshallTagFlattenTags = 1;

// Audio attributes format in a parcel:
//
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       usage                                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       content_type                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       source                                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       flags                                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       kAudioAttributesMarshallTagFlattenTags  | // ignore tags if not found
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       flattened tags in UTF16                 |
// |                         ...                                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// @param p Parcel that contains audio attributes.
// @param[out] attributes On exit points to an initialized audio_attributes_t structure
// @param[out] status On exit contains the status code to be returned.
void unmarshallAudioAttributes(const Parcel& parcel, audio_attributes_t *attributes)
{
    attributes->usage = (audio_usage_t) parcel.readInt32();
    attributes->content_type = (audio_content_type_t) parcel.readInt32();
    attributes->source = (audio_source_t) parcel.readInt32();
    attributes->flags = (audio_flags_mask_t) parcel.readInt32();
    const bool hasFlattenedTag = (parcel.readInt32() == kAudioAttributesMarshallTagFlattenTags);
    if (hasFlattenedTag) {
        // the tags are UTF16, convert to UTF8
        String16 tags = parcel.readString16();
        ssize_t realTagSize = utf16_to_utf8_length(tags.string(), tags.size());
        if (realTagSize <= 0) {
            strcpy(attributes->tags, "");
        } else {
            // copy the flattened string into the attributes as the destination for the conversion:
            // copying array size -1, array for tags was calloc'd, no need to NULL-terminate it
            size_t tagSize = realTagSize > AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1 ?
                    AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1 : realTagSize;
            utf16_to_utf8(tags.string(), tagSize, attributes->tags,
                    sizeof(attributes->tags) / sizeof(attributes->tags[0]));
        }
    } else {
        ALOGE("unmarshallAudioAttributes() received unflattened tags, ignoring tag values");
        strcpy(attributes->tags, "");
    }
}
} // anonymous namespace


namespace android {

extern ALooperRoster gLooperRoster;

MediaPlayer2Manager gMediaPlayer2Manager;

// TODO: Find real cause of Audio/Video delay in PV framework and remove this workaround
/* static */ int MediaPlayer2Manager::AudioOutput::mMinBufferCount = 4;
/* static */ bool MediaPlayer2Manager::AudioOutput::mIsOnEmulator = false;

// static
MediaPlayer2Manager& MediaPlayer2Manager::get() {
    return gMediaPlayer2Manager;
}

MediaPlayer2Manager::MediaPlayer2Manager() {
    ALOGV("MediaPlayer2Manager created");
    // TODO: remove all unnecessary pid/uid handling.
    mPid = IPCThreadState::self()->getCallingPid();
    mUid = IPCThreadState::self()->getCallingUid();
    mNextConnId = 1;
}

MediaPlayer2Manager::~MediaPlayer2Manager() {
    ALOGV("MediaPlayer2Manager destroyed");
}

sp<MediaPlayer2Engine> MediaPlayer2Manager::create(
        const sp<MediaPlayer2EngineClient>& client,
        audio_session_t audioSessionId)
{
    int32_t connId = android_atomic_inc(&mNextConnId);

    sp<Client> c = new Client(
            mPid, connId, client, audioSessionId, mUid);

    if (!c->init()) {
        return NULL;
    }

    ALOGV("Create new client(%d) from pid %d, uid %d, ", connId, mPid, mUid);

    wp<Client> w = c;
    {
        Mutex::Autolock lock(mLock);
        mClients.add(w);
    }
    return c;
}

status_t MediaPlayer2Manager::AudioOutput::dump(int fd, const Vector<String16>& args) const
{
    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;

    result.append(" AudioOutput\n");
    snprintf(buffer, 255, "  stream type(%d), left - right volume(%f, %f)\n",
            mStreamType, mLeftVolume, mRightVolume);
    result.append(buffer);
    snprintf(buffer, 255, "  msec per frame(%f), latency (%d)\n",
            mMsecsPerFrame, (mTrack != 0) ? mTrack->latency() : -1);
    result.append(buffer);
    snprintf(buffer, 255, "  aux effect id(%d), send level (%f)\n",
            mAuxEffectId, mSendLevel);
    result.append(buffer);

    ::write(fd, result.string(), result.size());
    if (mTrack != 0) {
        mTrack->dump(fd, args);
    }
    return NO_ERROR;
}

status_t MediaPlayer2Manager::Client::dump(int fd, const Vector<String16>& args)
{
    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;
    result.append(" Client\n");
    snprintf(buffer, 255, "  pid(%d), connId(%d), status(%d), looping(%s)\n",
            mPid, mConnId, mStatus, mLoop?"true": "false");
    result.append(buffer);

    sp<MediaPlayer2Interface> p;
    sp<AudioOutput> audioOutput;
    bool locked = false;
    for (int i = 0; i < kDumpLockRetries; ++i) {
        if (mLock.tryLock() == NO_ERROR) {
            locked = true;
            break;
        }
        usleep(kDumpLockSleepUs);
    }

    if (locked) {
        p = mPlayer;
        audioOutput = mAudioOutput;
        mLock.unlock();
    } else {
        result.append("  lock is taken, no dump from player and audio output\n");
    }
    write(fd, result.string(), result.size());

    if (p != NULL) {
        p->dump(fd, args);
    }
    if (audioOutput != 0) {
        audioOutput->dump(fd, args);
    }
    write(fd, "\n", 1);
    return NO_ERROR;
}

/**
 * The only arguments this understands right now are -c, -von and -voff,
 * which are parsed by ALooperRoster::dump()
 */
status_t MediaPlayer2Manager::dump(int fd, const Vector<String16>& args)
{
    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;
    SortedVector< sp<Client> > clients; //to serialise the mutex unlock & client destruction.

    if (checkCallingPermission(String16("android.permission.DUMP")) == false) {
        snprintf(buffer, SIZE, "Permission Denial: "
                "can't dump MediaPlayer2Manager from pid=%d, uid=%d\n",
                mPid, mUid);
        result.append(buffer);
    } else {
        Mutex::Autolock lock(mLock);
        for (int i = 0, n = mClients.size(); i < n; ++i) {
            sp<Client> c = mClients[i].promote();
            if (c != 0) c->dump(fd, args);
            clients.add(c);
        }

        result.append(" Files opened and/or mapped:\n");
        snprintf(buffer, SIZE, "/proc/%d/maps", getpid());
        FILE *f = fopen(buffer, "r");
        if (f) {
            while (!feof(f)) {
                fgets(buffer, SIZE, f);
                if (strstr(buffer, " /storage/") ||
                    strstr(buffer, " /system/sounds/") ||
                    strstr(buffer, " /data/") ||
                    strstr(buffer, " /system/media/")) {
                    result.append("  ");
                    result.append(buffer);
                }
            }
            fclose(f);
        } else {
            result.append("couldn't open ");
            result.append(buffer);
            result.append("\n");
        }

        snprintf(buffer, SIZE, "/proc/%d/fd", getpid());
        DIR *d = opendir(buffer);
        if (d) {
            struct dirent *ent;
            while((ent = readdir(d)) != NULL) {
                if (strcmp(ent->d_name,".") && strcmp(ent->d_name,"..")) {
                    snprintf(buffer, SIZE, "/proc/%d/fd/%s", getpid(), ent->d_name);
                    struct stat s;
                    if (lstat(buffer, &s) == 0) {
                        if ((s.st_mode & S_IFMT) == S_IFLNK) {
                            char linkto[256];
                            int len = readlink(buffer, linkto, sizeof(linkto));
                            if(len > 0) {
                                if(len > 255) {
                                    linkto[252] = '.';
                                    linkto[253] = '.';
                                    linkto[254] = '.';
                                    linkto[255] = 0;
                                } else {
                                    linkto[len] = 0;
                                }
                                if (strstr(linkto, "/storage/") == linkto ||
                                    strstr(linkto, "/system/sounds/") == linkto ||
                                    strstr(linkto, "/data/") == linkto ||
                                    strstr(linkto, "/system/media/") == linkto) {
                                    result.append("  ");
                                    result.append(buffer);
                                    result.append(" -> ");
                                    result.append(linkto);
                                    result.append("\n");
                                }
                            }
                        } else {
                            result.append("  unexpected type for ");
                            result.append(buffer);
                            result.append("\n");
                        }
                    }
                }
            }
            closedir(d);
        } else {
            result.append("couldn't open ");
            result.append(buffer);
            result.append("\n");
        }

        gLooperRoster.dump(fd, args);

        bool dumpMem = false;
        bool unreachableMemory = false;
        for (size_t i = 0; i < args.size(); i++) {
            if (args[i] == String16("-m")) {
                dumpMem = true;
            } else if (args[i] == String16("--unreachable")) {
                unreachableMemory = true;
            }
        }
        if (dumpMem) {
            result.append("\nDumping memory:\n");
            std::string s = dumpMemoryAddresses(100 /* limit */);
            result.append(s.c_str(), s.size());
        }
        if (unreachableMemory) {
            result.append("\nDumping unreachable memory:\n");
            // TODO - should limit be an argument parameter?
            // TODO: enable GetUnreachableMemoryString if it's part of stable API
            //std::string s = GetUnreachableMemoryString(true /* contents */, 10000 /* limit */);
            //result.append(s.c_str(), s.size());
        }
    }
    write(fd, result.string(), result.size());
    return NO_ERROR;
}

void MediaPlayer2Manager::removeClient(const wp<Client>& client)
{
    Mutex::Autolock lock(mLock);
    mClients.remove(client);
}

bool MediaPlayer2Manager::hasClient(wp<Client> client)
{
    Mutex::Autolock lock(mLock);
    return mClients.indexOf(client) != NAME_NOT_FOUND;
}

MediaPlayer2Manager::Client::Client(
        pid_t pid,
        int32_t connId,
        const sp<MediaPlayer2EngineClient>& client,
        audio_session_t audioSessionId,
        uid_t uid)
{
    ALOGV("Client(%d) constructor", connId);
    mPid = pid;
    mConnId = connId;
    mClient = client;
    mLoop = false;
    mStatus = NO_INIT;
    mAudioSessionId = audioSessionId;
    mUid = uid;
    mAudioAttributes = NULL;

#if CALLBACK_ANTAGONIZER
    ALOGD("create Antagonizer");
    mAntagonizer = new Antagonizer(notify, this);
#endif
}

bool MediaPlayer2Manager::Client::init() {
    sp<MediaPlayer2Interface> p = new NuPlayer2Driver(mPid, mUid);
    status_t init_result = p->initCheck();
    if (init_result != NO_ERROR) {
        ALOGE("Failed to create player object, initCheck failed(%d)", init_result);
        return false;
    }

    p->setNotifyCallback(this, notify);
    mAudioDeviceUpdatedListener = new AudioDeviceUpdatedNotifier(p);
    mAudioOutput = new AudioOutput(mAudioSessionId, mUid,
            mPid, mAudioAttributes, mAudioDeviceUpdatedListener);
    p->setAudioSink(mAudioOutput);

    mPlayer = p;
    return true;
}

MediaPlayer2Manager::Client::~Client()
{
    ALOGV("Client(%d) destructor pid = %d", mConnId, mPid);
    mAudioOutput.clear();
    wp<Client> client(this);
    disconnect();
    gMediaPlayer2Manager.removeClient(client);
    if (mAudioAttributes != NULL) {
        free(mAudioAttributes);
    }
    mAudioDeviceUpdatedListener.clear();
}

void MediaPlayer2Manager::Client::disconnect()
{
    ALOGV("disconnect(%d) from pid %d", mConnId, mPid);
    // grab local reference and clear main reference to prevent future
    // access to object
    sp<MediaPlayer2Interface> p;
    {
        Mutex::Autolock l(mLock);
        p = mPlayer;
        mClient.clear();
        mPlayer.clear();
    }

    // clear the notification to prevent callbacks to dead client
    // and reset the player. We assume the player will serialize
    // access to itself if necessary.
    if (p != 0) {
        p->setNotifyCallback(0, 0);
#if CALLBACK_ANTAGONIZER
        ALOGD("kill Antagonizer");
        mAntagonizer->kill();
#endif
        p->reset();
    }

    {
        Mutex::Autolock l(mLock);
        disconnectNativeWindow_l();
    }

    IPCThreadState::self()->flushCommands();
}

void MediaPlayer2Manager::Client::AudioDeviceUpdatedNotifier::onAudioDeviceUpdate(
        audio_io_handle_t audioIo,
        audio_port_handle_t deviceId) {
    sp<MediaPlayer2Interface> listener = mListener.promote();
    if (listener != NULL) {
        listener->sendEvent(MEDIA2_AUDIO_ROUTING_CHANGED, audioIo, deviceId);
    } else {
        ALOGW("listener for process %d death is gone", MEDIA2_AUDIO_ROUTING_CHANGED);
    }
}

status_t MediaPlayer2Manager::Client::setDataSource(
        const sp<DataSourceDesc> &dsd) {
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == NULL) {
        return NO_INIT;
    }

    if (dsd == NULL) {
        return BAD_VALUE;
    }

    status_t status = p->setDataSource(dsd);
    if (status != OK) {
        ALOGE("setDataSource error: %d", status);
        return status;
    }

    return status;
}

void MediaPlayer2Manager::Client::disconnectNativeWindow_l() {
    if (mConnectedWindow != NULL && mConnectedWindow->getANativeWindow() != NULL) {
        status_t err = native_window_api_disconnect(
                mConnectedWindow->getANativeWindow(), NATIVE_WINDOW_API_MEDIA);

        if (err != OK) {
            ALOGW("nativeWindowDisconnect returned an error: %s (%d)",
                    strerror(-err), err);
        }
    }
    mConnectedWindow.clear();
}

status_t MediaPlayer2Manager::Client::setVideoSurfaceTexture(
        const sp<ANativeWindowWrapper>& nww)
{
    ALOGV("[%d] setVideoSurfaceTexture(%p)",
          mConnId,
          (nww == NULL ? NULL : nww->getANativeWindow()));
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;

    if (nww != NULL && nww->getANativeWindow() != NULL) {
        if (mConnectedWindow != NULL
            && mConnectedWindow->getANativeWindow() == nww->getANativeWindow()) {
            return OK;
        }
        status_t err = native_window_api_connect(
                nww->getANativeWindow(), NATIVE_WINDOW_API_MEDIA);

        if (err != OK) {
            ALOGE("setVideoSurfaceTexture failed: %d", err);
            // Note that we must do the reset before disconnecting from the ANW.
            // Otherwise queue/dequeue calls could be made on the disconnected
            // ANW, which may result in errors.
            reset();

            Mutex::Autolock lock(mLock);
            disconnectNativeWindow_l();

            return err;
        }
    }

    // Note that we must set the player's new GraphicBufferProducer before
    // disconnecting the old one.  Otherwise queue/dequeue calls could be made
    // on the disconnected ANW, which may result in errors.
    status_t err = p->setVideoSurfaceTexture(nww);

    mLock.lock();
    disconnectNativeWindow_l();

    if (err == OK) {
        mConnectedWindow = nww;
        mLock.unlock();
    } else if (nww != NULL) {
        mLock.unlock();
        status_t err = native_window_api_disconnect(
                nww->getANativeWindow(), NATIVE_WINDOW_API_MEDIA);

        if (err != OK) {
            ALOGW("nativeWindowDisconnect returned an error: %s (%d)",
                    strerror(-err), err);
        }
    }

    return err;
}

status_t MediaPlayer2Manager::Client::invoke(const Parcel& request,
                                            Parcel *reply)
{
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == NULL) return UNKNOWN_ERROR;
    return p->invoke(request, reply);
}

// This call doesn't need to access the native player.
status_t MediaPlayer2Manager::Client::setMetadataFilter(const Parcel& filter)
{
    status_t status;
    media::Metadata::Filter allow, drop;

    if (unmarshallFilter(filter, &allow, &status) &&
        unmarshallFilter(filter, &drop, &status)) {
        Mutex::Autolock lock(mLock);

        mMetadataAllow = allow;
        mMetadataDrop = drop;
    }
    return status;
}

status_t MediaPlayer2Manager::Client::getMetadata(
        bool update_only, bool /*apply_filter*/, Parcel *reply)
{
    sp<MediaPlayer2Interface> player = getPlayer();
    if (player == 0) return UNKNOWN_ERROR;

    status_t status;
    // Placeholder for the return code, updated by the caller.
    reply->writeInt32(-1);

    media::Metadata::Filter ids;

    // We don't block notifications while we fetch the data. We clear
    // mMetadataUpdated first so we don't lose notifications happening
    // during the rest of this call.
    {
        Mutex::Autolock lock(mLock);
        if (update_only) {
            ids = mMetadataUpdated;
        }
        mMetadataUpdated.clear();
    }

    media::Metadata metadata(reply);

    metadata.appendHeader();
    status = player->getMetadata(ids, reply);

    if (status != OK) {
        metadata.resetParcel();
        ALOGE("getMetadata failed %d", status);
        return status;
    }

    // FIXME: ement filtering on the result. Not critical since
    // filtering takes place on the update notifications already. This
    // would be when all the metadata are fetch and a filter is set.

    // Everything is fine, update the metadata length.
    metadata.updateLength();
    return OK;
}

status_t MediaPlayer2Manager::Client::setBufferingSettings(
        const BufferingSettings& buffering)
{
    ALOGV("[%d] setBufferingSettings{%s}",
            mConnId, buffering.toString().string());
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    return p->setBufferingSettings(buffering);
}

status_t MediaPlayer2Manager::Client::getBufferingSettings(
        BufferingSettings* buffering /* nonnull */)
{
    sp<MediaPlayer2Interface> p = getPlayer();
    // TODO: create mPlayer on demand.
    if (p == 0) return UNKNOWN_ERROR;
    status_t ret = p->getBufferingSettings(buffering);
    if (ret == NO_ERROR) {
        ALOGV("[%d] getBufferingSettings{%s}",
                mConnId, buffering->toString().string());
    } else {
        ALOGE("[%d] getBufferingSettings returned %d", mConnId, ret);
    }
    return ret;
}

status_t MediaPlayer2Manager::Client::prepareAsync()
{
    ALOGV("[%d] prepareAsync", mConnId);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    status_t ret = p->prepareAsync();
#if CALLBACK_ANTAGONIZER
    ALOGD("start Antagonizer");
    if (ret == NO_ERROR) mAntagonizer->start();
#endif
    return ret;
}

status_t MediaPlayer2Manager::Client::start()
{
    ALOGV("[%d] start", mConnId);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    p->setLooping(mLoop);
    return p->start();
}

status_t MediaPlayer2Manager::Client::stop()
{
    ALOGV("[%d] stop", mConnId);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    return p->stop();
}

status_t MediaPlayer2Manager::Client::pause()
{
    ALOGV("[%d] pause", mConnId);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    return p->pause();
}

status_t MediaPlayer2Manager::Client::isPlaying(bool* state)
{
    *state = false;
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    *state = p->isPlaying();
    ALOGV("[%d] isPlaying: %d", mConnId, *state);
    return NO_ERROR;
}

status_t MediaPlayer2Manager::Client::setPlaybackSettings(const AudioPlaybackRate& rate)
{
    ALOGV("[%d] setPlaybackSettings(%f, %f, %d, %d)",
            mConnId, rate.mSpeed, rate.mPitch, rate.mFallbackMode, rate.mStretchMode);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    return p->setPlaybackSettings(rate);
}

status_t MediaPlayer2Manager::Client::getPlaybackSettings(AudioPlaybackRate* rate /* nonnull */)
{
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    status_t ret = p->getPlaybackSettings(rate);
    if (ret == NO_ERROR) {
        ALOGV("[%d] getPlaybackSettings(%f, %f, %d, %d)",
                mConnId, rate->mSpeed, rate->mPitch, rate->mFallbackMode, rate->mStretchMode);
    } else {
        ALOGV("[%d] getPlaybackSettings returned %d", mConnId, ret);
    }
    return ret;
}

status_t MediaPlayer2Manager::Client::setSyncSettings(
        const AVSyncSettings& sync, float videoFpsHint)
{
    ALOGV("[%d] setSyncSettings(%u, %u, %f, %f)",
            mConnId, sync.mSource, sync.mAudioAdjustMode, sync.mTolerance, videoFpsHint);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    return p->setSyncSettings(sync, videoFpsHint);
}

status_t MediaPlayer2Manager::Client::getSyncSettings(
        AVSyncSettings* sync /* nonnull */, float* videoFps /* nonnull */)
{
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    status_t ret = p->getSyncSettings(sync, videoFps);
    if (ret == NO_ERROR) {
        ALOGV("[%d] getSyncSettings(%u, %u, %f, %f)",
                mConnId, sync->mSource, sync->mAudioAdjustMode, sync->mTolerance, *videoFps);
    } else {
        ALOGV("[%d] getSyncSettings returned %d", mConnId, ret);
    }
    return ret;
}

status_t MediaPlayer2Manager::Client::getCurrentPosition(int *msec)
{
    ALOGV("getCurrentPosition");
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    status_t ret = p->getCurrentPosition(msec);
    if (ret == NO_ERROR) {
        ALOGV("[%d] getCurrentPosition = %d", mConnId, *msec);
    } else {
        ALOGE("getCurrentPosition returned %d", ret);
    }
    return ret;
}

status_t MediaPlayer2Manager::Client::getDuration(int *msec)
{
    ALOGV("getDuration");
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    status_t ret = p->getDuration(msec);
    if (ret == NO_ERROR) {
        ALOGV("[%d] getDuration = %d", mConnId, *msec);
    } else {
        ALOGE("getDuration returned %d", ret);
    }
    return ret;
}

status_t MediaPlayer2Manager::Client::setNextPlayer(const sp<MediaPlayer2Engine>& player) {
    ALOGV("setNextPlayer");
    Mutex::Autolock l(mLock);
    sp<Client> c = static_cast<Client*>(player.get());
    if (c != NULL && !gMediaPlayer2Manager.hasClient(c)) {
      return BAD_VALUE;
    }

    mNextClient = c;

    if (c != NULL) {
        if (mAudioOutput != NULL) {
            mAudioOutput->setNextOutput(c->mAudioOutput);
        } else {
            ALOGE("no current audio output");
        }

        if ((mPlayer != NULL) && (mNextClient->getPlayer() != NULL)) {
            mPlayer->setNextPlayer(mNextClient->getPlayer());
        }
    }

    return OK;
}

status_t MediaPlayer2Manager::Client::seekTo(int msec, MediaPlayer2SeekMode mode)
{
    ALOGV("[%d] seekTo(%d, %d)", mConnId, msec, mode);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    return p->seekTo(msec, mode);
}

status_t MediaPlayer2Manager::Client::reset()
{
    ALOGV("[%d] reset", mConnId);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    return p->reset();
}

status_t MediaPlayer2Manager::Client::notifyAt(int64_t mediaTimeUs)
{
    ALOGV("[%d] notifyAt(%lld)", mConnId, (long long)mediaTimeUs);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    return p->notifyAt(mediaTimeUs);
}

status_t MediaPlayer2Manager::Client::setAudioStreamType(audio_stream_type_t type)
{
    ALOGV("[%d] setAudioStreamType(%d)", mConnId, type);
    // TODO: for hardware output, call player instead
    Mutex::Autolock l(mLock);
    if (mAudioOutput != 0) mAudioOutput->setAudioStreamType(type);
    return NO_ERROR;
}

status_t MediaPlayer2Manager::Client::setAudioAttributes_l(const Parcel &parcel)
{
    if (mAudioAttributes != NULL) { free(mAudioAttributes); }
    mAudioAttributes = (audio_attributes_t *) calloc(1, sizeof(audio_attributes_t));
    if (mAudioAttributes == NULL) {
        return NO_MEMORY;
    }
    unmarshallAudioAttributes(parcel, mAudioAttributes);

    ALOGV("setAudioAttributes_l() usage=%d content=%d flags=0x%x tags=%s",
            mAudioAttributes->usage, mAudioAttributes->content_type, mAudioAttributes->flags,
            mAudioAttributes->tags);

    if (mAudioOutput != 0) {
        mAudioOutput->setAudioAttributes(mAudioAttributes);
    }
    return NO_ERROR;
}

status_t MediaPlayer2Manager::Client::setLooping(int loop)
{
    ALOGV("[%d] setLooping(%d)", mConnId, loop);
    mLoop = loop;
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p != 0) return p->setLooping(loop);
    return NO_ERROR;
}

status_t MediaPlayer2Manager::Client::setVolume(float leftVolume, float rightVolume)
{
    ALOGV("[%d] setVolume(%f, %f)", mConnId, leftVolume, rightVolume);

    // for hardware output, call player instead
    sp<MediaPlayer2Interface> p = getPlayer();
    {
      Mutex::Autolock l(mLock);
      if (mAudioOutput != 0) mAudioOutput->setVolume(leftVolume, rightVolume);
    }

    return NO_ERROR;
}

status_t MediaPlayer2Manager::Client::setAuxEffectSendLevel(float level)
{
    ALOGV("[%d] setAuxEffectSendLevel(%f)", mConnId, level);
    Mutex::Autolock l(mLock);
    if (mAudioOutput != 0) return mAudioOutput->setAuxEffectSendLevel(level);
    return NO_ERROR;
}

status_t MediaPlayer2Manager::Client::attachAuxEffect(int effectId)
{
    ALOGV("[%d] attachAuxEffect(%d)", mConnId, effectId);
    Mutex::Autolock l(mLock);
    if (mAudioOutput != 0) return mAudioOutput->attachAuxEffect(effectId);
    return NO_ERROR;
}

status_t MediaPlayer2Manager::Client::setParameter(int key, const Parcel &request) {
    ALOGV("[%d] setParameter(%d)", mConnId, key);
    switch (key) {
    case MEDIA2_KEY_PARAMETER_AUDIO_ATTRIBUTES:
    {
        Mutex::Autolock l(mLock);
        return setAudioAttributes_l(request);
    }
    default:
        sp<MediaPlayer2Interface> p = getPlayer();
        if (p == 0) { return UNKNOWN_ERROR; }
        return p->setParameter(key, request);
    }
}

status_t MediaPlayer2Manager::Client::getParameter(int key, Parcel *reply) {
    ALOGV("[%d] getParameter(%d)", mConnId, key);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;
    return p->getParameter(key, reply);
}

void MediaPlayer2Manager::Client::notify(
        const wp<MediaPlayer2Engine> &listener, int msg, int ext1, int ext2, const Parcel *obj)
{
    sp<MediaPlayer2Engine> spListener = listener.promote();
    if (spListener == NULL) {
        return;
    }
    Client* client = static_cast<Client*>(spListener.get());

    sp<MediaPlayer2EngineClient> c;
    sp<Client> nextClient;
    status_t errStartNext = NO_ERROR;
    {
        Mutex::Autolock l(client->mLock);
        c = client->mClient;
        if (msg == MEDIA2_PLAYBACK_COMPLETE && client->mNextClient != NULL) {
            nextClient = client->mNextClient;

            if (client->mAudioOutput != NULL)
                client->mAudioOutput->switchToNextOutput();

            errStartNext = nextClient->start();
        }
    }

    if (nextClient != NULL) {
        sp<MediaPlayer2EngineClient> nc;
        {
            Mutex::Autolock l(nextClient->mLock);
            nc = nextClient->mClient;
        }
        if (nc != NULL) {
            if (errStartNext == NO_ERROR) {
                nc->notify(MEDIA2_INFO, MEDIA2_INFO_STARTED_AS_NEXT, 0, obj);
            } else {
                nc->notify(MEDIA2_ERROR, MEDIA2_ERROR_UNKNOWN , 0, obj);
                ALOGE("gapless:start playback for next track failed, err(%d)", errStartNext);
            }
        }
    }

    if (MEDIA2_INFO == msg &&
        MEDIA2_INFO_METADATA_UPDATE == ext1) {
        const media::Metadata::Type metadata_type = ext2;

        if(client->shouldDropMetadata(metadata_type)) {
            return;
        }

        // Update the list of metadata that have changed. getMetadata
        // also access mMetadataUpdated and clears it.
        client->addNewMetadataUpdate(metadata_type);
    }

    if (c != NULL) {
        ALOGV("[%d] notify (%p, %d, %d, %d)", client->mConnId, spListener.get(), msg, ext1, ext2);
        c->notify(msg, ext1, ext2, obj);
    }
}


bool MediaPlayer2Manager::Client::shouldDropMetadata(media::Metadata::Type code) const
{
    Mutex::Autolock lock(mLock);

    if (findMetadata(mMetadataDrop, code)) {
        return true;
    }

    if (mMetadataAllow.isEmpty() || findMetadata(mMetadataAllow, code)) {
        return false;
    } else {
        return true;
    }
}


void MediaPlayer2Manager::Client::addNewMetadataUpdate(media::Metadata::Type metadata_type) {
    Mutex::Autolock lock(mLock);
    if (mMetadataUpdated.indexOf(metadata_type) < 0) {
        mMetadataUpdated.add(metadata_type);
    }
}

// Modular DRM
status_t MediaPlayer2Manager::Client::prepareDrm(const uint8_t uuid[16],
        const Vector<uint8_t>& drmSessionId)
{
    ALOGV("[%d] prepareDrm", mConnId);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;

    status_t ret = p->prepareDrm(uuid, drmSessionId);
    ALOGV("prepareDrm ret: %d", ret);

    return ret;
}

status_t MediaPlayer2Manager::Client::releaseDrm()
{
    ALOGV("[%d] releaseDrm", mConnId);
    sp<MediaPlayer2Interface> p = getPlayer();
    if (p == 0) return UNKNOWN_ERROR;

    status_t ret = p->releaseDrm();
    ALOGV("releaseDrm ret: %d", ret);

    return ret;
}

status_t MediaPlayer2Manager::Client::setOutputDevice(audio_port_handle_t deviceId)
{
    ALOGV("[%d] setOutputDevice", mConnId);
    {
        Mutex::Autolock l(mLock);
        if (mAudioOutput.get() != nullptr) {
            return mAudioOutput->setOutputDevice(deviceId);
        }
    }
    return NO_INIT;
}

status_t MediaPlayer2Manager::Client::getRoutedDeviceId(audio_port_handle_t* deviceId)
{
    ALOGV("[%d] getRoutedDeviceId", mConnId);
    {
        Mutex::Autolock l(mLock);
        if (mAudioOutput.get() != nullptr) {
            return mAudioOutput->getRoutedDeviceId(deviceId);
        }
    }
    return NO_INIT;
}

status_t MediaPlayer2Manager::Client::enableAudioDeviceCallback(bool enabled)
{
    ALOGV("[%d] enableAudioDeviceCallback, %d", mConnId, enabled);
    {
        Mutex::Autolock l(mLock);
        if (mAudioOutput.get() != nullptr) {
            return mAudioOutput->enableAudioDeviceCallback(enabled);
        }
    }
    return NO_INIT;
}

#if CALLBACK_ANTAGONIZER
const int Antagonizer::interval = 10000; // 10 msecs

Antagonizer::Antagonizer(
        MediaPlayer2Manager::NotifyCallback cb,
        const wp<MediaPlayer2Engine> &client) :
    mExit(false), mActive(false), mClient(client), mCb(cb)
{
    createThread(callbackThread, this);
}

void Antagonizer::kill()
{
    Mutex::Autolock _l(mLock);
    mActive = false;
    mExit = true;
    mCondition.wait(mLock);
}

int Antagonizer::callbackThread(void* user)
{
    ALOGD("Antagonizer started");
    Antagonizer* p = reinterpret_cast<Antagonizer*>(user);
    while (!p->mExit) {
        if (p->mActive) {
            ALOGV("send event");
            p->mCb(p->mClient, 0, 0, 0);
        }
        usleep(interval);
    }
    Mutex::Autolock _l(p->mLock);
    p->mCondition.signal();
    ALOGD("Antagonizer stopped");
    return 0;
}
#endif

#undef LOG_TAG
#define LOG_TAG "AudioSink"
MediaPlayer2Manager::AudioOutput::AudioOutput(audio_session_t sessionId, uid_t uid, int pid,
        const audio_attributes_t* attr, const sp<AudioSystem::AudioDeviceCallback>& deviceCallback)
    : mCallback(NULL),
      mCallbackCookie(NULL),
      mCallbackData(NULL),
      mStreamType(AUDIO_STREAM_MUSIC),
      mLeftVolume(1.0),
      mRightVolume(1.0),
      mPlaybackRate(AUDIO_PLAYBACK_RATE_DEFAULT),
      mSampleRateHz(0),
      mMsecsPerFrame(0),
      mFrameSize(0),
      mSessionId(sessionId),
      mUid(uid),
      mPid(pid),
      mSendLevel(0.0),
      mAuxEffectId(0),
      mFlags(AUDIO_OUTPUT_FLAG_NONE),
      mSelectedDeviceId(AUDIO_PORT_HANDLE_NONE),
      mRoutedDeviceId(AUDIO_PORT_HANDLE_NONE),
      mDeviceCallbackEnabled(false),
      mDeviceCallback(deviceCallback)
{
    ALOGV("AudioOutput(%d)", sessionId);
    if (attr != NULL) {
        mAttributes = (audio_attributes_t *) calloc(1, sizeof(audio_attributes_t));
        if (mAttributes != NULL) {
            memcpy(mAttributes, attr, sizeof(audio_attributes_t));
            mStreamType = audio_attributes_to_stream_type(attr);
        }
    } else {
        mAttributes = NULL;
    }

    setMinBufferCount();
}

MediaPlayer2Manager::AudioOutput::~AudioOutput()
{
    close();
    free(mAttributes);
    delete mCallbackData;
}

//static
void MediaPlayer2Manager::AudioOutput::setMinBufferCount()
{
    char value[PROPERTY_VALUE_MAX];
    if (property_get("ro.kernel.qemu", value, 0)) {
        mIsOnEmulator = true;
        mMinBufferCount = 12;  // to prevent systematic buffer underrun for emulator
    }
}

// static
bool MediaPlayer2Manager::AudioOutput::isOnEmulator()
{
    setMinBufferCount(); // benign race wrt other threads
    return mIsOnEmulator;
}

// static
int MediaPlayer2Manager::AudioOutput::getMinBufferCount()
{
    setMinBufferCount(); // benign race wrt other threads
    return mMinBufferCount;
}

ssize_t MediaPlayer2Manager::AudioOutput::bufferSize() const
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) return NO_INIT;
    return mTrack->frameCount() * mFrameSize;
}

ssize_t MediaPlayer2Manager::AudioOutput::frameCount() const
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) return NO_INIT;
    return mTrack->frameCount();
}

ssize_t MediaPlayer2Manager::AudioOutput::channelCount() const
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) return NO_INIT;
    return mTrack->channelCount();
}

ssize_t MediaPlayer2Manager::AudioOutput::frameSize() const
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) return NO_INIT;
    return mFrameSize;
}

uint32_t MediaPlayer2Manager::AudioOutput::latency () const
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) return 0;
    return mTrack->latency();
}

float MediaPlayer2Manager::AudioOutput::msecsPerFrame() const
{
    Mutex::Autolock lock(mLock);
    return mMsecsPerFrame;
}

status_t MediaPlayer2Manager::AudioOutput::getPosition(uint32_t *position) const
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) return NO_INIT;
    return mTrack->getPosition(position);
}

status_t MediaPlayer2Manager::AudioOutput::getTimestamp(AudioTimestamp &ts) const
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) return NO_INIT;
    return mTrack->getTimestamp(ts);
}

// TODO: Remove unnecessary calls to getPlayedOutDurationUs()
// as it acquires locks and may query the audio driver.
//
// Some calls could conceivably retrieve extrapolated data instead of
// accessing getTimestamp() or getPosition() every time a data buffer with
// a media time is received.
//
// Calculate duration of played samples if played at normal rate (i.e., 1.0).
int64_t MediaPlayer2Manager::AudioOutput::getPlayedOutDurationUs(int64_t nowUs) const
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0 || mSampleRateHz == 0) {
        return 0;
    }

    uint32_t numFramesPlayed;
    int64_t numFramesPlayedAtUs;
    AudioTimestamp ts;

    status_t res = mTrack->getTimestamp(ts);
    if (res == OK) {                 // case 1: mixing audio tracks and offloaded tracks.
        numFramesPlayed = ts.mPosition;
        numFramesPlayedAtUs = ts.mTime.tv_sec * 1000000LL + ts.mTime.tv_nsec / 1000;
        //ALOGD("getTimestamp: OK %d %lld", numFramesPlayed, (long long)numFramesPlayedAtUs);
    } else if (res == WOULD_BLOCK) { // case 2: transitory state on start of a new track
        numFramesPlayed = 0;
        numFramesPlayedAtUs = nowUs;
        //ALOGD("getTimestamp: WOULD_BLOCK %d %lld",
        //        numFramesPlayed, (long long)numFramesPlayedAtUs);
    } else {                         // case 3: transitory at new track or audio fast tracks.
        res = mTrack->getPosition(&numFramesPlayed);
        CHECK_EQ(res, (status_t)OK);
        numFramesPlayedAtUs = nowUs;
        numFramesPlayedAtUs += 1000LL * mTrack->latency() / 2; /* XXX */
        //ALOGD("getPosition: %u %lld", numFramesPlayed, (long long)numFramesPlayedAtUs);
    }

    // CHECK_EQ(numFramesPlayed & (1 << 31), 0);  // can't be negative until 12.4 hrs, test
    // TODO: remove the (int32_t) casting below as it may overflow at 12.4 hours.
    int64_t durationUs = (int64_t)((int32_t)numFramesPlayed * 1000000LL / mSampleRateHz)
            + nowUs - numFramesPlayedAtUs;
    if (durationUs < 0) {
        // Occurs when numFramesPlayed position is very small and the following:
        // (1) In case 1, the time nowUs is computed before getTimestamp() is called and
        //     numFramesPlayedAtUs is greater than nowUs by time more than numFramesPlayed.
        // (2) In case 3, using getPosition and adding mAudioSink->latency() to
        //     numFramesPlayedAtUs, by a time amount greater than numFramesPlayed.
        //
        // Both of these are transitory conditions.
        ALOGV("getPlayedOutDurationUs: negative duration %lld set to zero", (long long)durationUs);
        durationUs = 0;
    }
    ALOGV("getPlayedOutDurationUs(%lld) nowUs(%lld) frames(%u) framesAt(%lld)",
            (long long)durationUs, (long long)nowUs,
            numFramesPlayed, (long long)numFramesPlayedAtUs);
    return durationUs;
}

status_t MediaPlayer2Manager::AudioOutput::getFramesWritten(uint32_t *frameswritten) const
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) return NO_INIT;
    ExtendedTimestamp ets;
    status_t status = mTrack->getTimestamp(&ets);
    if (status == OK || status == WOULD_BLOCK) {
        *frameswritten = (uint32_t)ets.mPosition[ExtendedTimestamp::LOCATION_CLIENT];
    }
    return status;
}

status_t MediaPlayer2Manager::AudioOutput::setParameters(const String8& keyValuePairs)
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) return NO_INIT;
    return mTrack->setParameters(keyValuePairs);
}

String8  MediaPlayer2Manager::AudioOutput::getParameters(const String8& keys)
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) return String8::empty();
    return mTrack->getParameters(keys);
}

void MediaPlayer2Manager::AudioOutput::setAudioAttributes(const audio_attributes_t * attributes) {
    Mutex::Autolock lock(mLock);
    if (attributes == NULL) {
        free(mAttributes);
        mAttributes = NULL;
    } else {
        if (mAttributes == NULL) {
            mAttributes = (audio_attributes_t *) calloc(1, sizeof(audio_attributes_t));
        }
        memcpy(mAttributes, attributes, sizeof(audio_attributes_t));
        mStreamType = audio_attributes_to_stream_type(attributes);
    }
}

void MediaPlayer2Manager::AudioOutput::setAudioStreamType(audio_stream_type_t streamType)
{
    Mutex::Autolock lock(mLock);
    // do not allow direct stream type modification if attributes have been set
    if (mAttributes == NULL) {
        mStreamType = streamType;
    }
}

void MediaPlayer2Manager::AudioOutput::deleteRecycledTrack_l()
{
    ALOGV("deleteRecycledTrack_l");
    if (mRecycledTrack != 0) {

        if (mCallbackData != NULL) {
            mCallbackData->setOutput(NULL);
            mCallbackData->endTrackSwitch();
        }

        if ((mRecycledTrack->getFlags() & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) == 0) {
            int32_t msec = 0;
            if (!mRecycledTrack->stopped()) { // check if active
                 (void)mRecycledTrack->pendingDuration(&msec);
            }
            mRecycledTrack->stop(); // ensure full data drain
            ALOGD("deleting recycled track, waiting for data drain (%d msec)", msec);
            if (msec > 0) {
                static const int32_t WAIT_LIMIT_MS = 3000;
                if (msec > WAIT_LIMIT_MS) {
                    msec = WAIT_LIMIT_MS;
                }
                usleep(msec * 1000LL);
            }
        }
        // An offloaded track isn't flushed because the STREAM_END is reported
        // slightly prematurely to allow time for the gapless track switch
        // but this means that if we decide not to recycle the track there
        // could be a small amount of residual data still playing. We leave
        // AudioFlinger to drain the track.

        mRecycledTrack.clear();
        close_l();
        delete mCallbackData;
        mCallbackData = NULL;
    }
}

void MediaPlayer2Manager::AudioOutput::close_l()
{
    mTrack.clear();
}

status_t MediaPlayer2Manager::AudioOutput::open(
        uint32_t sampleRate, int channelCount, audio_channel_mask_t channelMask,
        audio_format_t format, int bufferCount,
        AudioCallback cb, void *cookie,
        audio_output_flags_t flags,
        const audio_offload_info_t *offloadInfo,
        bool doNotReconnect,
        uint32_t suggestedFrameCount)
{
    ALOGV("open(%u, %d, 0x%x, 0x%x, %d, %d 0x%x)", sampleRate, channelCount, channelMask,
                format, bufferCount, mSessionId, flags);

    // offloading is only supported in callback mode for now.
    // offloadInfo must be present if offload flag is set
    if (((flags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) != 0) &&
            ((cb == NULL) || (offloadInfo == NULL))) {
        return BAD_VALUE;
    }

    // compute frame count for the AudioTrack internal buffer
    size_t frameCount;
    if ((flags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) != 0) {
        frameCount = 0; // AudioTrack will get frame count from AudioFlinger
    } else {
        // try to estimate the buffer processing fetch size from AudioFlinger.
        // framesPerBuffer is approximate and generally correct, except when it's not :-).
        uint32_t afSampleRate;
        size_t afFrameCount;
        if (AudioSystem::getOutputFrameCount(&afFrameCount, mStreamType) != NO_ERROR) {
            return NO_INIT;
        }
        if (AudioSystem::getOutputSamplingRate(&afSampleRate, mStreamType) != NO_ERROR) {
            return NO_INIT;
        }
        const size_t framesPerBuffer =
                (unsigned long long)sampleRate * afFrameCount / afSampleRate;

        if (bufferCount == 0) {
            // use suggestedFrameCount
            bufferCount = (suggestedFrameCount + framesPerBuffer - 1) / framesPerBuffer;
        }
        // Check argument bufferCount against the mininum buffer count
        if (bufferCount != 0 && bufferCount < mMinBufferCount) {
            ALOGV("bufferCount (%d) increased to %d", bufferCount, mMinBufferCount);
            bufferCount = mMinBufferCount;
        }
        // if frameCount is 0, then AudioTrack will get frame count from AudioFlinger
        // which will be the minimum size permitted.
        frameCount = bufferCount * framesPerBuffer;
    }

    if (channelMask == CHANNEL_MASK_USE_CHANNEL_ORDER) {
        channelMask = audio_channel_out_mask_from_count(channelCount);
        if (0 == channelMask) {
            ALOGE("open() error, can\'t derive mask for %d audio channels", channelCount);
            return NO_INIT;
        }
    }

    Mutex::Autolock lock(mLock);
    mCallback = cb;
    mCallbackCookie = cookie;

    // Check whether we can recycle the track
    bool reuse = false;
    bool bothOffloaded = false;

    if (mRecycledTrack != 0) {
        // check whether we are switching between two offloaded tracks
        bothOffloaded = (flags & mRecycledTrack->getFlags()
                                & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) != 0;

        // check if the existing track can be reused as-is, or if a new track needs to be created.
        reuse = true;

        if ((mCallbackData == NULL && mCallback != NULL) ||
                (mCallbackData != NULL && mCallback == NULL)) {
            // recycled track uses callbacks but the caller wants to use writes, or vice versa
            ALOGV("can't chain callback and write");
            reuse = false;
        } else if ((mRecycledTrack->getSampleRate() != sampleRate) ||
                (mRecycledTrack->channelCount() != (uint32_t)channelCount) ) {
            ALOGV("samplerate, channelcount differ: %u/%u Hz, %u/%d ch",
                  mRecycledTrack->getSampleRate(), sampleRate,
                  mRecycledTrack->channelCount(), channelCount);
            reuse = false;
        } else if (flags != mFlags) {
            ALOGV("output flags differ %08x/%08x", flags, mFlags);
            reuse = false;
        } else if (mRecycledTrack->format() != format) {
            reuse = false;
        }
    } else {
        ALOGV("no track available to recycle");
    }

    ALOGV_IF(bothOffloaded, "both tracks offloaded");

    // If we can't recycle and both tracks are offloaded
    // we must close the previous output before opening a new one
    if (bothOffloaded && !reuse) {
        ALOGV("both offloaded and not recycling");
        deleteRecycledTrack_l();
    }

    sp<AudioTrack> t;
    CallbackData *newcbd = NULL;

    // We don't attempt to create a new track if we are recycling an
    // offloaded track. But, if we are recycling a non-offloaded or we
    // are switching where one is offloaded and one isn't then we create
    // the new track in advance so that we can read additional stream info

    if (!(reuse && bothOffloaded)) {
        ALOGV("creating new AudioTrack");

        if (mCallback != NULL) {
            newcbd = new CallbackData(this);
            t = new AudioTrack(
                    mStreamType,
                    sampleRate,
                    format,
                    channelMask,
                    frameCount,
                    flags,
                    CallbackWrapper,
                    newcbd,
                    0,  // notification frames
                    mSessionId,
                    AudioTrack::TRANSFER_CALLBACK,
                    offloadInfo,
                    mUid,
                    mPid,
                    mAttributes,
                    doNotReconnect,
                    1.0f,  // default value for maxRequiredSpeed
                    mSelectedDeviceId);
        } else {
            // TODO: Due to buffer memory concerns, we use a max target playback speed
            // based on mPlaybackRate at the time of open (instead of kMaxRequiredSpeed),
            // also clamping the target speed to 1.0 <= targetSpeed <= kMaxRequiredSpeed.
            const float targetSpeed =
                    std::min(std::max(mPlaybackRate.mSpeed, 1.0f), kMaxRequiredSpeed);
            ALOGW_IF(targetSpeed != mPlaybackRate.mSpeed,
                    "track target speed:%f clamped from playback speed:%f",
                    targetSpeed, mPlaybackRate.mSpeed);
            t = new AudioTrack(
                    mStreamType,
                    sampleRate,
                    format,
                    channelMask,
                    frameCount,
                    flags,
                    NULL, // callback
                    NULL, // user data
                    0, // notification frames
                    mSessionId,
                    AudioTrack::TRANSFER_DEFAULT,
                    NULL, // offload info
                    mUid,
                    mPid,
                    mAttributes,
                    doNotReconnect,
                    targetSpeed,
                    mSelectedDeviceId);
        }

        if ((t == 0) || (t->initCheck() != NO_ERROR)) {
            ALOGE("Unable to create audio track");
            delete newcbd;
            // t goes out of scope, so reference count drops to zero
            return NO_INIT;
        } else {
            // successful AudioTrack initialization implies a legacy stream type was generated
            // from the audio attributes
            mStreamType = t->streamType();
        }
    }

    if (reuse) {
        CHECK(mRecycledTrack != NULL);

        if (!bothOffloaded) {
            if (mRecycledTrack->frameCount() != t->frameCount()) {
                ALOGV("framecount differs: %zu/%zu frames",
                      mRecycledTrack->frameCount(), t->frameCount());
                reuse = false;
            }
        }

        if (reuse) {
            ALOGV("chaining to next output and recycling track");
            close_l();
            mTrack = mRecycledTrack;
            mRecycledTrack.clear();
            if (mCallbackData != NULL) {
                mCallbackData->setOutput(this);
            }
            delete newcbd;
            return updateTrack();
        }
    }

    // we're not going to reuse the track, unblock and flush it
    // this was done earlier if both tracks are offloaded
    if (!bothOffloaded) {
        deleteRecycledTrack_l();
    }

    CHECK((t != NULL) && ((mCallback == NULL) || (newcbd != NULL)));

    mCallbackData = newcbd;
    ALOGV("setVolume");
    t->setVolume(mLeftVolume, mRightVolume);

    mSampleRateHz = sampleRate;
    mFlags = flags;
    mMsecsPerFrame = 1E3f / (mPlaybackRate.mSpeed * sampleRate);
    mFrameSize = t->frameSize();
    mTrack = t;

    return updateTrack();
}

status_t MediaPlayer2Manager::AudioOutput::updateTrack() {
    if (mTrack == NULL) {
        return NO_ERROR;
    }

    status_t res = NO_ERROR;
    // Note some output devices may give us a direct track even though we don't specify it.
    // Example: Line application b/17459982.
    if ((mTrack->getFlags()
            & (AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD | AUDIO_OUTPUT_FLAG_DIRECT)) == 0) {
        res = mTrack->setPlaybackRate(mPlaybackRate);
        if (res == NO_ERROR) {
            mTrack->setAuxEffectSendLevel(mSendLevel);
            res = mTrack->attachAuxEffect(mAuxEffectId);
        }
    }
    mTrack->setOutputDevice(mSelectedDeviceId);
    if (mDeviceCallbackEnabled) {
        mTrack->addAudioDeviceCallback(mDeviceCallback.promote());
    }
    ALOGV("updateTrack() DONE status %d", res);
    return res;
}

status_t MediaPlayer2Manager::AudioOutput::start()
{
    ALOGV("start");
    Mutex::Autolock lock(mLock);
    if (mCallbackData != NULL) {
        mCallbackData->endTrackSwitch();
    }
    if (mTrack != 0) {
        mTrack->setVolume(mLeftVolume, mRightVolume);
        mTrack->setAuxEffectSendLevel(mSendLevel);
        status_t status = mTrack->start();
        return status;
    }
    return NO_INIT;
}

void MediaPlayer2Manager::AudioOutput::setNextOutput(const sp<AudioOutput>& nextOutput) {
    Mutex::Autolock lock(mLock);
    mNextOutput = nextOutput;
}

void MediaPlayer2Manager::AudioOutput::switchToNextOutput() {
    ALOGV("switchToNextOutput");

    // Try to acquire the callback lock before moving track (without incurring deadlock).
    const unsigned kMaxSwitchTries = 100;
    Mutex::Autolock lock(mLock);
    for (unsigned tries = 0;;) {
        if (mTrack == 0) {
            return;
        }
        if (mNextOutput != NULL && mNextOutput != this) {
            if (mCallbackData != NULL) {
                // two alternative approaches
#if 1
                CallbackData *callbackData = mCallbackData;
                mLock.unlock();
                // proper acquisition sequence
                callbackData->lock();
                mLock.lock();
                // Caution: it is unlikely that someone deleted our callback or changed our target
                if (callbackData != mCallbackData || mNextOutput == NULL || mNextOutput == this) {
                    // fatal if we are starved out.
                    LOG_ALWAYS_FATAL_IF(++tries > kMaxSwitchTries,
                            "switchToNextOutput() cannot obtain correct lock sequence");
                    callbackData->unlock();
                    continue;
                }
                callbackData->mSwitching = true; // begin track switch
                callbackData->setOutput(NULL);
#else
                // tryBeginTrackSwitch() returns false if the callback has the lock.
                if (!mCallbackData->tryBeginTrackSwitch()) {
                    // fatal if we are starved out.
                    LOG_ALWAYS_FATAL_IF(++tries > kMaxSwitchTries,
                            "switchToNextOutput() cannot obtain callback lock");
                    mLock.unlock();
                    usleep(5 * 1000 /* usec */); // allow callback to use AudioOutput
                    mLock.lock();
                    continue;
                }
#endif
            }

            Mutex::Autolock nextLock(mNextOutput->mLock);

            // If the next output track is not NULL, then it has been
            // opened already for playback.
            // This is possible even without the next player being started,
            // for example, the next player could be prepared and seeked.
            //
            // Presuming it isn't advisable to force the track over.
             if (mNextOutput->mTrack == NULL) {
                ALOGD("Recycling track for gapless playback");
                delete mNextOutput->mCallbackData;
                mNextOutput->mCallbackData = mCallbackData;
                mNextOutput->mRecycledTrack = mTrack;
                mNextOutput->mSampleRateHz = mSampleRateHz;
                mNextOutput->mMsecsPerFrame = mMsecsPerFrame;
                mNextOutput->mFlags = mFlags;
                mNextOutput->mFrameSize = mFrameSize;
                close_l();
                mCallbackData = NULL;  // destruction handled by mNextOutput
            } else {
                ALOGW("Ignoring gapless playback because next player has already started");
                // remove track in case resource needed for future players.
                if (mCallbackData != NULL) {
                    mCallbackData->endTrackSwitch();  // release lock for callbacks before close.
                }
                close_l();
            }
        }
        break;
    }
}

ssize_t MediaPlayer2Manager::AudioOutput::write(const void* buffer, size_t size, bool blocking)
{
    Mutex::Autolock lock(mLock);
    LOG_ALWAYS_FATAL_IF(mCallback != NULL, "Don't call write if supplying a callback.");

    //ALOGV("write(%p, %u)", buffer, size);
    if (mTrack != 0) {
        return mTrack->write(buffer, size, blocking);
    }
    return NO_INIT;
}

void MediaPlayer2Manager::AudioOutput::stop()
{
    ALOGV("stop");
    Mutex::Autolock lock(mLock);
    if (mTrack != 0) mTrack->stop();
}

void MediaPlayer2Manager::AudioOutput::flush()
{
    ALOGV("flush");
    Mutex::Autolock lock(mLock);
    if (mTrack != 0) mTrack->flush();
}

void MediaPlayer2Manager::AudioOutput::pause()
{
    ALOGV("pause");
    Mutex::Autolock lock(mLock);
    if (mTrack != 0) mTrack->pause();
}

void MediaPlayer2Manager::AudioOutput::close()
{
    ALOGV("close");
    sp<AudioTrack> track;
    {
        Mutex::Autolock lock(mLock);
        track = mTrack;
        close_l(); // clears mTrack
    }
    // destruction of the track occurs outside of mutex.
}

void MediaPlayer2Manager::AudioOutput::setVolume(float left, float right)
{
    ALOGV("setVolume(%f, %f)", left, right);
    Mutex::Autolock lock(mLock);
    mLeftVolume = left;
    mRightVolume = right;
    if (mTrack != 0) {
        mTrack->setVolume(left, right);
    }
}

status_t MediaPlayer2Manager::AudioOutput::setPlaybackRate(const AudioPlaybackRate &rate)
{
    ALOGV("setPlaybackRate(%f %f %d %d)",
                rate.mSpeed, rate.mPitch, rate.mFallbackMode, rate.mStretchMode);
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) {
        // remember rate so that we can set it when the track is opened
        mPlaybackRate = rate;
        return OK;
    }
    status_t res = mTrack->setPlaybackRate(rate);
    if (res != NO_ERROR) {
        return res;
    }
    // rate.mSpeed is always greater than 0 if setPlaybackRate succeeded
    CHECK_GT(rate.mSpeed, 0.f);
    mPlaybackRate = rate;
    if (mSampleRateHz != 0) {
        mMsecsPerFrame = 1E3f / (rate.mSpeed * mSampleRateHz);
    }
    return res;
}

status_t MediaPlayer2Manager::AudioOutput::getPlaybackRate(AudioPlaybackRate *rate)
{
    ALOGV("setPlaybackRate");
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) {
        return NO_INIT;
    }
    *rate = mTrack->getPlaybackRate();
    return NO_ERROR;
}

status_t MediaPlayer2Manager::AudioOutput::setAuxEffectSendLevel(float level)
{
    ALOGV("setAuxEffectSendLevel(%f)", level);
    Mutex::Autolock lock(mLock);
    mSendLevel = level;
    if (mTrack != 0) {
        return mTrack->setAuxEffectSendLevel(level);
    }
    return NO_ERROR;
}

status_t MediaPlayer2Manager::AudioOutput::attachAuxEffect(int effectId)
{
    ALOGV("attachAuxEffect(%d)", effectId);
    Mutex::Autolock lock(mLock);
    mAuxEffectId = effectId;
    if (mTrack != 0) {
        return mTrack->attachAuxEffect(effectId);
    }
    return NO_ERROR;
}

status_t MediaPlayer2Manager::AudioOutput::setOutputDevice(audio_port_handle_t deviceId)
{
    ALOGV("setOutputDevice(%d)", deviceId);
    Mutex::Autolock lock(mLock);
    mSelectedDeviceId = deviceId;
    if (mTrack != 0) {
        return mTrack->setOutputDevice(deviceId);
    }
    return NO_ERROR;
}

status_t MediaPlayer2Manager::AudioOutput::getRoutedDeviceId(audio_port_handle_t* deviceId)
{
    ALOGV("getRoutedDeviceId");
    Mutex::Autolock lock(mLock);
    if (mTrack != 0) {
        mRoutedDeviceId = mTrack->getRoutedDeviceId();
    }
    *deviceId = mRoutedDeviceId;
    return NO_ERROR;
}

status_t MediaPlayer2Manager::AudioOutput::enableAudioDeviceCallback(bool enabled)
{
    ALOGV("enableAudioDeviceCallback, %d", enabled);
    Mutex::Autolock lock(mLock);
    mDeviceCallbackEnabled = enabled;
    if (mTrack != 0) {
        status_t status;
        if (enabled) {
            status = mTrack->addAudioDeviceCallback(mDeviceCallback.promote());
        } else {
            status = mTrack->removeAudioDeviceCallback(mDeviceCallback.promote());
        }
        return status;
    }
    return NO_ERROR;
}

// static
void MediaPlayer2Manager::AudioOutput::CallbackWrapper(
        int event, void *cookie, void *info) {
    //ALOGV("callbackwrapper");
    CallbackData *data = (CallbackData*)cookie;
    // lock to ensure we aren't caught in the middle of a track switch.
    data->lock();
    AudioOutput *me = data->getOutput();
    AudioTrack::Buffer *buffer = (AudioTrack::Buffer *)info;
    if (me == NULL) {
        // no output set, likely because the track was scheduled to be reused
        // by another player, but the format turned out to be incompatible.
        data->unlock();
        if (buffer != NULL) {
            buffer->size = 0;
        }
        return;
    }

    switch(event) {
    case AudioTrack::EVENT_MORE_DATA: {
        size_t actualSize = (*me->mCallback)(
                me, buffer->raw, buffer->size, me->mCallbackCookie,
                CB_EVENT_FILL_BUFFER);

        // Log when no data is returned from the callback.
        // (1) We may have no data (especially with network streaming sources).
        // (2) We may have reached the EOS and the audio track is not stopped yet.
        // Note that AwesomePlayer/AudioPlayer will only return zero size when it reaches the EOS.
        // NuPlayer2Renderer will return zero when it doesn't have data (it doesn't block to fill).
        //
        // This is a benign busy-wait, with the next data request generated 10 ms or more later;
        // nevertheless for power reasons, we don't want to see too many of these.

        ALOGV_IF(actualSize == 0 && buffer->size > 0, "callbackwrapper: empty buffer returned");

        buffer->size = actualSize;
        } break;

    case AudioTrack::EVENT_STREAM_END:
        // currently only occurs for offloaded callbacks
        ALOGV("callbackwrapper: deliver EVENT_STREAM_END");
        (*me->mCallback)(me, NULL /* buffer */, 0 /* size */,
                me->mCallbackCookie, CB_EVENT_STREAM_END);
        break;

    case AudioTrack::EVENT_NEW_IAUDIOTRACK :
        ALOGV("callbackwrapper: deliver EVENT_TEAR_DOWN");
        (*me->mCallback)(me,  NULL /* buffer */, 0 /* size */,
                me->mCallbackCookie, CB_EVENT_TEAR_DOWN);
        break;

    case AudioTrack::EVENT_UNDERRUN:
        // This occurs when there is no data available, typically
        // when there is a failure to supply data to the AudioTrack.  It can also
        // occur in non-offloaded mode when the audio device comes out of standby.
        //
        // If an AudioTrack underruns it outputs silence. Since this happens suddenly
        // it may sound like an audible pop or glitch.
        //
        // The underrun event is sent once per track underrun; the condition is reset
        // when more data is sent to the AudioTrack.
        ALOGD("callbackwrapper: EVENT_UNDERRUN (discarded)");
        break;

    default:
        ALOGE("received unknown event type: %d inside CallbackWrapper !", event);
    }

    data->unlock();
}

audio_session_t MediaPlayer2Manager::AudioOutput::getSessionId() const
{
    Mutex::Autolock lock(mLock);
    return mSessionId;
}

uint32_t MediaPlayer2Manager::AudioOutput::getSampleRate() const
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) return 0;
    return mTrack->getSampleRate();
}

int64_t MediaPlayer2Manager::AudioOutput::getBufferDurationInUs() const
{
    Mutex::Autolock lock(mLock);
    if (mTrack == 0) {
        return 0;
    }
    int64_t duration;
    if (mTrack->getBufferDurationInUs(&duration) != OK) {
        return 0;
    }
    return duration;
}

} // namespace android
