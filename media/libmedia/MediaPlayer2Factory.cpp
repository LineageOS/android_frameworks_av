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

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaPlayer2Factory"
#include <utils/Log.h>

#include <cutils/properties.h>
#include <media/DataSource.h>
#include <media/MediaPlayer2Engine.h>
#include <media/stagefright/FileSource.h>
#include <media/stagefright/foundation/ADebug.h>
#include <utils/Errors.h>
#include <utils/misc.h>

#include "MediaPlayer2Factory.h"

#include "TestPlayerStub.h"
#include "nuplayer2/NuPlayer2Driver.h"

namespace android {

Mutex MediaPlayer2Factory::sLock;
MediaPlayer2Factory::tFactoryMap MediaPlayer2Factory::sFactoryMap;
bool MediaPlayer2Factory::sInitComplete = false;

status_t MediaPlayer2Factory::registerFactory_l(IFactory* factory,
                                                player2_type type) {
    if (NULL == factory) {
        ALOGE("Failed to register MediaPlayer2Factory of type %d, factory is"
              " NULL.", type);
        return BAD_VALUE;
    }

    if (sFactoryMap.indexOfKey(type) >= 0) {
        ALOGE("Failed to register MediaPlayer2Factory of type %d, type is"
              " already registered.", type);
        return ALREADY_EXISTS;
    }

    if (sFactoryMap.add(type, factory) < 0) {
        ALOGE("Failed to register MediaPlayer2Factory of type %d, failed to add"
              " to map.", type);
        return UNKNOWN_ERROR;
    }

    return OK;
}

static player2_type getDefaultPlayerType() {
    return PLAYER2_NU_PLAYER2;
}

status_t MediaPlayer2Factory::registerFactory(IFactory* factory,
                                              player2_type type) {
    Mutex::Autolock lock_(&sLock);
    return registerFactory_l(factory, type);
}

void MediaPlayer2Factory::unregisterFactory(player2_type type) {
    Mutex::Autolock lock_(&sLock);
    sFactoryMap.removeItem(type);
}

#define GET_PLAYER_TYPE_IMPL(a...)                      \
    Mutex::Autolock lock_(&sLock);                      \
                                                        \
    player2_type ret = PLAYER2_STAGEFRIGHT_PLAYER;      \
    float bestScore = 0.0;                              \
                                                        \
    for (size_t i = 0; i < sFactoryMap.size(); ++i) {   \
                                                        \
        IFactory* v = sFactoryMap.valueAt(i);           \
        float thisScore;                                \
        CHECK(v != NULL);                               \
        thisScore = v->scoreFactory(a, bestScore);      \
        if (thisScore > bestScore) {                    \
            ret = sFactoryMap.keyAt(i);                 \
            bestScore = thisScore;                      \
        }                                               \
    }                                                   \
                                                        \
    if (0.0 == bestScore) {                             \
        ret = getDefaultPlayerType();                   \
    }                                                   \
                                                        \
    return ret;

player2_type MediaPlayer2Factory::getPlayerType(const sp<MediaPlayer2Engine>& client,
                                               const char* url) {
    GET_PLAYER_TYPE_IMPL(client, url);
}

player2_type MediaPlayer2Factory::getPlayerType(const sp<MediaPlayer2Engine>& client,
                                                int fd,
                                                int64_t offset,
                                                int64_t length) {
    GET_PLAYER_TYPE_IMPL(client, fd, offset, length);
}

player2_type MediaPlayer2Factory::getPlayerType(const sp<MediaPlayer2Engine>& client,
                                                const sp<IStreamSource> &source) {
    GET_PLAYER_TYPE_IMPL(client, source);
}

player2_type MediaPlayer2Factory::getPlayerType(const sp<MediaPlayer2Engine>& client,
                                                const sp<DataSource> &source) {
    GET_PLAYER_TYPE_IMPL(client, source);
}

#undef GET_PLAYER_TYPE_IMPL

sp<MediaPlayer2Base> MediaPlayer2Factory::createPlayer(
        player2_type playerType,
        void* cookie,
        notify_callback_f notifyFunc,
        pid_t pid) {
    sp<MediaPlayer2Base> p;
    IFactory* factory;
    status_t init_result;
    Mutex::Autolock lock_(&sLock);

    if (sFactoryMap.indexOfKey(playerType) < 0) {
        ALOGE("Failed to create player object of type %d, no registered"
              " factory", playerType);
        return p;
    }

    factory = sFactoryMap.valueFor(playerType);
    CHECK(NULL != factory);
    p = factory->createPlayer(pid);

    if (p == NULL) {
        ALOGE("Failed to create player object of type %d, create failed",
              playerType);
        return p;
    }

    init_result = p->initCheck();
    if (init_result == NO_ERROR) {
        p->setNotifyCallback(cookie, notifyFunc);
    } else {
        ALOGE("Failed to create player object of type %d, initCheck failed"
              " (res = %d)", playerType, init_result);
        p.clear();
    }

    return p;
}

/*****************************************************************************
 *                                                                           *
 *                     Built-In Factory Implementations                      *
 *                                                                           *
 *****************************************************************************/

class NuPlayer2Factory : public MediaPlayer2Factory::IFactory {
  public:
    virtual float scoreFactory(const sp<MediaPlayer2Engine>& /*client*/,
                               const char* url,
                               float curScore) {
        static const float kOurScore = 0.8;

        if (kOurScore <= curScore) {
            return 0.0;
        }

        if (!strncasecmp("http://", url, 7)
                || !strncasecmp("https://", url, 8)
                || !strncasecmp("file://", url, 7)) {
            size_t len = strlen(url);
            if (len >= 5 && !strcasecmp(".m3u8", &url[len - 5])) {
                return kOurScore;
            }

            if (strstr(url,"m3u8")) {
                return kOurScore;
            }

            if ((len >= 4 && !strcasecmp(".sdp", &url[len - 4])) || strstr(url, ".sdp?")) {
                return kOurScore;
            }
        }

        if (!strncasecmp("rtsp://", url, 7)) {
            return kOurScore;
        }

        return 0.0;
    }

    virtual float scoreFactory(const sp<MediaPlayer2Engine>& /*client*/,
                               const sp<IStreamSource>& /*source*/,
                               float /*curScore*/) {
        return 1.0;
    }

    virtual float scoreFactory(const sp<MediaPlayer2Engine>& /*client*/,
                               const sp<DataSource>& /*source*/,
                               float /*curScore*/) {
        // Only NuPlayer2 supports setting a DataSource source directly.
        return 1.0;
    }

    virtual sp<MediaPlayer2Base> createPlayer(pid_t pid) {
        ALOGV(" create NuPlayer2");
        return new NuPlayer2Driver(pid);
    }
};

class TestPlayerFactory : public MediaPlayer2Factory::IFactory {
  public:
    virtual float scoreFactory(const sp<MediaPlayer2Engine>& /*client*/,
                               const char* url,
                               float /*curScore*/) {
        if (TestPlayerStub::canBeUsed(url)) {
            return 1.0;
        }

        return 0.0;
    }

    virtual sp<MediaPlayer2Base> createPlayer(pid_t /* pid */) {
        ALOGV("Create Test Player stub");
        return new TestPlayerStub();
    }
};

void MediaPlayer2Factory::registerBuiltinFactories() {
    Mutex::Autolock lock_(&sLock);

    if (sInitComplete) {
        return;
    }

    IFactory* factory = new NuPlayer2Factory();
    if (registerFactory_l(factory, PLAYER2_NU_PLAYER2) != OK) {
        delete factory;
    }
    factory = new TestPlayerFactory();
    if (registerFactory_l(factory, PLAYER2_TEST_PLAYER) != OK) {
        delete factory;
    }

    sInitComplete = true;
}

}  // namespace android
