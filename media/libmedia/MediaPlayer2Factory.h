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

#ifndef ANDROID_MEDIAPLAYER2FACTORY_H
#define ANDROID_MEDIAPLAYER2FACTORY_H

#include <media/MediaPlayer2Interface.h>
#include <media/stagefright/foundation/ABase.h>

namespace android {

class MediaPlayer2Factory {
  public:
    class IFactory {
      public:
        virtual ~IFactory() { }

        virtual float scoreFactory(const sp<MediaPlayer2Engine>& /*client*/,
                                   const char* /*url*/,
                                   float /*curScore*/) { return 0.0; }

        virtual float scoreFactory(const sp<MediaPlayer2Engine>& /*client*/,
                                   int /*fd*/,
                                   int64_t /*offset*/,
                                   int64_t /*length*/,
                                   float /*curScore*/) { return 0.0; }

        virtual float scoreFactory(const sp<MediaPlayer2Engine>& /*client*/,
                                   const sp<IStreamSource> &/*source*/,
                                   float /*curScore*/) { return 0.0; }

        virtual float scoreFactory(const sp<MediaPlayer2Engine>& /*client*/,
                                   const sp<DataSource> &/*source*/,
                                   float /*curScore*/) { return 0.0; }

        virtual sp<MediaPlayer2Base> createPlayer(pid_t pid) = 0;
    };

    static player2_type getPlayerType(const sp<MediaPlayer2Engine>& client,
                                      const char* url);
    static player2_type getPlayerType(const sp<MediaPlayer2Engine>& client,
                                      int fd,
                                      int64_t offset,
                                      int64_t length);
    static player2_type getPlayerType(const sp<MediaPlayer2Engine>& client,
                                      const sp<IStreamSource> &source);
    static player2_type getPlayerType(const sp<MediaPlayer2Engine>& client,
                                      const sp<DataSource> &source);

    static sp<MediaPlayer2Base> createPlayer(player2_type playerType,
                                             const wp<MediaPlayer2Engine> &client,
                                             MediaPlayer2Base::NotifyCallback notifyFunc,
                                             pid_t pid);

    static void registerBuiltinFactories();

  private:
    typedef KeyedVector<player2_type, IFactory*> tFactoryMap;

    MediaPlayer2Factory() { }

    static bool ensureInit_l();

    static status_t registerFactory_l(IFactory* factory,
                                      player2_type type);

    static Mutex       sLock;
    static tFactoryMap *sFactoryMap;
    static bool        sInitComplete;

    DISALLOW_EVIL_CONSTRUCTORS(MediaPlayer2Factory);
};

}  // namespace android
#endif  // ANDROID_MEDIAPLAYER2FACTORY_H
