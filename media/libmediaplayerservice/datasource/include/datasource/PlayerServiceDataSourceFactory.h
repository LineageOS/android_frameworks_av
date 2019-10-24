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

#ifndef PLAYER_SERVICE_DATA_SOURCE_FACTORY_H_

#define PLAYER_SERVICE_DATA_SOURCE_FACTORY_H_

#include <datasource/DataSourceFactory.h>
#include <media/DataSource.h>
#include <sys/types.h>
#include <utils/RefBase.h>

namespace android {

struct MediaHTTPService;
class String8;
struct HTTPBase;

class PlayerServiceDataSourceFactory : public DataSourceFactory {
public:
    static sp<PlayerServiceDataSourceFactory> getInstance();
    virtual sp<DataSource> CreateMediaHTTP(const sp<MediaHTTPService> &httpService);

protected:
    virtual sp<DataSource> CreateFileSource(const char *uri);

private:
    static sp<PlayerServiceDataSourceFactory> sInstance;
    static Mutex sInstanceLock;
    PlayerServiceDataSourceFactory() {};
};

}  // namespace android

#endif  // PLAYER_SERVICE_DATA_SOURCE_FACTORY_H_
