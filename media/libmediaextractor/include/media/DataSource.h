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

#ifndef DATA_SOURCE_H_

#define DATA_SOURCE_H_

#include <sys/types.h>
#include <media/stagefright/MediaErrors.h>
#include <media/DataSourceBase.h>
#include <media/IDataSource.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/threads.h>
#include <drm/DrmManagerClient.h>


namespace android {

class String8;

class DataSource : public DataSourceBase, public virtual RefBase {
public:
    DataSource() {}

    // returns a pointer to IDataSource if it is wrapped.
    virtual sp<IDataSource> getIDataSource() const {
        return nullptr;
    }

protected:
    virtual ~DataSource() {}

private:
    DataSource(const DataSource &);
    DataSource &operator=(const DataSource &);
};

}  // namespace android

#endif  // DATA_SOURCE_H_
