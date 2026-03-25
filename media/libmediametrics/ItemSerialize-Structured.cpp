/*
 * Copyright (C) 2026 The Android Open Source Project
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

#define LOG_TAG "mediametrics::Item-Serialization"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/endian.h>
#include <sys/types.h>

#include <cutils/multiuser.h>
#include <cutils/properties.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/SortedVector.h>
#include <utils/threads.h>

#include <media/MediaMetricsItem.h>
#include <media/MediaMetricsInternal.h>
#include <private/android_filesystem_config.h>

#include <android/media/metrics/StructuredItem.h>

namespace android::mediametrics {

// for the 'Value' subtype
using Value = android::media::metrics::StructuredItem::Value;
using Rate = android::media::metrics::StructuredItem::Rate;

// we want these *outside* of the Item class because they would require a bunch
// of stuff to be included by everyone that #includes the item class.
// The loss is that we are no longer 'inside' of the class, and therefore can't use 'this->'
// any private fields.  which is probably not a bad thing.

std::shared_ptr<StructuredItem> writeItemToStructured(mediametrics::Item& item)
{
    std::shared_ptr<StructuredItem> ret = std::make_shared<StructuredItem>();
    if (ret == nullptr) return nullptr;

    ret->key = item.getKey().c_str();
    ret->debugPid = item.getPid();
    ret->uid = item.getUid();
    ret->timestampNs = item.getTimestamp();

    // and then copy the properties over
    // std::map<std::string, Prop> mProps;
    // should *this be mProps?
    for (auto &prop : item) {
        ::android::media::metrics::StructuredItem::Property *lProp =
            new ::android::media::metrics::StructuredItem::Property();
        lProp->mName = prop.getName();
        auto lElem = prop.get();
        switch (lElem.index()) {
            case kTypeInt32:
                lProp->mValue.set<Value::mInt32>(std::get<int32_t>(prop.get()));
                break;
            case kTypeInt64:
                lProp->mValue.set<Value::mInt64>(std::get<int64_t>(prop.get()));
                break;
            case kTypeDouble:
                lProp->mValue.set<Value::mDouble>(std::get<double>(prop.get()));
                break;
            case kTypeCString:
                lProp->mValue.set<Value::mString>(std::get<std::string>(prop.get()));
                break;
            case kTypeRate:
                {
                    Rate r;
                    r.numerator = std::get<std::pair<int64_t, int64_t>>(lElem).first;
                    r.denominator = std::get<std::pair<int64_t, int64_t>>(lElem).second;
                    lProp->mValue.set<Value::mRate>(r);
                    ALOGD("rate item->structured");
                }
                break;
            default:
                ALOGE("Property '%s' has unknown type %zu", prop.getName(), lElem.index());
                break;
        }
        ret->properties.push_back(*lProp);
    }

  return ret;
}

std::shared_ptr<mediametrics::Item> readFromStructuredItem( const StructuredItem *p)
{

    std::shared_ptr<mediametrics::Item> item = std::make_shared<mediametrics::Item>();
    if (item == nullptr) return nullptr;

    item->setKey(p->key.c_str());

    item->setPid(p->debugPid);
    item->setUid(p->uid);
    item->setTimestamp(p->timestampNs);

    // and then crack the properties.
    for (auto &prop : p->properties) {
        switch (prop.mValue.getTag()) {
            case Value::mInt32:
                item->setInt32(prop.mName.c_str(), prop.mValue.get<Value::mInt32>());
                break;
            case Value::mInt64:
                item->setInt64(prop.mName.c_str(), prop.mValue.get<Value::mInt64>());
                break;
            case Value::mDouble:
                item->setDouble(prop.mName.c_str(), prop.mValue.get<Value::mDouble>());
                break;
            case Value::mString:
                item->set(prop.mName.c_str(), prop.mValue.get<Value::mString>().c_str());
                break;
            case Value::mRate:
                {
                    Rate r = prop.mValue.get<Value::mRate>();
                    std::pair<int64_t,int64_t> rate;
                    rate.first = r.numerator;
                    rate.second = r.denominator;
                    item->set(prop.mName.c_str(), rate);
                    ALOGD("rate structured->item");
                }
                break;
            default:
                ALOGE("Property '%s' has unknown type %zu", prop.mName.c_str(),
                      prop.mValue.getTag());
                break;
        }
    }

    return item;
}

} // namespace android::mediametrics
