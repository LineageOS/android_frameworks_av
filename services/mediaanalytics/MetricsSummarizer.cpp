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

#define LOG_TAG "MetricsSummarizer"
#include <utils/Log.h>

#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include <utils/threads.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/String8.h>
#include <utils/List.h>

#include <media/IMediaAnalyticsService.h>

#include "MetricsSummarizer.h"


namespace android {

#define DEBUG_SORT      0
#define DEBUG_QUEUE     0


MetricsSummarizer::MetricsSummarizer(const char *key)
    : mIgnorables(NULL)
{
    ALOGV("MetricsSummarizer::MetricsSummarizer");

    if (key == NULL) {
        mKey = key;
    } else {
        mKey = strdup(key);
    }

    mSummaries = new List<MediaAnalyticsItem *>();
}

MetricsSummarizer::~MetricsSummarizer()
{
    ALOGV("MetricsSummarizer::~MetricsSummarizer");
    if (mKey) {
        free((void *)mKey);
        mKey = NULL;
    }

    // clear the list of items we have saved
    while (mSummaries->size() > 0) {
        MediaAnalyticsItem * oitem = *(mSummaries->begin());
        if (DEBUG_QUEUE) {
            ALOGD("zap old record: key %s sessionID %" PRId64 " ts %" PRId64 "",
                oitem->getKey().c_str(), oitem->getSessionID(),
                oitem->getTimestamp());
        }
        mSummaries->erase(mSummaries->begin());
        delete oitem;
    }
}

// so we know what summarizer we were using
const char *MetricsSummarizer::getKey() {
    const char *value = mKey;
    if (value == NULL) {
        value = "unknown";
    }
    return value;
}

// should the record be given to this summarizer
bool MetricsSummarizer::isMine(MediaAnalyticsItem &item)
{
    if (mKey == NULL)
        return true;
    AString itemKey = item.getKey();
    if (strcmp(mKey, itemKey.c_str()) != 0) {
        return false;
    }
    return true;
}

AString MetricsSummarizer::dumpSummary(int &slot)
{
    return dumpSummary(slot, NULL);
}

AString MetricsSummarizer::dumpSummary(int &slot, const char *only)
{
    AString value = "";

    List<MediaAnalyticsItem *>::iterator it = mSummaries->begin();
    if (it != mSummaries->end()) {
        char buf[16];   // enough for "#####: "
        for (; it != mSummaries->end(); it++) {
            if (only != NULL && strcmp(only, (*it)->getKey().c_str()) != 0) {
                continue;
            }
            AString entry = (*it)->toString();
            snprintf(buf, sizeof(buf), "%5d: ", slot);
            value.append(buf);
            value.append(entry.c_str());
            value.append("\n");
            slot++;
        }
    }
    return value;
}

void MetricsSummarizer::setIgnorables(const char **ignorables) {
    mIgnorables = ignorables;
}

const char **MetricsSummarizer::getIgnorables() {
    return mIgnorables;
}

void MetricsSummarizer::handleRecord(MediaAnalyticsItem *item) {

    ALOGV("MetricsSummarizer::handleRecord() for %s",
                item == NULL ? "<nothing>" : item->toString().c_str());

    if (item == NULL) {
        return;
    }

    List<MediaAnalyticsItem *>::iterator it = mSummaries->begin();
    for (; it != mSummaries->end(); it++) {
        bool good = sameAttributes((*it), item, getIgnorables());
        ALOGV("Match against %s says %d",
              (*it)->toString().c_str(), good);
        if (good)
            break;
    }
    if (it == mSummaries->end()) {
            ALOGV("save new record");
            item = item->dup();
            if (item == NULL) {
                ALOGE("unable to save MediaMetrics record");
            }
            sortProps(item);
            item->setInt32("count",1);
            mSummaries->push_back(item);
    } else {
            ALOGV("increment existing record");
            (*it)->addInt32("count",1);
            mergeRecord(*(*it), *item);
    }
}

void MetricsSummarizer::mergeRecord(MediaAnalyticsItem &/*have*/, MediaAnalyticsItem &/*item*/) {
    // default is no further massaging.
    ALOGV("MetricsSummarizer::mergeRecord() [default]");
    return;
}


//
// Comparators
//

// testing that all of 'single' is in 'summ'
// and that the values match.
// 'summ' may have extra fields.
// 'ignorable' is a set of things that we don't worry about matching up
// (usually time- or count-based values we'll sum elsewhere)
bool MetricsSummarizer::sameAttributes(MediaAnalyticsItem *summ, MediaAnalyticsItem *single, const char **ignorable) {

    if (single == NULL || summ == NULL) {
        return false;
    }
    ALOGV("MetricsSummarizer::sameAttributes(): summ %s", summ->toString().c_str());
    ALOGV("MetricsSummarizer::sameAttributes(): single %s", single->toString().c_str());

    // this can be made better.
    for(size_t i=0;i<single->mPropCount;i++) {
        MediaAnalyticsItem::Prop *prop1 = &(single->mProps[i]);
        const char *attrName = prop1->mName;
        ALOGV("compare on attr '%s'", attrName);

        // is it something we should ignore
        if (ignorable != NULL) {
            const char **ig = ignorable;
            while (*ig) {
                if (strcmp(*ig, attrName) == 0) {
                    break;
                }
                ig++;
            }
            if (*ig) {
                ALOGV("we don't mind that it has attr '%s'", attrName);
                continue;
            }
        }

        MediaAnalyticsItem::Prop *prop2 = summ->findProp(attrName);
        if (prop2 == NULL) {
            ALOGV("summ doesn't have this attr");
            return false;
        }
        if (prop1->mType != prop2->mType) {
            ALOGV("mismatched attr types");
            return false;
        }
        switch (prop1->mType) {
            case MediaAnalyticsItem::kTypeInt32:
                if (prop1->u.int32Value != prop2->u.int32Value)
                    return false;
                break;
            case MediaAnalyticsItem::kTypeInt64:
                if (prop1->u.int64Value != prop2->u.int64Value)
                    return false;
                break;
            case MediaAnalyticsItem::kTypeDouble:
                // XXX: watch out for floating point comparisons!
                if (prop1->u.doubleValue != prop2->u.doubleValue)
                    return false;
                break;
            case MediaAnalyticsItem::kTypeCString:
                if (strcmp(prop1->u.CStringValue, prop2->u.CStringValue) != 0)
                    return false;
                break;
            case MediaAnalyticsItem::kTypeRate:
                if (prop1->u.rate.count != prop2->u.rate.count)
                    return false;
                if (prop1->u.rate.duration != prop2->u.rate.duration)
                    return false;
                break;
            default:
                return false;
        }
    }

    return true;
}

bool MetricsSummarizer::sameAttributesId(MediaAnalyticsItem *summ, MediaAnalyticsItem *single, const char **ignorable) {

    // verify same user
    if (summ->mPid != single->mPid)
        return false;

    // and finally do the more expensive validation of the attributes
    return sameAttributes(summ, single, ignorable);
}

int MetricsSummarizer::PropSorter(const void *a, const void *b) {
    MediaAnalyticsItem::Prop *ai = (MediaAnalyticsItem::Prop *)a;
    MediaAnalyticsItem::Prop *bi = (MediaAnalyticsItem::Prop *)b;
    return strcmp(ai->mName, bi->mName);
}

// we sort in the summaries so that it looks pretty in the dumpsys
void MetricsSummarizer::sortProps(MediaAnalyticsItem *item) {
    if (item->mPropCount != 0) {
        if (DEBUG_SORT) {
            ALOGD("sortProps(pre): %s", item->toString().c_str());
        }
        qsort(item->mProps, item->mPropCount,
              sizeof(MediaAnalyticsItem::Prop), MetricsSummarizer::PropSorter);
        if (DEBUG_SORT) {
            ALOGD("sortProps(pst): %s", item->toString().c_str());
        }
    }
}

} // namespace android
