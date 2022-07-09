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

#define LOG_TAG "Camera3-TagMonitor"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include "TagMonitor.h"

#include <inttypes.h>
#include <utils/Log.h>
#include <camera/VendorTagDescriptor.h>
#include <camera_metadata_hidden.h>
#include <device3/Camera3Stream.h>

namespace android {

TagMonitor::TagMonitor():
        mMonitoringEnabled(false),
        mMonitoringEvents(kMaxMonitorEvents),
        mVendorTagId(CAMERA_METADATA_INVALID_VENDOR_ID)
{}

TagMonitor::TagMonitor(const TagMonitor& other):
        mMonitoringEnabled(other.mMonitoringEnabled.load()),
        mMonitoredTagList(other.mMonitoredTagList),
        mLastMonitoredRequestValues(other.mLastMonitoredRequestValues),
        mLastMonitoredResultValues(other.mLastMonitoredResultValues),
        mLastMonitoredPhysicalRequestKeys(other.mLastMonitoredPhysicalRequestKeys),
        mLastMonitoredPhysicalResultKeys(other.mLastMonitoredPhysicalResultKeys),
        mMonitoringEvents(other.mMonitoringEvents),
        mVendorTagId(other.mVendorTagId) {}

const String16 TagMonitor::kMonitorOption = String16("-m");

const char* TagMonitor::k3aTags =
        "android.control.aeMode, android.control.afMode, android.control.awbMode,"
        "android.control.aeState, android.control.afState, android.control.awbState,"
        "android.control.aePrecaptureTrigger, android.control.afTrigger,"
        "android.control.aeRegions, android.control.awbRegions, android.control.afRegions,"
        "android.control.aeExposureCompensation, android.control.aeLock, android.control.awbLock,"
        "android.control.aeAntibandingMode, android.control.aeTargetFpsRange,"
        "android.control.effectMode, android.control.mode, android.control.sceneMode,"
        "android.control.videoStabilizationMode";

void TagMonitor::parseTagsToMonitor(String8 tagNames) {
    std::lock_guard<std::mutex> lock(mMonitorMutex);

    // Expand shorthands
    ssize_t idx = tagNames.find("3a");
    if (idx != -1) {
        ssize_t end = tagNames.find(",", idx);
        char* start = tagNames.lockBuffer(tagNames.size());
        start[idx] = '\0';
        char* rest = (end != -1) ? (start + end) : (start + tagNames.size());
        tagNames = String8::format("%s%s%s", start, k3aTags, rest);
    }

    sp<VendorTagDescriptor> vTags =
            VendorTagDescriptor::getGlobalVendorTagDescriptor();
    if ((nullptr == vTags.get()) || (0 >= vTags->getTagCount())) {
        sp<VendorTagDescriptorCache> cache =
                VendorTagDescriptorCache::getGlobalVendorTagCache();
        if (cache.get()) {
            cache->getVendorTagDescriptor(mVendorTagId, &vTags);
        }
    }

    bool gotTag = false;

    char *tokenized = tagNames.lockBuffer(tagNames.size());
    char *savePtr;
    char *nextTagName = strtok_r(tokenized, ", ", &savePtr);
    while (nextTagName != nullptr) {
        uint32_t tag;
        status_t res = CameraMetadata::getTagFromName(nextTagName, vTags.get(), &tag);
        if (res != OK) {
            ALOGW("%s: Unknown tag %s, ignoring", __FUNCTION__, nextTagName);
        } else {
            if (!gotTag) {
                mMonitoredTagList.clear();
                gotTag = true;
            }
            mMonitoredTagList.push_back(tag);
        }
        nextTagName = strtok_r(nullptr, ", ", &savePtr);
    }

    tagNames.unlockBuffer();

    if (gotTag) {
        // Got at least one new tag
        mMonitoringEnabled = true;
    }
}

void TagMonitor::disableMonitoring() {
    mMonitoringEnabled = false;
    mLastMonitoredRequestValues.clear();
    mLastMonitoredResultValues.clear();
    mLastMonitoredPhysicalRequestKeys.clear();
    mLastMonitoredPhysicalResultKeys.clear();
    mLastStreamIds.clear();
    mLastInputStreamId = -1;
}

void TagMonitor::monitorMetadata(eventSource source, int64_t frameNumber, nsecs_t timestamp,
        const CameraMetadata& metadata,
        const std::unordered_map<std::string, CameraMetadata>& physicalMetadata,
        const camera3::camera_stream_buffer_t *outputBuffers, uint32_t numOutputBuffers,
        int32_t inputStreamId) {
    if (!mMonitoringEnabled) return;

    std::lock_guard<std::mutex> lock(mMonitorMutex);

    if (timestamp == 0) {
        timestamp = systemTime(SYSTEM_TIME_BOOTTIME);
    }
    std::unordered_set<int32_t> outputStreamIds;
    for (size_t i = 0; i < numOutputBuffers; i++) {
        const camera3::camera_stream_buffer_t *src = outputBuffers + i;
        int32_t streamId = camera3::Camera3Stream::cast(src->stream)->getId();
        outputStreamIds.emplace(streamId);
    }
    std::string emptyId;
    for (auto tag : mMonitoredTagList) {
        monitorSingleMetadata(source, frameNumber, timestamp, emptyId, tag, metadata,
                outputStreamIds, inputStreamId);

        for (auto& m : physicalMetadata) {
            monitorSingleMetadata(source, frameNumber, timestamp, m.first, tag, m.second,
                    outputStreamIds, inputStreamId);
        }
    }
}

void TagMonitor::monitorSingleMetadata(eventSource source, int64_t frameNumber, nsecs_t timestamp,
        const std::string& cameraId, uint32_t tag, const CameraMetadata& metadata,
        const std::unordered_set<int32_t> &outputStreamIds, int32_t inputStreamId) {

    CameraMetadata &lastValues = (source == REQUEST) ?
            (cameraId.empty() ? mLastMonitoredRequestValues :
                    mLastMonitoredPhysicalRequestKeys[cameraId]) :
            (cameraId.empty() ? mLastMonitoredResultValues :
                    mLastMonitoredPhysicalResultKeys[cameraId]);

    camera_metadata_ro_entry entry = metadata.find(tag);
    if (lastValues.isEmpty()) {
        lastValues = CameraMetadata(mMonitoredTagList.size());
        const camera_metadata_t *metaBuffer =
                lastValues.getAndLock();
        set_camera_metadata_vendor_id(
                const_cast<camera_metadata_t *> (metaBuffer), mVendorTagId);
        lastValues.unlock(metaBuffer);
    }

    camera_metadata_entry lastEntry = lastValues.find(tag);

    // Monitor when the stream ids change, this helps visually see what
    // monitored metadata values are for capture requests with different
    // stream ids.
    if (source == REQUEST) {
        if (inputStreamId != mLastInputStreamId) {
            mMonitoringEvents.emplace(source, frameNumber, timestamp, camera_metadata_ro_entry_t{},
                                      cameraId, std::unordered_set<int>(), inputStreamId);
            mLastInputStreamId = inputStreamId;
        }

        if (outputStreamIds != mLastStreamIds) {
            mMonitoringEvents.emplace(source, frameNumber, timestamp, camera_metadata_ro_entry_t{},
                                      cameraId, outputStreamIds, -1);
            mLastStreamIds = outputStreamIds;
        }
    }
    if (entry.count > 0) {
        bool isDifferent = false;
        if (lastEntry.count > 0) {
            // Have a last value, compare to see if changed
            if (lastEntry.type == entry.type &&
                    lastEntry.count == entry.count) {
                // Same type and count, compare values
                size_t bytesPerValue = camera_metadata_type_size[lastEntry.type];
                size_t entryBytes = bytesPerValue * lastEntry.count;
                int cmp = memcmp(entry.data.u8, lastEntry.data.u8, entryBytes);
                if (cmp != 0) {
                    isDifferent = true;
                }
            } else {
                // Count or type has changed
                isDifferent = true;
            }
        } else {
            // No last entry, so always consider to be different
            isDifferent = true;
        }

        if (isDifferent) {
            ALOGV("%s: Tag %s changed", __FUNCTION__,
                  get_local_camera_metadata_tag_name_vendor_id(
                          tag, mVendorTagId));
            lastValues.update(entry);
            mMonitoringEvents.emplace(source, frameNumber, timestamp, entry, cameraId,
                                      std::unordered_set<int>(), -1);
        }
    } else if (lastEntry.count > 0) {
        // Value has been removed
        ALOGV("%s: Tag %s removed", __FUNCTION__,
              get_local_camera_metadata_tag_name_vendor_id(
                      tag, mVendorTagId));
        lastValues.erase(tag);
        entry.tag = tag;
        entry.type = get_local_camera_metadata_tag_type_vendor_id(tag,
                mVendorTagId);
        entry.count = 0;
        mLastInputStreamId = inputStreamId;
        mLastStreamIds = outputStreamIds;
        mMonitoringEvents.emplace(source, frameNumber, timestamp, entry, cameraId,
                                  std::unordered_set<int>(), -1);
    }
}

void TagMonitor::dumpMonitoredMetadata(int fd) {
    std::lock_guard<std::mutex> lock(mMonitorMutex);

    if (mMonitoringEnabled) {
        dprintf(fd, "     Tag monitoring enabled for tags:\n");
        for (uint32_t tag : mMonitoredTagList) {
            dprintf(fd, "        %s.%s\n",
                    get_local_camera_metadata_section_name_vendor_id(tag,
                            mVendorTagId),
                    get_local_camera_metadata_tag_name_vendor_id(tag,
                            mVendorTagId));
        }
    } else {
        dprintf(fd, "     Tag monitoring disabled (enable with -m <name1,..,nameN>)\n");
    }

    if (mMonitoringEvents.size() == 0) { return; }

    dprintf(fd, "     Monitored tag event log:\n");

    std::vector<std::string> eventStrs;
    dumpMonitoredTagEventsToVectorLocked(eventStrs);
    for (const std::string &eventStr : eventStrs) {
        dprintf(fd, "        %s", eventStr.c_str());
    }
}

void TagMonitor::getLatestMonitoredTagEvents(std::vector<std::string> &out) {
    std::lock_guard<std::mutex> lock(mMonitorMutex);
    dumpMonitoredTagEventsToVectorLocked(out);
}

void TagMonitor::dumpMonitoredTagEventsToVectorLocked(std::vector<std::string> &vec) {
    if (mMonitoringEvents.size() == 0) { return; }

    for (const auto& event : mMonitoringEvents) {
        int indentation = (event.source == REQUEST) ? 15 : 30;
        String8 eventString = String8::format("f%d:%" PRId64 "ns:%*s%*s",
                event.frameNumber, event.timestamp,
                2, event.cameraId.c_str(),
                indentation,
                event.source == REQUEST ? "REQ:" : "RES:");

        if (!event.outputStreamIds.empty()) {
            eventString += " output stream ids:";
            for (const auto& id : event.outputStreamIds) {
                eventString.appendFormat(" %d", id);
            }
            eventString += "\n";
            vec.emplace_back(eventString.string());
            continue;
        }

        if (event.inputStreamId != -1) {
            eventString.appendFormat(" input stream id: %d\n", event.inputStreamId);
            vec.emplace_back(eventString.string());
            continue;
        }

        eventString += String8::format(
                "%s.%s: ",
                get_local_camera_metadata_section_name_vendor_id(event.tag, mVendorTagId),
                get_local_camera_metadata_tag_name_vendor_id(event.tag, mVendorTagId));

        if (event.newData.empty()) {
            eventString += " (Removed)\n";
        } else {
            eventString += getEventDataString(
                    event.newData.data(), event.tag, event.type,
                    event.newData.size() / camera_metadata_type_size[event.type], indentation + 18);
        }
        vec.emplace_back(eventString.string());
    }
}

#define CAMERA_METADATA_ENUM_STRING_MAX_SIZE 29

String8 TagMonitor::getEventDataString(const uint8_t* data_ptr, uint32_t tag, int type, int count,
                                       int indentation) {
    static int values_per_line[NUM_TYPES] = {
        [TYPE_BYTE]     = 16,
        [TYPE_INT32]    = 8,
        [TYPE_FLOAT]    = 8,
        [TYPE_INT64]    = 4,
        [TYPE_DOUBLE]   = 4,
        [TYPE_RATIONAL] = 4,
    };

    size_t type_size = camera_metadata_type_size[type];
    char value_string_tmp[CAMERA_METADATA_ENUM_STRING_MAX_SIZE];
    uint32_t value;

    int lines = count / values_per_line[type];
    if (count % values_per_line[type] != 0) lines++;

    String8 returnStr = String8();
    int index = 0;
    int j, k;
    for (j = 0; j < lines; j++) {
        returnStr.appendFormat("%*s[", (j != 0) ? indentation + 4 : 0, "");
        for (k = 0;
             k < values_per_line[type] && count > 0;
             k++, count--, index += type_size) {

            switch (type) {
                case TYPE_BYTE:
                    value = *(data_ptr + index);
                    if (camera_metadata_enum_snprint(tag,
                                                     value,
                                                     value_string_tmp,
                                                     sizeof(value_string_tmp))
                        == OK) {
                        returnStr += value_string_tmp;
                    } else {
                        returnStr.appendFormat("%hhu", *(data_ptr + index));
                    }
                    break;
                case TYPE_INT32:
                    value =
                            *(int32_t*)(data_ptr + index);
                    if (camera_metadata_enum_snprint(tag,
                                                     value,
                                                     value_string_tmp,
                                                     sizeof(value_string_tmp))
                        == OK) {
                        returnStr += value_string_tmp;
                    } else {
                        returnStr.appendFormat("%" PRId32 " ", *(int32_t*)(data_ptr + index));
                    }
                    break;
                case TYPE_FLOAT:
                    returnStr.appendFormat("%0.8f", *(float*)(data_ptr + index));
                    break;
                case TYPE_INT64:
                    returnStr.appendFormat("%" PRId64 " ", *(int64_t*)(data_ptr + index));
                    break;
                case TYPE_DOUBLE:
                    returnStr.appendFormat("%0.8f ", *(double*)(data_ptr + index));
                    break;
                case TYPE_RATIONAL: {
                    int32_t numerator = *(int32_t*)(data_ptr + index);
                    int32_t denominator = *(int32_t*)(data_ptr + index + 4);
                    returnStr.appendFormat("(%d / %d) ", numerator, denominator);
                    break;
                }
                default:
                    returnStr += "??? ";
            }
        }
        returnStr += "]\n";
    }
    return returnStr;
}

template<typename T>
TagMonitor::MonitorEvent::MonitorEvent(eventSource src, uint32_t frameNumber, nsecs_t timestamp,
        const T &value, const std::string& cameraId,
        const std::unordered_set<int32_t> &outputStreamIds,
        int32_t inputStreamId) :
        source(src),
        frameNumber(frameNumber),
        timestamp(timestamp),
        cameraId(cameraId),
        tag(value.tag),
        type(value.type),
        newData(value.data.u8, value.data.u8 + camera_metadata_type_size[value.type] * value.count),
        outputStreamIds(outputStreamIds),
        inputStreamId(inputStreamId) {}

TagMonitor::MonitorEvent::~MonitorEvent() {
}

} // namespace android
