/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */
#include <binder/IPCThreadState.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/MediaMetricsItem.h>
#include <mediametricsservice/AudioTypes.h>
#include <mediametricsservice/MediaMetricsService.h>
#include <mediametricsservice/StringUtils.h>
#include <stdio.h>
#include <string.h>
#include <utils/Log.h>
#include <algorithm>
#include <set>

using namespace android;
static constexpr size_t STATSD_LOG_LINES_MAX = 48;
static unsigned long long kPackedCallingUid = (unsigned long long)AID_SYSTEM << 32;
constexpr int8_t kMaxBytes = 100;
constexpr int8_t kMinBytes = 0;
constexpr size_t kMaxItemLength = 16;

// low water mark
constexpr size_t kLogItemsLowWater = 1;
// high water mark
constexpr size_t kLogItemsHighWater = 2;

/*
 * Concatenating strings to generate keys in such a way that the
 * lambda function inside AudioAnalytics() added in the 'mAction' object is covered
 */

std::string keyMediaValues[] = {
        "metrics.manager",
        "mediadrm",
        "audio.device.a2dp",
        AMEDIAMETRICS_KEY_AUDIO_MIDI,
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_SPATIALIZER "*",
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD "*",
        AMEDIAMETRICS_KEY_AUDIO_FLINGER,
        AMEDIAMETRICS_KEY_AUDIO_POLICY,
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK "*",
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_RECORD "*",
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_STREAM "*",
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_DEVICE
        "postBluetoothA2dpDeviceConnectionStateSuppressNoisyIntent",
};

std::string keyMediaAction[] = {
        "createAudioPatch",
        "connected",
        AMEDIAMETRICS_PROP_EVENT_VALUE_CREATE,
        AMEDIAMETRICS_PROP_EVENT_VALUE_TIMEOUT,
        AMEDIAMETRICS_PROP_EVENT_VALUE_CTOR,
        AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAAUDIOSTREAM,
        AMEDIAMETRICS_PROP_EVENT_VALUE_DEVICECLOSED,
        AMEDIAMETRICS_PROP_EVENT_VALUE_SETVOICEVOLUME,
        AMEDIAMETRICS_PROP_EVENT_VALUE_SETMODE,
        AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP,
};

class MediaMetricsServiceFuzzer {
  public:
    MediaMetricsServiceFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();
    void invokeStartsWith();
    void invokeInstantiate();
    void invokePackageInstallerCheck();
    void invokeTimeMachineStorage();
    void invokeTransactionLog();
    void invokeAnalyticsAction();
    void invokeAudioAnalytics();
    void invokeTimedAction();
    void setKeyValues(std::shared_ptr<mediametrics::Item>& item, std::string keyValue);
    std::shared_ptr<mediametrics::Item> CreateItem();
    sp<MediaMetricsService> mMediaMetricsService;
    FuzzedDataProvider mFdp;
    std::atomic_int mValue = 0;
};

void MediaMetricsServiceFuzzer::setKeyValues(std::shared_ptr<mediametrics::Item>& item,
                                             std::string keyValue) {
    auto invokeActionAPIs = mFdp.PickValueInArray<const std::function<void()>>({
            [&]() { item->setInt32(keyValue.c_str(), mFdp.ConsumeIntegral<int32_t>()); },
            [&]() { item->addInt32(keyValue.c_str(), mFdp.ConsumeIntegral<int32_t>()); },
            [&]() { item->setInt64(keyValue.c_str(), mFdp.ConsumeIntegral<int64_t>()); },
            [&]() { item->addInt64(keyValue.c_str(), mFdp.ConsumeIntegral<int64_t>()); },
            [&]() { item->setDouble(keyValue.c_str(), mFdp.ConsumeFloatingPoint<double>()); },
            [&]() { item->addDouble(keyValue.c_str(), mFdp.ConsumeFloatingPoint<double>()); },
            [&]() { item->setTimestamp(mFdp.ConsumeIntegral<int64_t>()); },
            [&]() {
                std::string value = mFdp.ConsumeBool()
                                            ? mFdp.ConsumeRandomLengthString(kMaxBytes)
                                            : mFdp.PickValueInArray<std::string>(keyMediaAction);
                item->setCString(keyValue.c_str(), value.c_str());
            },
            [&]() {
                item->setRate(keyValue.c_str(), mFdp.ConsumeIntegral<int64_t>(),
                              mFdp.ConsumeIntegral<int64_t>());
            },
            [&]() {
                mediametrics::LogItem<1> itemTemp(mFdp.ConsumeRandomLengthString(kMaxBytes));
                itemTemp.setPid(mFdp.ConsumeIntegral<int16_t>())
                        .setUid(mFdp.ConsumeIntegral<int16_t>());

                int32_t i = mFdp.ConsumeIntegral<int32_t>();
                itemTemp.set(std::to_string(i).c_str(), (int32_t)i);
                itemTemp.updateHeader();
                (void)item->readFromByteString(itemTemp.getBuffer(), itemTemp.getLength());
            },

    });
    invokeActionAPIs();
}

std::shared_ptr<mediametrics::Item> MediaMetricsServiceFuzzer::CreateItem() {
    std::string key;
    if (mFdp.ConsumeBool()) {
        key = mFdp.ConsumeRandomLengthString(kMaxItemLength);
    } else {
        key = mFdp.PickValueInArray<std::string>(keyMediaValues);
    }

    std::shared_ptr<mediametrics::Item> item = std::make_shared<mediametrics::Item>(key.c_str());
    size_t numKeys = mFdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes);
    std::set<std::string> keySet;
    for (size_t i = 0; i < numKeys; ++i) {
        std::string keyValue;
        if (mFdp.ConsumeBool()) {
            keyValue = mFdp.ConsumeRandomLengthString(kMaxBytes);
        } else {
            keyValue = mFdp.PickValueInArray<std::string>(
                    {AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_STATE, "logSessionIkeyd"});
        }
        if (keySet.find(keyValue) == keySet.end()) {
            setKeyValues(item, keyValue);
            keySet.insert(keyValue);
        }
    }
    return item;
}

void MediaMetricsServiceFuzzer::invokeStartsWith() {
    android::mediametrics::startsWith(mFdp.ConsumeRandomLengthString(kMaxBytes),
                                      mFdp.ConsumeRandomLengthString(kMaxBytes));
}

void MediaMetricsServiceFuzzer::invokeInstantiate() {
    auto item = CreateItem();
    mMediaMetricsService->submit(item.get());
}

void MediaMetricsServiceFuzzer::invokePackageInstallerCheck() {
    MediaMetricsService::useUidForPackage(mFdp.ConsumeRandomLengthString(kMaxBytes).c_str(),
                                          mFdp.ConsumeRandomLengthString(kMaxBytes).c_str());
}

void MediaMetricsServiceFuzzer::invokeTimeMachineStorage() {
    auto item = CreateItem();
    int32_t i32 = mFdp.ConsumeIntegral<int32_t>();
    int64_t i64 = mFdp.ConsumeIntegral<int64_t>();
    double d = mFdp.ConsumeFloatingPoint<double>();
    std::string str = mFdp.ConsumeRandomLengthString(kMaxBytes);
    std::pair<int64_t, int64_t> pair(mFdp.ConsumeIntegral<int64_t>(),
                                     mFdp.ConsumeIntegral<int64_t>());
    (*item).set("i32", i32).set("i64", i64).set("double", d).set("string", str).set("rate", pair);

    android::mediametrics::TimeMachine timeMachine;
    timeMachine.put(item, true);

    timeMachine.get("Key", "i32", &i32, -1);

    timeMachine.get("Key", "i64", &i64, -1);

    timeMachine.get("Key", "double", &d, -1);

    timeMachine.get("Key", "string", &str, -1);

    timeMachine.get("Key.i32", &i32, -1);

    timeMachine.get("Key.i64", &i64, -1);

    timeMachine.get("Key.double", &d, -1);

    str.clear();
    timeMachine.get("Key.string", &str, -1);
}

void MediaMetricsServiceFuzzer::invokeTransactionLog() {
    auto item = CreateItem();

    android::mediametrics::TransactionLog transactionLog(
        kLogItemsLowWater, kLogItemsHighWater);  // keep at most 2 items
    transactionLog.size();

    transactionLog.put(item);
}

void MediaMetricsServiceFuzzer::invokeAnalyticsAction() {
    mediametrics::AnalyticsActions analyticsActions;
    bool action = false;

    analyticsActions.addAction(
            (mFdp.ConsumeRandomLengthString(kMaxBytes) + std::string(".event")).c_str(),
            mFdp.ConsumeRandomLengthString(kMaxBytes),
            std::make_shared<mediametrics::AnalyticsActions::Function>(
                    [&](const std::shared_ptr<const android::mediametrics::Item>&) {
                        action = true;
                    }));

    // make a test item
    auto item = CreateItem();
    (*item).set("event", mFdp.ConsumeRandomLengthString(kMaxBytes).c_str());

    // get the actions and execute them
    auto actions = analyticsActions.getActionsForItem(item);
    for (const auto& action : actions) {
        action->operator()(item);
        }
}

void MediaMetricsServiceFuzzer::invokeAudioAnalytics() {
    int32_t maxLogLine = mFdp.ConsumeIntegralInRange<int32_t>(0, STATSD_LOG_LINES_MAX);
    std::shared_ptr<android::mediametrics::StatsdLog> statsdLog =
            std::make_shared<android::mediametrics::StatsdLog>(maxLogLine);
    android::mediametrics::AudioAnalytics audioAnalytics{statsdLog};

    auto item = CreateItem();
    Parcel parcel;
    item->writeToParcel(&parcel);
    parcel.setDataPosition(0);
    if (mFdp.ConsumeBool()) {
        item->readFromParcel(parcel);
    }
    audioAnalytics.submit(item, mFdp.ConsumeBool());
}

void MediaMetricsServiceFuzzer::invokeTimedAction() {
    android::mediametrics::TimedAction timedAction;
    timedAction.postIn(std::chrono::seconds(mFdp.ConsumeIntegral<uint32_t>()),
                       [this] { ++mValue; });
    timedAction.size();
}

void MediaMetricsServiceFuzzer::process() {
    mMediaMetricsService = sp<MediaMetricsService>::make();

    if (mFdp.ConsumeBool()) {
        IPCThreadState::self()->restoreCallingIdentity(kPackedCallingUid);
    } else {
        IPCThreadState::self()->restoreCallingIdentity(mFdp.ConsumeIntegral<size_t>());
    }
    while (mFdp.remaining_bytes()) {
        auto invokeAPIs = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() { invokeStartsWith(); },
                [&]() { invokeInstantiate(); },
                [&]() { invokePackageInstallerCheck(); },
                [&]() { invokeTimeMachineStorage(); },
                [&]() { invokeTransactionLog(); },
                [&]() { invokeAudioAnalytics(); },
                [&]() { invokeTimedAction(); },
        });
        invokeAPIs();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) {
        return 0;
    }
    MediaMetricsServiceFuzzer mediaMetricsServiceFuzzer(data, size);
    mediaMetricsServiceFuzzer.process();
    return 0;
}
