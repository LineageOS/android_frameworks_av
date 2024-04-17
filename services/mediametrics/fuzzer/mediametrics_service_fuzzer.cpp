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
#include <fuzzer/FuzzedDataProvider.h>
#include <media/MediaMetricsItem.h>
#include <mediametricsservice/AudioTypes.h>
#include <mediametricsservice/MediaMetricsService.h>
#include <mediametricsservice/StringUtils.h>
#include <stdio.h>
#include <string.h>
#include <utils/Log.h>
#include <algorithm>

using namespace android;

// low water mark
constexpr size_t kLogItemsLowWater = 1;
// high water mark
constexpr size_t kLogItemsHighWater = 2;
constexpr size_t kMaxItemLength = 16;
constexpr size_t kMaxApis = 64;

class MediaMetricsServiceFuzzer {
   public:
    void invokeStartsWith(const uint8_t *data, size_t size);
    void invokeInstantiate(const uint8_t *data, size_t size);
    void invokePackageInstallerCheck(const uint8_t *data, size_t size);
    void invokeItemManipulation(const uint8_t *data, size_t size);
    void invokeItemExpansion(const uint8_t *data, size_t size);
    void invokeTimeMachineStorage(const uint8_t *data, size_t size);
    void invokeTransactionLog(const uint8_t *data, size_t size);
    void invokeAnalyticsAction(const uint8_t *data, size_t size);
    void invokeAudioAnalytics(const uint8_t *data, size_t size);
    void invokeTimedAction(const uint8_t *data, size_t size);
    void process(const uint8_t *data, size_t size);
    std::atomic_int mValue = 0;
};

void MediaMetricsServiceFuzzer::invokeStartsWith(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    while (fdp.remaining_bytes()) {
        android::mediametrics::startsWith(fdp.ConsumeRandomLengthString(),
                                          fdp.ConsumeRandomLengthString());
    }
}

void MediaMetricsServiceFuzzer::invokeInstantiate(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    sp mediaMetricsService = new MediaMetricsService();

    while (fdp.remaining_bytes()) {
        std::unique_ptr<mediametrics::Item> random_key(
            mediametrics::Item::create(fdp.ConsumeRandomLengthString()));
        mediaMetricsService->submit(random_key.get());
        random_key->setInt32(fdp.ConsumeRandomLengthString().c_str(),
                             fdp.ConsumeIntegral<int32_t>());
        mediaMetricsService->submit(random_key.get());

        std::unique_ptr<mediametrics::Item> audiotrack_key(
            mediametrics::Item::create("audiotrack"));
        mediaMetricsService->submit(audiotrack_key.get());
        audiotrack_key->addInt32(fdp.ConsumeRandomLengthString().c_str(),
                                 fdp.ConsumeIntegral<int32_t>());
        mediaMetricsService->submit(audiotrack_key.get());
    }
}

void MediaMetricsServiceFuzzer::invokePackageInstallerCheck(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    while (fdp.remaining_bytes()) {
        MediaMetricsService::useUidForPackage(fdp.ConsumeRandomLengthString().c_str(),
                                              fdp.ConsumeRandomLengthString().c_str());
    }
}

void MediaMetricsServiceFuzzer::invokeItemManipulation(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);

    mediametrics::Item item(fdp.ConsumeRandomLengthString().c_str());
    while (fdp.remaining_bytes()) {
        const uint8_t action = fdp.ConsumeIntegralInRange<uint8_t>(0, 16);
        const std::string key = fdp.ConsumeRandomLengthString();
        if (fdp.remaining_bytes() < 1 || key.length() < 1) {
            break;
        }
        switch (action) {
            case 0: {
                item.setInt32(key.c_str(), fdp.ConsumeIntegral<int32_t>());
                break;
            }
            case 1: {
                item.addInt32(key.c_str(), fdp.ConsumeIntegral<int32_t>());
                break;
            }
            case 2: {
                int32_t i32 = 0;
                item.getInt32(key.c_str(), &i32);
                break;
            }
            case 3: {
                item.setInt64(key.c_str(), fdp.ConsumeIntegral<int64_t>());
                break;
            }
            case 4: {
                item.addInt64(key.c_str(), fdp.ConsumeIntegral<int64_t>());
                break;
            }
            case 5: {
                int64_t i64 = 0;
                item.getInt64(key.c_str(), &i64);
                break;
            }
            case 6: {
                item.setDouble(key.c_str(), fdp.ConsumeFloatingPoint<double>());
                break;
            }
            case 7: {
                item.addDouble(key.c_str(), fdp.ConsumeFloatingPoint<double>());
                break;
            }
            case 8: {
                double d = 0;
                item.getDouble(key.c_str(), &d);
                break;
            }
            case 9: {
                item.setCString(key.c_str(), fdp.ConsumeRandomLengthString().c_str());
                break;
            }
            case 10: {
                char *s = nullptr;
                item.getCString(key.c_str(), &s);
                if (s) free(s);
                break;
            }
            case 11: {
                std::string s;
                item.getString(key.c_str(), &s);
                break;
            }
            case 12: {
                item.setRate(key.c_str(), fdp.ConsumeIntegral<int64_t>(),
                             fdp.ConsumeIntegral<int64_t>());
                break;
            }
            case 13: {
                int64_t b = 0, h = 0;
                double d = 0;
                item.getRate(key.c_str(), &b, &h, &d);
                break;
            }
            case 14: {
                (void)item.filter(key.c_str());
                break;
            }
            case 15: {
                const char *arr[1] = {""};
                arr[0] = const_cast<char *>(key.c_str());
                (void)item.filterNot(1, arr);
                break;
            }
            case 16: {
                (void)item.toString().c_str();
                break;
            }
        }
    }

    Parcel p;
    mediametrics::Item item2;

    (void)item.writeToParcel(&p);
    p.setDataPosition(0);  // rewind for reading
    (void)item2.readFromParcel(p);

    char *byteData = nullptr;
    size_t length = 0;
    (void)item.writeToByteString(&byteData, &length);
    (void)item2.readFromByteString(byteData, length);
    if (byteData) {
        free(byteData);
    }

    sp mediaMetricsService = new MediaMetricsService();
    mediaMetricsService->submit(&item2);
}

void MediaMetricsServiceFuzzer::invokeItemExpansion(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);

    mediametrics::LogItem<1> item("FuzzItem");
    item.setPid(fdp.ConsumeIntegral<int16_t>()).setUid(fdp.ConsumeIntegral<int16_t>());

    while (fdp.remaining_bytes()) {
        int32_t i = fdp.ConsumeIntegral<int32_t>();
        item.set(std::to_string(i).c_str(), (int32_t)i);
    }
    item.updateHeader();

    mediametrics::Item item2;
    (void)item2.readFromByteString(item.getBuffer(), item.getLength());

    sp mediaMetricsService = new MediaMetricsService();
    mediaMetricsService->submit(&item2);
}

void MediaMetricsServiceFuzzer::invokeTimeMachineStorage(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);

    auto item = std::make_shared<mediametrics::Item>("FuzzKey");
    int32_t i32 = fdp.ConsumeIntegral<int32_t>();
    int64_t i64 = fdp.ConsumeIntegral<int64_t>();
    double d = fdp.ConsumeFloatingPoint<double>();
    std::string str = fdp.ConsumeRandomLengthString();
    std::pair<int64_t, int64_t> pair(fdp.ConsumeIntegral<int64_t>(),
                                     fdp.ConsumeIntegral<int64_t>());
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

void MediaMetricsServiceFuzzer::invokeTransactionLog(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);

    auto item = std::make_shared<mediametrics::Item>("Key1");
    (*item)
        .set("one", fdp.ConsumeIntegral<int32_t>())
        .set("two", fdp.ConsumeIntegral<int32_t>())
        .setTimestamp(fdp.ConsumeIntegral<int32_t>());

    android::mediametrics::TransactionLog transactionLog(
        kLogItemsLowWater, kLogItemsHighWater);  // keep at most 2 items
    transactionLog.size();

    transactionLog.put(item);
    transactionLog.size();

    auto item2 = std::make_shared<mediametrics::Item>("Key2");
    (*item2)
        .set("three", fdp.ConsumeIntegral<int32_t>())
        .set("[Key1]three", fdp.ConsumeIntegral<int32_t>())
        .setTimestamp(fdp.ConsumeIntegral<int32_t>());

    transactionLog.put(item2);
    transactionLog.size();

    auto item3 = std::make_shared<mediametrics::Item>("Key3");
    (*item3)
        .set("six", fdp.ConsumeIntegral<int32_t>())
        .set("[Key1]four", fdp.ConsumeIntegral<int32_t>())  // affects Key1
        .set("[Key1]five", fdp.ConsumeIntegral<int32_t>())  // affects key1
        .setTimestamp(fdp.ConsumeIntegral<int32_t>());

    transactionLog.put(item3);
    transactionLog.size();
}

void MediaMetricsServiceFuzzer::invokeAnalyticsAction(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);

    mediametrics::AnalyticsActions analyticsActions;
    bool action = false;

    while (fdp.remaining_bytes()) {
        analyticsActions.addAction(
            (fdp.ConsumeRandomLengthString() + std::string(".event")).c_str(),
            fdp.ConsumeRandomLengthString(),
            std::make_shared<mediametrics::AnalyticsActions::Function>(
                [&](const std::shared_ptr<const android::mediametrics::Item> &) {
                    action = true;
                }));
    }

    FuzzedDataProvider fdp2 = FuzzedDataProvider(data, size);
    size_t apiCount = 0;
    while (fdp2.remaining_bytes() && ++apiCount <= kMaxApis) {
        // make a test item
        auto item = std::make_shared<mediametrics::Item>(
                fdp2.ConsumeRandomLengthString(kMaxItemLength).c_str());
        (*item).set("event", fdp2.ConsumeRandomLengthString().c_str());

        // get the actions and execute them
        auto actions = analyticsActions.getActionsForItem(item);
        for (const auto &action : actions) {
            action->operator()(item);
        }
    }
}

void MediaMetricsServiceFuzzer::invokeAudioAnalytics(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    std::shared_ptr<android::mediametrics::StatsdLog> statsdLog =
            std::make_shared<android::mediametrics::StatsdLog>(10);
    android::mediametrics::AudioAnalytics audioAnalytics{statsdLog};

    while (fdp.remaining_bytes()) {
        auto item = std::make_shared<mediametrics::Item>(fdp.ConsumeRandomLengthString().c_str());
        int32_t transactionUid = fdp.ConsumeIntegral<int32_t>();  // arbitrary
        (*item)
            .set(fdp.ConsumeRandomLengthString().c_str(), fdp.ConsumeIntegral<int32_t>())
            .set(fdp.ConsumeRandomLengthString().c_str(), fdp.ConsumeIntegral<int32_t>())
            .set(AMEDIAMETRICS_PROP_ALLOWUID, transactionUid)
            .setUid(transactionUid)
            .setTimestamp(fdp.ConsumeIntegral<int32_t>());
        audioAnalytics.submit(item, fdp.ConsumeBool());
    }

    audioAnalytics.dump(1000);
}

void MediaMetricsServiceFuzzer::invokeTimedAction(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    android::mediametrics::TimedAction timedAction;

    while (fdp.remaining_bytes()) {
        timedAction.postIn(std::chrono::seconds(fdp.ConsumeIntegral<int32_t>()),
                           [this] { ++mValue; });
        timedAction.size();
    }
}

void MediaMetricsServiceFuzzer::process(const uint8_t *data, size_t size) {
    invokeStartsWith(data, size);
    invokeInstantiate(data, size);
    invokePackageInstallerCheck(data, size);
    invokeItemManipulation(data, size);
    invokeItemExpansion(data, size);
    invokeTimeMachineStorage(data, size);
    invokeTransactionLog(data, size);
    invokeAnalyticsAction(data, size);
    invokeAudioAnalytics(data, size);
    invokeTimedAction(data, size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    MediaMetricsServiceFuzzer mediaMetricsServiceFuzzer;
    mediaMetricsServiceFuzzer.process(data, size);
    return 0;
}
