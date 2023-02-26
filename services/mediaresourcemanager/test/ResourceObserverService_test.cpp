/*
 * Copyright 2020 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "ResourceObserverService_test"

#include <iostream>
#include <list>

#include <aidl/android/media/BnResourceObserver.h>
#include <utils/Log.h>
#include "ResourceObserverService.h"
#include "ResourceManagerServiceTestUtils.h"

namespace android {

using ::aidl::android::media::BnResourceObserver;
using ::aidl::android::media::MediaObservableParcel;
using ::aidl::android::media::MediaObservableType;

#define BUSY ::aidl::android::media::MediaObservableEvent::kBusy
#define IDLE ::aidl::android::media::MediaObservableEvent::kIdle
#define ALL ::aidl::android::media::MediaObservableEvent::kAll

struct EventTracker {
    struct Event {
        enum { NoEvent, Busy, Idle } type = NoEvent;
        int uid = 0;
        int pid = 0;
        std::vector<MediaObservableParcel> observables;
    };

    static const Event NoEvent;

    static std::string toString(const MediaObservableParcel& observable) {
        return "{" + ::aidl::android::media::toString(observable.type)
        + ", " + std::to_string(observable.value) + "}";
    }
    static std::string toString(const Event& event) {
        std::string eventStr;
        switch (event.type) {
        case Event::Busy:
            eventStr = "Busy";
            break;
        case Event::Idle:
            eventStr = "Idle";
            break;
        default:
            return "NoEvent";
        }
        std::string observableStr;
        for (auto &observable : event.observables) {
            if (!observableStr.empty()) {
                observableStr += ", ";
            }
            observableStr += toString(observable);
        }
        return "{" + eventStr + ", " + std::to_string(event.uid) + ", "
                + std::to_string(event.pid) + ", {" + observableStr + "}}";
    }

    static Event Busy(int uid, int pid, const std::vector<MediaObservableParcel>& observables) {
        return { Event::Busy, uid, pid, observables };
    }
    static Event Idle(int uid, int pid, const std::vector<MediaObservableParcel>& observables) {
        return { Event::Idle, uid, pid, observables };
    }

    // Pop 1 event from front, wait for up to timeoutUs if empty.
    const Event& pop(int64_t timeoutUs = 0) {
        std::unique_lock lock(mLock);

        if (mEventQueue.empty() && timeoutUs > 0) {
            mCondition.wait_for(lock, std::chrono::microseconds(timeoutUs));
        }

        if (mEventQueue.empty()) {
            mPoppedEvent = NoEvent;
        } else {
            mPoppedEvent = *mEventQueue.begin();
            mEventQueue.pop_front();
        }

        return mPoppedEvent;
    }

    // Push 1 event to back.
    void append(const Event& event) {
        ALOGD("%s", toString(event).c_str());

        std::unique_lock lock(mLock);

        mEventQueue.push_back(event);
        mCondition.notify_one();
    }

private:
    std::mutex mLock;
    std::condition_variable mCondition;
    Event mPoppedEvent;
    std::list<Event> mEventQueue;
};

const EventTracker::Event EventTracker::NoEvent;

static MediaResource createSecureVideoCodecResource(int amount = 1) {
    return MediaResource(MediaResource::Type::kSecureCodec,
        MediaResource::SubType::kVideoCodec, amount);
}

static MediaResource createNonSecureVideoCodecResource(int amount = 1) {
    return MediaResource(MediaResource::Type::kNonSecureCodec,
        MediaResource::SubType::kVideoCodec, amount);
}

static MediaResource createSecureAudioCodecResource(int amount = 1) {
    return MediaResource(MediaResource::Type::kSecureCodec,
        MediaResource::SubType::kAudioCodec, amount);
}

static MediaResource createNonSecureAudioCodecResource(int amount = 1) {
    return MediaResource(MediaResource::Type::kNonSecureCodec,
        MediaResource::SubType::kAudioCodec, amount);
}

// Operators for GTest macros.
bool operator==(const EventTracker::Event& lhs, const EventTracker::Event& rhs) {
    return lhs.type == rhs.type && lhs.uid == rhs.uid && lhs.pid == rhs.pid &&
            lhs.observables == rhs.observables;
}

std::ostream& operator<<(std::ostream& str, const EventTracker::Event& v) {
    str << EventTracker::toString(v);
    return str;
}

struct TestObserver : public BnResourceObserver, public EventTracker {
    TestObserver(const char *name) : mName(name) {}
    ~TestObserver() = default;
    Status onStatusChanged(MediaObservableEvent event, int32_t uid, int32_t pid,
            const std::vector<MediaObservableParcel>& observables) override {
        ALOGD("%s: %s", mName.c_str(), __FUNCTION__);
        if (event == MediaObservableEvent::kBusy) {
            append(Busy(uid, pid, observables));
        } else {
            append(Idle(uid, pid, observables));
        }

        return Status::ok();
    }
    std::string mName;
};

class ResourceObserverServiceTest : public ResourceManagerServiceTestBase {
public:
    ResourceObserverServiceTest() : ResourceManagerServiceTestBase(),
        mObserverService(::ndk::SharedRefBase::make<ResourceObserverService>()),
        mTestObserver1(::ndk::SharedRefBase::make<TestObserver>("observer1")),
        mTestObserver2(::ndk::SharedRefBase::make<TestObserver>("observer2")),
        mTestObserver3(::ndk::SharedRefBase::make<TestObserver>("observer3")) {
        mService->setObserverService(mObserverService);
    }

    void registerObservers(MediaObservableEvent filter = ALL) {
        std::vector<MediaObservableFilter> filters1, filters2, filters3;
        filters1 = {{MediaObservableType::kVideoSecureCodec, filter}};
        filters2 = {{MediaObservableType::kVideoNonSecureCodec, filter}};
        filters3 = {{MediaObservableType::kVideoSecureCodec, filter},
                   {MediaObservableType::kVideoNonSecureCodec, filter}};

        // mTestObserver1 monitors secure video codecs.
        EXPECT_TRUE(mObserverService->registerObserver(mTestObserver1, filters1).isOk());

        // mTestObserver2 monitors non-secure video codecs.
        EXPECT_TRUE(mObserverService->registerObserver(mTestObserver2, filters2).isOk());

        // mTestObserver3 monitors both secure & non-secure video codecs.
        EXPECT_TRUE(mObserverService->registerObserver(mTestObserver3, filters3).isOk());
    }

protected:
    std::shared_ptr<ResourceObserverService> mObserverService;
    std::shared_ptr<TestObserver> mTestObserver1;
    std::shared_ptr<TestObserver> mTestObserver2;
    std::shared_ptr<TestObserver> mTestObserver3;
};

TEST_F(ResourceObserverServiceTest, testRegisterObserver) {
    std::vector<MediaObservableFilter> filters1;
    Status status;

    // Register with null observer should fail.
    status = mObserverService->registerObserver(nullptr, filters1);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), BAD_VALUE);

    // Register with empty observables should fail.
    status = mObserverService->registerObserver(mTestObserver1, filters1);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), BAD_VALUE);

    // mTestObserver1 monitors secure video codecs.
    filters1 = {{MediaObservableType::kVideoSecureCodec, ALL}};
    EXPECT_TRUE(mObserverService->registerObserver(mTestObserver1, filters1).isOk());

    // Register duplicates should fail.
    status = mObserverService->registerObserver(mTestObserver1, filters1);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), ALREADY_EXISTS);
}

TEST_F(ResourceObserverServiceTest, testUnregisterObserver) {
    std::vector<MediaObservableFilter> filters1;
    Status status;

    // Unregister without registering first should fail.
    status = mObserverService->unregisterObserver(mTestObserver1);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), NAME_NOT_FOUND);

    // mTestObserver1 monitors secure video codecs.
    filters1 = {{MediaObservableType::kVideoSecureCodec, ALL}};
    EXPECT_TRUE(mObserverService->registerObserver(mTestObserver1, filters1).isOk());
    EXPECT_TRUE(mObserverService->unregisterObserver(mTestObserver1).isOk());

    // Unregister again should fail.
    status = mObserverService->unregisterObserver(mTestObserver1);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), NAME_NOT_FOUND);
}

TEST_F(ResourceObserverServiceTest, testAddResourceBasic) {
    registerObservers();

    std::vector<MediaObservableParcel> observables1, observables2, observables3;
    observables1 = {{MediaObservableType::kVideoSecureCodec, 1}};
    observables2 = {{MediaObservableType::kVideoNonSecureCodec, 1}};
    observables3 = {{MediaObservableType::kVideoSecureCodec, 1},
                   {MediaObservableType::kVideoNonSecureCodec, 1}};

    ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kTestPid1),
                                 .uid = static_cast<int32_t>(kTestUid1),
                                 .id = getId(mTestClient1),
                                 .name = "none"};

    ClientInfoParcel client2Info{.pid = static_cast<int32_t>(kTestPid2),
                                 .uid = static_cast<int32_t>(kTestUid2),
                                 .id = getId(mTestClient2),
                                 .name = "none"};

    ClientInfoParcel client3Info{.pid = static_cast<int32_t>(kTestPid2),
                                 .uid = static_cast<int32_t>(kTestUid2),
                                 .id = getId(mTestClient3),
                                 .name = "none"};
    std::vector<MediaResourceParcel> resources;
    // Add secure video codec.
    resources = {createSecureVideoCodecResource()};
    mService->addResource(client1Info, mTestClient1, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::Busy(kTestUid1, kTestPid1, observables1));
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Busy(kTestUid1, kTestPid1, observables1));

    // Add non-secure video codec.
    resources = {createNonSecureVideoCodecResource()};
    mService->addResource(client2Info, mTestClient2, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables2));

    // Add secure & non-secure video codecs.
    resources = {createSecureVideoCodecResource(),
                 createNonSecureVideoCodecResource()};
    mService->addResource(client3Info, mTestClient3, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables1));
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables3));

    // Add additional audio codecs, should be ignored.
    resources.push_back(createSecureAudioCodecResource());
    resources.push_back(createNonSecureAudioCodecResource());
    mService->addResource(client1Info, mTestClient1, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::Busy(kTestUid1, kTestPid1, observables1));
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Busy(kTestUid1, kTestPid1, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Busy(kTestUid1, kTestPid1, observables3));
}

TEST_F(ResourceObserverServiceTest, testAddResourceMultiple) {
    registerObservers();

    std::vector<MediaObservableParcel> observables1, observables2, observables3;
    observables1 = {{MediaObservableType::kVideoSecureCodec, 1}};
    observables2 = {{MediaObservableType::kVideoNonSecureCodec, 1}};
    observables3 = {{MediaObservableType::kVideoSecureCodec, 1},
                   {MediaObservableType::kVideoNonSecureCodec, 1}};

    std::vector<MediaResourceParcel> resources;

    // Add multiple secure & non-secure video codecs.
    // Multiple entries of the same type should be merged, count should be propagated correctly.
    resources = {createSecureVideoCodecResource(),
                 createSecureVideoCodecResource(),
                 createNonSecureVideoCodecResource(3)};
    observables1 = {{MediaObservableType::kVideoSecureCodec, 2}};
    observables2 = {{MediaObservableType::kVideoNonSecureCodec, 3}};
    observables3 = {{MediaObservableType::kVideoSecureCodec, 2},
                   {MediaObservableType::kVideoNonSecureCodec, 3}};
    ClientInfoParcel client3Info{.pid = static_cast<int32_t>(kTestPid2),
                                 .uid = static_cast<int32_t>(kTestUid2),
                                 .id = getId(mTestClient3),
                                 .name = "none"};
    mService->addResource(client3Info, mTestClient3, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables1));
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables3));
}

TEST_F(ResourceObserverServiceTest, testRemoveResourceBasic) {
    registerObservers();

    std::vector<MediaObservableParcel> observables1, observables2, observables3;
    observables1 = {{MediaObservableType::kVideoSecureCodec, 1}};
    observables2 = {{MediaObservableType::kVideoNonSecureCodec, 1}};
    observables3 = {{MediaObservableType::kVideoSecureCodec, 1},
                   {MediaObservableType::kVideoNonSecureCodec, 1}};

    ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kTestPid1),
                                 .uid = static_cast<int32_t>(kTestUid1),
                                 .id = getId(mTestClient1),
                                 .name = "none"};

    ClientInfoParcel client2Info{.pid = static_cast<int32_t>(kTestPid2),
                                 .uid = static_cast<int32_t>(kTestUid2),
                                 .id = getId(mTestClient2),
                                 .name = "none"};

    ClientInfoParcel client3Info{.pid = static_cast<int32_t>(kTestPid2),
                                 .uid = static_cast<int32_t>(kTestUid2),
                                 .id = getId(mTestClient3),
                                 .name = "none"};
    std::vector<MediaResourceParcel> resources;
    // Add secure video codec to client1.
    resources = {createSecureVideoCodecResource()};
    mService->addResource(client1Info, mTestClient1, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::Busy(kTestUid1, kTestPid1, observables1));
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Busy(kTestUid1, kTestPid1, observables1));
    // Remove secure video codec. observer 1&3 should receive updates.
    mService->removeResource(client1Info, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::Idle(kTestUid1, kTestPid1, observables1));
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Idle(kTestUid1, kTestPid1, observables1));
    // Remove secure video codec again, should have no event.
    mService->removeResource(client1Info, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::NoEvent);
    // Remove client1, should have no event.
    mService->removeClient(client1Info);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::NoEvent);

    // Add non-secure video codec to client2.
    resources = {createNonSecureVideoCodecResource()};
    mService->addResource(client2Info, mTestClient2, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables2));
    // Remove client2, observer 2&3 should receive updates.
    mService->removeClient(client2Info);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables2));
    // Remove non-secure codec after client2 removed, should have no event.
    mService->removeResource(client2Info, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::NoEvent);
    // Remove client2 again, should have no event.
    mService->removeClient(client2Info);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::NoEvent);

    // Add secure & non-secure video codecs, plus audio codecs (that's ignored).
    resources = {createSecureVideoCodecResource(),
                 createNonSecureVideoCodecResource(),
                 createSecureAudioCodecResource(),
                 createNonSecureAudioCodecResource()};
    mService->addResource(client3Info, mTestClient3, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables1));
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables3));
    // Remove one audio codec, should have no event.
    resources = {createSecureAudioCodecResource()};
    mService->removeResource(client3Info, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::NoEvent);
    // Remove the other audio codec and the secure video codec, only secure video codec
    // removal should be reported.
    resources = {createNonSecureAudioCodecResource(),
                 createSecureVideoCodecResource()};
    mService->removeResource(client3Info, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables1));
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables1));
    // Remove client3 entirely. Non-secure video codec removal should be reported.
    mService->removeClient(client3Info);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables2));
}

TEST_F(ResourceObserverServiceTest, testRemoveResourceMultiple) {
    registerObservers();

    std::vector<MediaObservableParcel> observables1, observables2, observables3;
    observables1 = {{MediaObservableType::kVideoSecureCodec, 1}};
    observables2 = {{MediaObservableType::kVideoNonSecureCodec, 1}};
    observables3 = {{MediaObservableType::kVideoSecureCodec, 1},
                    {MediaObservableType::kVideoNonSecureCodec, 1}};

    std::vector<MediaResourceParcel> resources;

    // Add multiple secure & non-secure video codecs, plus audio codecs (that's ignored).
    // (ResourceManager will merge these internally.)
    resources = {createSecureVideoCodecResource(),
                 createNonSecureVideoCodecResource(4),
                 createSecureAudioCodecResource(),
                 createNonSecureAudioCodecResource()};

    ClientInfoParcel client3Info{.pid = static_cast<int32_t>(kTestPid2),
                                 .uid = static_cast<int32_t>(kTestUid2),
                                 .id = getId(mTestClient3),
                                 .name = "none"};
    mService->addResource(client3Info, mTestClient3, resources);
    observables1 = {{MediaObservableType::kVideoSecureCodec, 1}};
    observables2 = {{MediaObservableType::kVideoNonSecureCodec, 4}};
    observables3 = {{MediaObservableType::kVideoSecureCodec, 1},
                    {MediaObservableType::kVideoNonSecureCodec, 4}};
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables1));
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables3));
    // Remove one audio codec, 2 secure video codecs and 2 non-secure video codecs.
    // 1 secure video codec removal and 2 non-secure video codec removals should be reported.
    resources = {createNonSecureAudioCodecResource(),
                 createSecureVideoCodecResource(),
                 createSecureVideoCodecResource(),
                 createNonSecureVideoCodecResource(2)};
    mService->removeResource(client3Info, resources);
    observables1 = {{MediaObservableType::kVideoSecureCodec, 1}};
    observables2 = {{MediaObservableType::kVideoNonSecureCodec, 2}};
    observables3 = {{MediaObservableType::kVideoSecureCodec, 1},
                    {MediaObservableType::kVideoNonSecureCodec, 2}};
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables1));
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables3));
    // Remove client3 entirely. 2 non-secure video codecs removal should be reported.
    mService->removeClient(client3Info);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables2));
}

TEST_F(ResourceObserverServiceTest, testEventFilters) {
    // Register observers with different event filters.
    std::vector<MediaObservableFilter> filters1, filters2, filters3;
    filters1 = {{MediaObservableType::kVideoSecureCodec, BUSY}};
    filters2 = {{MediaObservableType::kVideoNonSecureCodec, IDLE}};
    filters3 = {{MediaObservableType::kVideoSecureCodec, IDLE},
               {MediaObservableType::kVideoNonSecureCodec, BUSY}};

    // mTestObserver1 monitors secure video codecs.
    EXPECT_TRUE(mObserverService->registerObserver(mTestObserver1, filters1).isOk());

    // mTestObserver2 monitors non-secure video codecs.
    EXPECT_TRUE(mObserverService->registerObserver(mTestObserver2, filters2).isOk());

    // mTestObserver3 monitors both secure & non-secure video codecs.
    EXPECT_TRUE(mObserverService->registerObserver(mTestObserver3, filters3).isOk());

    std::vector<MediaObservableParcel> observables1, observables2;
    observables1 = {{MediaObservableType::kVideoSecureCodec, 1}};
    observables2 = {{MediaObservableType::kVideoNonSecureCodec, 1}};

    std::vector<MediaResourceParcel> resources;

    // Add secure & non-secure video codecs.
    resources = {createSecureVideoCodecResource(),
                 createNonSecureVideoCodecResource()};
    ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kTestPid1),
                                 .uid = static_cast<int32_t>(kTestUid1),
                                 .id = getId(mTestClient1),
                                 .name = "none"};

    ClientInfoParcel client2Info{.pid = static_cast<int32_t>(kTestPid2),
                                 .uid = static_cast<int32_t>(kTestUid2),
                                 .id = getId(mTestClient2),
                                 .name = "none"};

    ClientInfoParcel client3Info{.pid = static_cast<int32_t>(kTestPid2),
                                 .uid = static_cast<int32_t>(kTestUid2),
                                 .id = getId(mTestClient3),
                                 .name = "none"};
    mService->addResource(client3Info, mTestClient3, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables1));
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Busy(kTestUid2, kTestPid2, observables2));

    // Remove secure & non-secure video codecs.
    mService->removeResource(client3Info, resources);
    EXPECT_EQ(mTestObserver1->pop(), EventTracker::NoEvent);
    EXPECT_EQ(mTestObserver2->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables2));
    EXPECT_EQ(mTestObserver3->pop(), EventTracker::Idle(kTestUid2, kTestPid2, observables1));
}

} // namespace android
