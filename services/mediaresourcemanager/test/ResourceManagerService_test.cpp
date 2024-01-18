/*
 * Copyright 2015 The Android Open Source Project
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
#define LOG_TAG "ResourceManagerService_test"

#include <utils/Log.h>

#include "ResourceManagerServiceTestUtils.h"
#include "ResourceManagerService.h"

namespace android {

class ResourceManagerServiceTest : public ResourceManagerServiceTestBase {
private:
    static MediaResource createSecureVideoCodecResource(int amount = 1) {
        return MediaResource(MediaResource::Type::kSecureCodec,
            MediaResource::SubType::kHwVideoCodec, amount);
    }

    static MediaResource createNonSecureVideoCodecResource(int amount = 1) {
        return MediaResource(MediaResource::Type::kNonSecureCodec,
            MediaResource::SubType::kHwVideoCodec, amount);
    }

    static MediaResource createSecureAudioCodecResource(int amount = 1) {
        return MediaResource(MediaResource::Type::kSecureCodec,
            MediaResource::SubType::kHwAudioCodec, amount);
    }

    static MediaResource createNonSecureAudioCodecResource(int amount = 1) {
        return MediaResource(MediaResource::Type::kNonSecureCodec,
            MediaResource::SubType::kHwAudioCodec, amount);
    }

    static MediaResource createSecureImageCodecResource(int amount = 1) {
        return MediaResource(MediaResource::Type::kSecureCodec,
            MediaResource::SubType::kHwImageCodec, amount);
    }

    static MediaResource createNonSecureImageCodecResource(int amount = 1) {
        return MediaResource(MediaResource::Type::kNonSecureCodec,
            MediaResource::SubType::kHwImageCodec, amount);
    }

    static MediaResource createGraphicMemoryResource(int amount = 1) {
        return MediaResource(MediaResource::Type::kGraphicMemory,
            MediaResource::SubType::kUnspecifiedSubType, amount);
    }

    static MediaResource createDrmSessionResource(int amount = 1) {
        return MediaResource(MediaResource::Type::kDrmSession,
            MediaResource::SubType::kUnspecifiedSubType, amount);
    }

    static MediaResource createBatteryResource() {
        return MediaResource(MediaResource::Type::kBattery,
            MediaResource::SubType::kUnspecifiedSubType, 1);
    }

    static MediaResource createCpuBoostResource() {
        return MediaResource(MediaResource::Type::kCpuBoost,
            MediaResource::SubType::kUnspecifiedSubType, 1);
    }

public:
    ResourceManagerServiceTest(bool newRM = false) : ResourceManagerServiceTestBase(newRM) {}

    void updateConfig(bool bSupportsMultipleSecureCodecs, bool bSupportsSecureWithNonSecureCodec) {
        std::vector<MediaResourcePolicyParcel> policies;
        policies.push_back(
                MediaResourcePolicy(
                        IResourceManagerService::kPolicySupportsMultipleSecureCodecs,
                        bSupportsMultipleSecureCodecs ? "true" : "false"));
        policies.push_back(
                MediaResourcePolicy(
                        IResourceManagerService::kPolicySupportsSecureWithNonSecureCodec,
                        bSupportsSecureWithNonSecureCodec ? "true" : "false"));
        mService->config(policies);
    }

    // test set up
    // ---------------------------------------------------------------------------------
    //   pid                priority         client           type               number
    // ---------------------------------------------------------------------------------
    //   kTestPid1(30)      30               mTestClient1     secure codec       1
    //                                                        graphic memory     200
    //                                                        graphic memory     200
    // ---------------------------------------------------------------------------------
    //   kTestPid2(20)      20               mTestClient2     non-secure codec   1
    //                                                        graphic memory     300
    //                                       -------------------------------------------
    //                                       mTestClient3     secure codec       1
    //                                                        graphic memory     100
    // ---------------------------------------------------------------------------------
    void addResource() {
        // kTestPid1 mTestClient1
        std::vector<MediaResourceParcel> resources1;
        resources1.push_back(MediaResource(MediaResource::Type::kSecureCodec, 1));
        ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kTestPid1),
                                     .uid = static_cast<int32_t>(kTestUid1),
                                     .id = getId(mTestClient1),
                                     .name = "none"};
        mService->addResource(client1Info, mTestClient1, resources1);
        resources1.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 200));
        std::vector<MediaResourceParcel> resources11;
        resources11.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 200));
        mService->addResource(client1Info, mTestClient1, resources11);

        // kTestPid2 mTestClient2
        std::vector<MediaResourceParcel> resources2;
        resources2.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, 1));
        resources2.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 300));
        ClientInfoParcel client2Info{.pid = static_cast<int32_t>(kTestPid2),
                                     .uid = static_cast<int32_t>(kTestUid2),
                                     .id = getId(mTestClient2),
                                     .name = "none"};
        mService->addResource(client2Info, mTestClient2, resources2);

        // kTestPid2 mTestClient3
        std::vector<MediaResourceParcel> resources3;
        ClientInfoParcel client3Info{.pid = static_cast<int32_t>(kTestPid2),
                                     .uid = static_cast<int32_t>(kTestUid2),
                                     .id = getId(mTestClient3),
                                     .name = "none"};
        mService->addResource(client3Info, mTestClient3, resources3);
        resources3.push_back(MediaResource(MediaResource::Type::kSecureCodec, 1));
        resources3.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 100));
        mService->addResource(client3Info, mTestClient3, resources3);

        const PidResourceInfosMap &map = mService->getResourceMap();
        EXPECT_EQ(2u, map.size());
        const auto& mapIndex1 = map.find(kTestPid1);
        EXPECT_TRUE(mapIndex1 != map.end());
        const ResourceInfos &infos1 = mapIndex1->second;
        EXPECT_EQ(1u, infos1.size());
        expectEqResourceInfo(infos1.at(getId(mTestClient1)), kTestUid1, mTestClient1, resources1);

        const auto& mapIndex2 = map.find(kTestPid2);
        EXPECT_TRUE(mapIndex2 != map.end());
        const ResourceInfos &infos2 = mapIndex2->second;
        EXPECT_EQ(2u, infos2.size());
        expectEqResourceInfo(infos2.at(getId(mTestClient2)), kTestUid2, mTestClient2, resources2);
        expectEqResourceInfo(infos2.at(getId(mTestClient3)), kTestUid2, mTestClient3, resources3);
    }

    void testCombineResourceWithNegativeValues() {
        // kTestPid1 mTestClient1
        std::vector<MediaResourceParcel> resources1;
        resources1.push_back(MediaResource(MediaResource::Type::kDrmSession, -100));
        resources1.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, -100));
        ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kTestPid1),
                                     .uid = static_cast<int32_t>(kTestUid1),
                                     .id = getId(mTestClient1),
                                     .name = "none"};
        mService->addResource(client1Info, mTestClient1, resources1);

        // Expected result:
        // 1) the client should have been added;
        // 2) both resource entries should have been rejected, resource list should be empty.
        const PidResourceInfosMap &map = mService->getResourceMap();
        EXPECT_EQ(1u, map.size());
        const auto& mapIndex1 = map.find(kTestPid1);
        EXPECT_TRUE(mapIndex1 != map.end());
        const ResourceInfos &infos1 = mapIndex1->second;
        EXPECT_EQ(1u, infos1.size());
        std::vector<MediaResourceParcel> expected;
        expectEqResourceInfo(infos1.at(getId(mTestClient1)), kTestUid1, mTestClient1, expected);

        resources1.clear();
        resources1.push_back(MediaResource(MediaResource::Type::kDrmSession, INT64_MAX));
        resources1.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, INT64_MAX));
        mService->addResource(client1Info, mTestClient1, resources1);
        resources1.clear();
        resources1.push_back(MediaResource(MediaResource::Type::kDrmSession, 10));
        resources1.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, 10));
        mService->addResource(client1Info, mTestClient1, resources1);

        // Expected result:
        // Both values should saturate to INT64_MAX
        expected.push_back(MediaResource(MediaResource::Type::kDrmSession, INT64_MAX));
        expected.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, INT64_MAX));
        expectEqResourceInfo(infos1.at(getId(mTestClient1)), kTestUid1, mTestClient1, expected);

        resources1.clear();
        resources1.push_back(MediaResource(MediaResource::Type::kDrmSession, -10));
        resources1.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, -10));
        mService->addResource(client1Info, mTestClient1, resources1);

        // Expected result:
        // 1) DrmSession resource should allow negative value addition, and value should drop accordingly
        // 2) Non-drm session resource should ignore negative value addition.
        expected.push_back(MediaResource(MediaResource::Type::kDrmSession, INT64_MAX - 10));
        expected.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, INT64_MAX));
        expectEqResourceInfo(infos1.at(getId(mTestClient1)), kTestUid1, mTestClient1, expected);

        resources1.clear();
        resources1.push_back(MediaResource(MediaResource::Type::kDrmSession, INT64_MIN));
        mService->addResource(client1Info, mTestClient1, resources1);

        // Expected result:
        // 1) DrmSession resource value should drop to 0, but the entry shouldn't be removed.
        // 2) Non-drm session resource should ignore negative value addition.
        expected.clear();
        expected.push_back(MediaResource(MediaResource::Type::kDrmSession, 0));
        expected.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, INT64_MAX));
        expectEqResourceInfo(infos1.at(getId(mTestClient1)), kTestUid1, mTestClient1, expected);
    }

    void testConfig() {
        EXPECT_TRUE(mService->mSupportsMultipleSecureCodecs);
        EXPECT_TRUE(mService->mSupportsSecureWithNonSecureCodec);

        updateConfig(true, false);
        EXPECT_TRUE(mService->mSupportsMultipleSecureCodecs);
        EXPECT_FALSE(mService->mSupportsSecureWithNonSecureCodec);

        updateConfig(false, true);
        EXPECT_FALSE(mService->mSupportsMultipleSecureCodecs);
        EXPECT_TRUE(mService->mSupportsSecureWithNonSecureCodec);
    }

    void testCombineResource() {
        // kTestPid1 mTestClient1
        std::vector<MediaResourceParcel> resources1;
        resources1.push_back(MediaResource(MediaResource::Type::kSecureCodec, 1));
        ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kTestPid1),
                                     .uid = static_cast<int32_t>(kTestUid1),
                                     .id = getId(mTestClient1),
                                     .name = "none"};
        mService->addResource(client1Info, mTestClient1, resources1);

        std::vector<MediaResourceParcel> resources11;
        resources11.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 200));
        mService->addResource(client1Info, mTestClient1, resources11);

        const PidResourceInfosMap &map = mService->getResourceMap();
        EXPECT_EQ(1u, map.size());
        const auto& mapIndex1 = map.find(kTestPid1);
        EXPECT_TRUE(mapIndex1 != map.end());
        const ResourceInfos &infos1 = mapIndex1->second;
        EXPECT_EQ(1u, infos1.size());

        // test adding existing types to combine values
        resources1.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 100));
        mService->addResource(client1Info, mTestClient1, resources1);

        std::vector<MediaResourceParcel> expected;
        expected.push_back(MediaResource(MediaResource::Type::kSecureCodec, 2));
        expected.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 300));
        expectEqResourceInfo(infos1.at(getId(mTestClient1)), kTestUid1, mTestClient1, expected);

        // test adding new types (including types that differs only in subType)
        resources11.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, 1));
        resources11.push_back(MediaResource(MediaResource::Type::kSecureCodec,
                                            MediaResource::SubType::kHwVideoCodec, 1));
        mService->addResource(client1Info, mTestClient1, resources11);

        expected.clear();
        expected.push_back(MediaResource(MediaResource::Type::kSecureCodec, 2));
        expected.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, 1));
        expected.push_back(MediaResource(MediaResource::Type::kSecureCodec,
                                         MediaResource::SubType::kHwVideoCodec, 1));
        expected.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 500));
        expectEqResourceInfo(infos1.at(getId(mTestClient1)), kTestUid1, mTestClient1, expected);
    }

    void testRemoveResource() {
        // kTestPid1 mTestClient1
        std::vector<MediaResourceParcel> resources1;
        resources1.push_back(MediaResource(MediaResource::Type::kSecureCodec, 1));
        ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kTestPid1),
                                     .uid = static_cast<int32_t>(kTestUid1),
                                     .id = getId(mTestClient1),
                                     .name = "none"};
        mService->addResource(client1Info, mTestClient1, resources1);

        std::vector<MediaResourceParcel> resources11;
        resources11.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 200));
        mService->addResource(client1Info, mTestClient1, resources11);

        const PidResourceInfosMap &map = mService->getResourceMap();
        EXPECT_EQ(1u, map.size());
        const auto& mapIndex1 = map.find(kTestPid1);
        EXPECT_TRUE(mapIndex1 != map.end());
        const ResourceInfos &infos1 = mapIndex1->second;
        EXPECT_EQ(1u, infos1.size());

        // test partial removal
        resources11[0].value = 100;
        mService->removeResource(client1Info, resources11);

        std::vector<MediaResourceParcel> expected;
        expected.push_back(MediaResource(MediaResource::Type::kSecureCodec, 1));
        expected.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 100));
        expectEqResourceInfo(infos1.at(getId(mTestClient1)), kTestUid1, mTestClient1, expected);

        // test removal request with negative value, should be ignored
        resources11[0].value = -10000;
        mService->removeResource(client1Info, resources11);

        expectEqResourceInfo(infos1.at(getId(mTestClient1)), kTestUid1, mTestClient1, expected);

        // test complete removal with overshoot value
        resources11[0].value = 1000;
        mService->removeResource(client1Info, resources11);

        expected.clear();
        expected.push_back(MediaResource(MediaResource::Type::kSecureCodec, 1));
        expectEqResourceInfo(infos1.at(getId(mTestClient1)), kTestUid1, mTestClient1, expected);
    }

    void testOverridePid() {

        std::vector<MediaResourceParcel> resources;
        resources.push_back(MediaResource(MediaResource::Type::kSecureCodec, 1));
        resources.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 150));

        // ### secure codec can't coexist and secure codec can coexist with non-secure codec ###
        {
            addResource();
            updateConfig(false, true);

            // priority too low to reclaim resource
            ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(kLowPriorityPid),
                                        .uid = static_cast<int32_t>(kTestUid1),
                                        .id = 0,
                                        .name = "none"};
            CHECK_STATUS_FALSE(mService->reclaimResource(clientInfo, resources, &result));

            // override Low Priority Pid with High Priority Pid
            mService->overridePid(kLowPriorityPid, kHighPriorityPid);
            CHECK_STATUS_TRUE(mService->reclaimResource(clientInfo, resources, &result));

            // restore Low Priority Pid
            mService->overridePid(kLowPriorityPid, -1);
            CHECK_STATUS_FALSE(mService->reclaimResource(clientInfo, resources, &result));
        }
    }

    void testMarkClientForPendingRemoval() {
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
        {
            addResource();
            updateConfig(true, true);

            std::vector<MediaResourceParcel> resources;
            resources.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, 1));

            // Remove low priority clients
            mService->removeClient(client1Info);

            // no lower priority client
            CHECK_STATUS_FALSE(mService->reclaimResource(client2Info, resources, &result));
            EXPECT_EQ(false, toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_EQ(false, toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_EQ(false, toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            mService->markClientForPendingRemoval(client2Info);

            // client marked for pending removal from the same process got reclaimed
            CHECK_STATUS_TRUE(mService->reclaimResource(client2Info, resources, &result));
            EXPECT_EQ(false, toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_EQ(true, toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_EQ(false, toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // clean up client 3 which still left
            mService->removeClient(client3Info);
        }

        {
            addResource();
            updateConfig(true, true);

            std::vector<MediaResourceParcel> resources;
            resources.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, 1));

            mService->markClientForPendingRemoval(client2Info);

            // client marked for pending removal from the same process got reclaimed
            // first, even though there are lower priority process
            CHECK_STATUS_TRUE(mService->reclaimResource(client2Info, resources, &result));
            EXPECT_EQ(false, toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_EQ(true, toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_EQ(false, toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // lower priority client got reclaimed
            CHECK_STATUS_TRUE(mService->reclaimResource(client2Info, resources, &result));
            EXPECT_EQ(true, toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_EQ(false, toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_EQ(false, toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // clean up client 3 which still left
            mService->removeClient(client3Info);
        }

        {
            addResource();
            updateConfig(true, true);

            mService->markClientForPendingRemoval(client2Info);

            // client marked for pending removal got reclaimed
            EXPECT_TRUE(mService->reclaimResourcesFromClientsPendingRemoval(kTestPid2).isOk());
            EXPECT_EQ(false, toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_EQ(true, toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_EQ(false, toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // No more clients marked for removal
            EXPECT_TRUE(mService->reclaimResourcesFromClientsPendingRemoval(kTestPid2).isOk());
            EXPECT_EQ(false, toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_EQ(false, toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_EQ(false, toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            mService->markClientForPendingRemoval(client3Info);

            // client marked for pending removal got reclaimed
            EXPECT_TRUE(mService->reclaimResourcesFromClientsPendingRemoval(kTestPid2).isOk());
            EXPECT_EQ(false, toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_EQ(false, toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_EQ(true, toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // clean up client 1 which still left
            mService->removeClient(client1Info);
        }
    }

    void testRemoveClient() {
        addResource();

        ClientInfoParcel client2Info{.pid = static_cast<int32_t>(kTestPid2),
                                     .uid = static_cast<int32_t>(kTestUid2),
                                     .id = getId(mTestClient2),
                                     .name = "none"};
        mService->removeClient(client2Info);

        const PidResourceInfosMap &map = mService->getResourceMap();
        EXPECT_EQ(2u, map.size());
        const ResourceInfos &infos1 = map.at(kTestPid1);
        const ResourceInfos &infos2 = map.at(kTestPid2);
        EXPECT_EQ(1u, infos1.size());
        EXPECT_EQ(1u, infos2.size());
        // mTestClient2 has been removed.
        EXPECT_EQ(mTestClient3, infos2.at(getId(mTestClient3)).client);
    }

    void testGetAllClients() {
        addResource();

        std::vector<ClientInfo> targetClients;
        MediaResource resource(MediaResource::Type::kSecureCodec,
                               MediaResource::SubType::kUnspecifiedSubType,
                               1);
        ResourceRequestInfo requestInfoHigh { kHighPriorityPid, &resource};
        ResourceRequestInfo requestInfoMid { kMidPriorityPid, &resource};
        ResourceRequestInfo requestInfoLow { kLowPriorityPid, &resource};

        EXPECT_FALSE(mService->getAllClients_l(requestInfoLow, targetClients));
        // some higher priority process (e.g. kTestPid2) owns the resource, so getAllClients_l
        // will fail.
        EXPECT_FALSE(mService->getAllClients_l(requestInfoMid, targetClients));
        EXPECT_TRUE(mService->getAllClients_l(requestInfoHigh, targetClients));

        EXPECT_EQ(2u, targetClients.size());
        // (OK to require ordering in clients[], as the pid map is sorted)
        EXPECT_EQ(getId(mTestClient3), targetClients[0].mClientId);
        EXPECT_EQ(getId(mTestClient1), targetClients[1].mClientId);
    }

    void testReclaimResourceSecure() {
        std::vector<MediaResourceParcel> resources;
        resources.push_back(MediaResource(MediaResource::Type::kSecureCodec, 1));
        resources.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 150));

        ClientInfoParcel lowPriorityClient{.pid = static_cast<int32_t>(kLowPriorityPid),
                                          .uid = static_cast<int32_t>(kTestUid2),
                                           .id = 0,
                                           .name = "none"};
        ClientInfoParcel midPriorityClient{.pid = static_cast<int32_t>(kMidPriorityPid),
                                           .uid = static_cast<int32_t>(kTestUid2),
                                           .id = 0,
                                           .name = "none"};
        ClientInfoParcel highPriorityClient{.pid = static_cast<int32_t>(kHighPriorityPid),
                                            .uid = static_cast<int32_t>(kTestUid2),
                                            .id = 0,
                                            .name = "none"};

        // ### secure codec can't coexist and secure codec can coexist with non-secure codec ###
        {
            addResource();
            updateConfig(false, true);

            // priority too low
            CHECK_STATUS_FALSE(mService->reclaimResource(lowPriorityClient, resources, &result));
            CHECK_STATUS_FALSE(mService->reclaimResource(midPriorityClient, resources, &result));

            // reclaim all secure codecs
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_TRUE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // call again should reclaim one largest graphic memory from lowest process
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // nothing left
            CHECK_STATUS_FALSE(mService->reclaimResource(highPriorityClient, resources, &result));
        }

        // ### secure codecs can't coexist and secure codec can't coexist with non-secure codec ###
        {
            addResource();
            updateConfig(false, false);

            // priority too low
            CHECK_STATUS_FALSE(mService->reclaimResource(lowPriorityClient, resources, &result));
            CHECK_STATUS_FALSE(mService->reclaimResource(midPriorityClient, resources, &result));

            // reclaim all secure and non-secure codecs
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_TRUE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // nothing left
            CHECK_STATUS_FALSE(mService->reclaimResource(highPriorityClient, resources, &result));
        }


        // ### secure codecs can coexist but secure codec can't coexist with non-secure codec ###
        {
            addResource();
            updateConfig(true, false);

            // priority too low
            CHECK_STATUS_FALSE(mService->reclaimResource(lowPriorityClient, resources, &result));
            CHECK_STATUS_FALSE(mService->reclaimResource(midPriorityClient, resources, &result));

            // reclaim all non-secure codecs
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // call again should reclaim one largest graphic memory from lowest process
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_TRUE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // call again should reclaim another largest graphic memory from lowest process
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // nothing left
            CHECK_STATUS_FALSE(mService->reclaimResource(highPriorityClient, resources, &result));
        }

        // ### secure codecs can coexist and secure codec can coexist with non-secure codec ###
        {
            addResource();
            updateConfig(true, true);

            // priority too low
            CHECK_STATUS_FALSE(mService->reclaimResource(lowPriorityClient, resources, &result));

            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            // one largest graphic memory from lowest process got reclaimed
            EXPECT_TRUE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // call again should reclaim another graphic memory from lowest process
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // call again should reclaim another graphic memory from lowest process
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // nothing left
            CHECK_STATUS_FALSE(mService->reclaimResource(highPriorityClient, resources, &result));
        }

        // ### secure codecs can coexist and secure codec can coexist with non-secure codec ###
        {
            addResource();
            updateConfig(true, true);

            std::vector<MediaResourceParcel> resources;
            resources.push_back(MediaResource(MediaResource::Type::kSecureCodec, 1));

            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            // secure codec from lowest process got reclaimed
            EXPECT_TRUE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // call again should reclaim another secure codec from lowest process
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // no more secure codec, non-secure codec will be reclaimed.
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());
        }
    }

    void testReclaimResourceNonSecure() {
        std::vector<MediaResourceParcel> resources;
        resources.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, 1));
        resources.push_back(MediaResource(MediaResource::Type::kGraphicMemory, 150));

        ClientInfoParcel lowPriorityClient{.pid = static_cast<int32_t>(kLowPriorityPid),
                                          .uid = static_cast<int32_t>(kTestUid2),
                                           .id = 0,
                                           .name = "none"};
        ClientInfoParcel midPriorityClient{.pid = static_cast<int32_t>(kMidPriorityPid),
                                           .uid = static_cast<int32_t>(kTestUid2),
                                           .id = 0,
                                           .name = "none"};
        ClientInfoParcel highPriorityClient{.pid = static_cast<int32_t>(kHighPriorityPid),
                                            .uid = static_cast<int32_t>(kTestUid2),
                                            .id = 0,
                                            .name = "none"};

        // ### secure codec can't coexist with non-secure codec ###
        {
            addResource();
            updateConfig(true, false);

            // priority too low
            CHECK_STATUS_FALSE(mService->reclaimResource(lowPriorityClient, resources, &result));
            CHECK_STATUS_FALSE(mService->reclaimResource(midPriorityClient, resources, &result));

            // reclaim all secure codecs
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_TRUE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // call again should reclaim one graphic memory from lowest process
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // nothing left
            CHECK_STATUS_FALSE(mService->reclaimResource(highPriorityClient, resources, &result));
        }


        // ### secure codec can coexist with non-secure codec ###
        {
            addResource();
            updateConfig(true, true);

            // priority too low
            CHECK_STATUS_FALSE(mService->reclaimResource(lowPriorityClient, resources, &result));

            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            // one largest graphic memory from lowest process got reclaimed
            EXPECT_TRUE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // call again should reclaim another graphic memory from lowest process
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // call again should reclaim another graphic memory from lowest process
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // nothing left
            CHECK_STATUS_FALSE(mService->reclaimResource(highPriorityClient, resources, &result));
        }

        // ### secure codec can coexist with non-secure codec ###
        {
            addResource();
            updateConfig(true, true);

            std::vector<MediaResourceParcel> resources;
            resources.push_back(MediaResource(MediaResource::Type::kNonSecureCodec, 1));

            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            // one non secure codec from lowest process got reclaimed
            EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_TRUE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // no more non-secure codec, secure codec from lowest priority process will be reclaimed
            CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, resources, &result));
            EXPECT_TRUE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
            EXPECT_FALSE(toTestClient(mTestClient3)->checkIfReclaimedAndReset());

            // clean up client 3 which still left
            ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(kTestPid2),
                                        .uid = static_cast<int32_t>(kTestUid2),
                                        .id = getId(mTestClient3),
                                        .name = "none"};
            mService->removeClient(clientInfo);
        }
    }

    void testGetLowestPriorityBiggestClient() {
        ClientInfo clientInfo;
        MediaResource resource(MediaResource::Type::kGraphicMemory,
                               MediaResource::SubType::kUnspecifiedSubType,
                               1);
        ResourceRequestInfo requestInfoHigh { kHighPriorityPid, &resource};
        ResourceRequestInfo requestInfoLow { kLowPriorityPid, &resource};
        EXPECT_FALSE(mService->getLowestPriorityBiggestClient_l(requestInfoHigh, clientInfo));

        addResource();

        EXPECT_FALSE(mService->getLowestPriorityBiggestClient_l(requestInfoLow, clientInfo));
        EXPECT_TRUE(mService->getLowestPriorityBiggestClient_l(requestInfoHigh, clientInfo));

        // kTestPid1 is the lowest priority process with MediaResource::Type::kGraphicMemory.
        // mTestClient1 has the largest MediaResource::Type::kGraphicMemory within kTestPid1.
        EXPECT_EQ(getId(mTestClient1), clientInfo.mClientId);
    }

    void testGetLowestPriorityPid() {
        int pid;
        int priority;
        TestProcessInfo processInfo;

        MediaResource::Type type = MediaResource::Type::kGraphicMemory;
        MediaResource::SubType subType = MediaResource::SubType::kUnspecifiedSubType;
        EXPECT_FALSE(mService->getLowestPriorityPid_l(type, subType, &pid, &priority));

        addResource();

        EXPECT_TRUE(mService->getLowestPriorityPid_l(type, subType, &pid, &priority));
        EXPECT_EQ(kTestPid1, pid);
        int priority1;
        processInfo.getPriority(kTestPid1, &priority1);
        EXPECT_EQ(priority1, priority);

        type = MediaResource::Type::kNonSecureCodec;
        EXPECT_TRUE(mService->getLowestPriorityPid_l(type, subType, &pid, &priority));
        EXPECT_EQ(kTestPid2, pid);
        int priority2;
        processInfo.getPriority(kTestPid2, &priority2);
        EXPECT_EQ(priority2, priority);
    }

    void testIsCallingPriorityHigher() {
        EXPECT_FALSE(mService->isCallingPriorityHigher_l(101, 100));
        EXPECT_FALSE(mService->isCallingPriorityHigher_l(100, 100));
        EXPECT_TRUE(mService->isCallingPriorityHigher_l(99, 100));
    }

    void testBatteryStats() {
        // reset should always be called when ResourceManagerService is created (restarted)
        EXPECT_EQ(1u, mSystemCB->eventCount());
        EXPECT_EQ(EventType::VIDEO_RESET, mSystemCB->lastEventType());

        // new client request should cause VIDEO_ON
        std::vector<MediaResourceParcel> resources1;
        resources1.push_back(MediaResource(MediaResource::Type::kBattery,
                                           MediaResource::SubType::kHwVideoCodec, 1));
        ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kTestPid1),
                                     .uid = static_cast<int32_t>(kTestUid1),
                                     .id = getId(mTestClient1),
                                     .name = "none"};
        mService->addResource(client1Info, mTestClient1, resources1);
        EXPECT_EQ(2u, mSystemCB->eventCount());
        EXPECT_EQ(EventEntry({EventType::VIDEO_ON, kTestUid1}), mSystemCB->lastEvent());

        // each client should only cause 1 VIDEO_ON
        mService->addResource(client1Info, mTestClient1, resources1);
        EXPECT_EQ(2u, mSystemCB->eventCount());

        // new client request should cause VIDEO_ON
        std::vector<MediaResourceParcel> resources2;
        resources2.push_back(MediaResource(MediaResource::Type::kBattery,
                                           MediaResource::SubType::kHwVideoCodec, 2));
        ClientInfoParcel client2Info{.pid = static_cast<int32_t>(kTestPid2),
                                     .uid = static_cast<int32_t>(kTestUid2),
                                     .id = getId(mTestClient2),
                                     .name = "none"};
        mService->addResource(client2Info, mTestClient2, resources2);
        EXPECT_EQ(3u, mSystemCB->eventCount());
        EXPECT_EQ(EventEntry({EventType::VIDEO_ON, kTestUid2}), mSystemCB->lastEvent());

        // partially remove mTestClient1's request, shouldn't be any VIDEO_OFF
        mService->removeResource(client1Info, resources1);
        EXPECT_EQ(3u, mSystemCB->eventCount());

        // remove mTestClient1's request, should be VIDEO_OFF for kTestUid1
        // (use resource2 to test removing more instances than previously requested)
        mService->removeResource(client1Info, resources2);
        EXPECT_EQ(4u, mSystemCB->eventCount());
        EXPECT_EQ(EventEntry({EventType::VIDEO_OFF, kTestUid1}), mSystemCB->lastEvent());

        // remove mTestClient2, should be VIDEO_OFF for kTestUid2
        mService->removeClient(client2Info);
        EXPECT_EQ(5u, mSystemCB->eventCount());
        EXPECT_EQ(EventEntry({EventType::VIDEO_OFF, kTestUid2}), mSystemCB->lastEvent());
    }

    void testCpusetBoost() {
        // reset should always be called when ResourceManagerService is created (restarted)
        EXPECT_EQ(1u, mSystemCB->eventCount());
        EXPECT_EQ(EventType::VIDEO_RESET, mSystemCB->lastEventType());

        // new client request should cause CPUSET_ENABLE
        std::vector<MediaResourceParcel> resources1;
        resources1.push_back(MediaResource(MediaResource::Type::kCpuBoost, 1));
        ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kTestPid1),
                                     .uid = static_cast<int32_t>(kTestUid1),
                                     .id = getId(mTestClient1),
                                     .name = "none"};
        mService->addResource(client1Info, mTestClient1, resources1);
        EXPECT_EQ(2u, mSystemCB->eventCount());
        EXPECT_EQ(EventType::CPUSET_ENABLE, mSystemCB->lastEventType());

        // each client should only cause 1 CPUSET_ENABLE
        mService->addResource(client1Info, mTestClient1, resources1);
        EXPECT_EQ(2u, mSystemCB->eventCount());

        // new client request should cause CPUSET_ENABLE
        std::vector<MediaResourceParcel> resources2;
        resources2.push_back(MediaResource(MediaResource::Type::kCpuBoost, 2));
        ClientInfoParcel client2Info{.pid = static_cast<int32_t>(kTestPid2),
                                     .uid = static_cast<int32_t>(kTestUid2),
                                     .id = getId(mTestClient2),
                                     .name = "none"};
        mService->addResource(client2Info, mTestClient2, resources2);
        EXPECT_EQ(3u, mSystemCB->eventCount());
        EXPECT_EQ(EventType::CPUSET_ENABLE, mSystemCB->lastEventType());

        // remove mTestClient2 should not cause CPUSET_DISABLE, mTestClient1 still active
        mService->removeClient(client2Info);
        EXPECT_EQ(3u, mSystemCB->eventCount());

        // remove 1 cpuboost from mTestClient1, should not be CPUSET_DISABLE (still 1 left)
        mService->removeResource(client1Info, resources1);
        EXPECT_EQ(3u, mSystemCB->eventCount());

        // remove 2 cpuboost from mTestClient1, should be CPUSET_DISABLE
        // (use resource2 to test removing more than previously requested)
        mService->removeResource(client1Info, resources2);
        EXPECT_EQ(4u, mSystemCB->eventCount());
        EXPECT_EQ(EventType::CPUSET_DISABLE, mSystemCB->lastEventType());
    }

    void testReclaimResources_withVideoCodec_reclaimsOnlyVideoCodec() {
        const std::shared_ptr<IResourceManagerClient>& audioImageTestClient = mTestClient1;
        const std::shared_ptr<IResourceManagerClient>& videoTestClient = mTestClient2;

        // Create an audio and image codec resource
        std::vector<MediaResourceParcel> audioImageResources;
        audioImageResources.push_back(createNonSecureAudioCodecResource());
        audioImageResources.push_back(createNonSecureImageCodecResource());
        ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kLowPriorityPid),
                                     .uid = static_cast<int32_t>(kTestUid1),
                                     .id = getId(audioImageTestClient),
                                     .name = "none"};
        mService->addResource(client1Info, audioImageTestClient, audioImageResources);

        // Fail to reclaim a video codec resource
        std::vector<MediaResourceParcel> reclaimResources;
        reclaimResources.push_back(createNonSecureVideoCodecResource());
        ClientInfoParcel highPriorityClient{.pid = static_cast<int32_t>(kHighPriorityPid),
                                            .uid = static_cast<int32_t>(kTestUid2),
                                            .id = 0,
                                            .name = "none"};
        CHECK_STATUS_FALSE(mService->reclaimResource(highPriorityClient, reclaimResources, &result));

        // Now add a video codec resource
        std::vector<MediaResourceParcel> videoResources;
        videoResources.push_back(createNonSecureVideoCodecResource());
        ClientInfoParcel client2Info{.pid = static_cast<int32_t>(kLowPriorityPid),
                                     .uid = static_cast<int32_t>(kTestUid1),
                                     .id = getId(videoTestClient),
                                     .name = "none"};
        mService->addResource(client2Info, videoTestClient, videoResources);

        // Verify that the newly-created video codec resource can be reclaimed
        CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, reclaimResources, &result));

        // Verify that the audio and image resources are untouched
        EXPECT_FALSE(toTestClient(audioImageTestClient)->checkIfReclaimedAndReset());
        // But the video resource was reclaimed
        EXPECT_TRUE(toTestClient(videoTestClient)->checkIfReclaimedAndReset());
    }

    void testReclaimResources_withAudioCodec_reclaimsOnlyAudioCodec() {
        const auto & videoImageTestClient = mTestClient1;
        const auto & audioTestClient = mTestClient2;

        // Create a video and audio codec resource
        std::vector<MediaResourceParcel> videoImageResources;
        videoImageResources.push_back(createNonSecureVideoCodecResource());
        videoImageResources.push_back(createNonSecureImageCodecResource());
        ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kLowPriorityPid),
                                     .uid = static_cast<int32_t>(kTestUid1),
                                     .id = getId(videoImageTestClient),
                                     .name = "none"};
        mService->addResource(client1Info, videoImageTestClient, videoImageResources);

        // Fail to reclaim an audio codec resource
        std::vector<MediaResourceParcel> reclaimResources;
        reclaimResources.push_back(createNonSecureAudioCodecResource());
        ClientInfoParcel highPriorityClient{.pid = static_cast<int32_t>(kHighPriorityPid),
                                            .uid = static_cast<int32_t>(kTestUid2),
                                            .id = 0,
                                            .name = "none"};
        CHECK_STATUS_FALSE(mService->reclaimResource(highPriorityClient, reclaimResources, &result));

        // Now add an audio codec resource
        std::vector<MediaResourceParcel> audioResources;
        audioResources.push_back(createNonSecureAudioCodecResource());
        ClientInfoParcel client2Info{.pid = static_cast<int32_t>(kLowPriorityPid),
                                     .uid = static_cast<int32_t>(kTestUid2),
                                     .id = getId(audioTestClient),
                                     .name = "none"};
        mService->addResource(client2Info, audioTestClient, audioResources);

        // Verify that the newly-created audio codec resource can be reclaimed
        CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, reclaimResources, &result));

        // Verify that the video and image resources are untouched
        EXPECT_FALSE(toTestClient(videoImageTestClient)->checkIfReclaimedAndReset());
        // But the audio resource was reclaimed
        EXPECT_TRUE(toTestClient(audioTestClient)->checkIfReclaimedAndReset());
    }

    void testReclaimResources_withImageCodec_reclaimsOnlyImageCodec() {
        const auto & videoAudioTestClient = mTestClient1;
        const auto & imageTestClient = mTestClient2;

        // Create a video and audio codec resource
        std::vector<MediaResourceParcel> videoAudioResources;
        videoAudioResources.push_back(createNonSecureVideoCodecResource());
        videoAudioResources.push_back(createNonSecureAudioCodecResource());
        ClientInfoParcel client1Info{.pid = static_cast<int32_t>(kLowPriorityPid),
                                     .uid = static_cast<int32_t>(kTestUid1),
                                     .id = getId(videoAudioTestClient),
                                     .name = "none"};
        mService->addResource(client1Info, videoAudioTestClient, videoAudioResources);

        // Fail to reclaim an image codec resource
        std::vector<MediaResourceParcel> reclaimResources;
        reclaimResources.push_back(createNonSecureImageCodecResource());
        ClientInfoParcel highPriorityClient{.pid = static_cast<int32_t>(kHighPriorityPid),
                                            .uid = static_cast<int32_t>(kTestUid2),
                                            .id = 0,
                                            .name = "none"};
        CHECK_STATUS_FALSE(mService->reclaimResource(highPriorityClient, reclaimResources, &result));

        // Now add an image codec resource
        std::vector<MediaResourceParcel> imageResources;
        imageResources.push_back(createNonSecureImageCodecResource());
        ClientInfoParcel client2Info{.pid = static_cast<int32_t>(kLowPriorityPid),
                                     .uid = static_cast<int32_t>(kTestUid2),
                                     .id = getId(imageTestClient),
                                     .name = "none"};
        mService->addResource(client2Info, imageTestClient, imageResources);

        // Verify that the newly-created image codec resource can be reclaimed
        CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, reclaimResources, &result));

        // Verify that the video and audio resources are untouched
        EXPECT_FALSE(toTestClient(mTestClient1)->checkIfReclaimedAndReset());
        // But the image resource was reclaimed
        EXPECT_TRUE(toTestClient(mTestClient2)->checkIfReclaimedAndReset());
    }

    void testReclaimResources_whenPartialResourceMatch_reclaims() {
        const int onlyUid = kTestUid1;
        const auto onlyClient = createTestClient(kLowPriorityPid, onlyUid);

        std::vector<MediaResourceParcel> ownedResources;
        ownedResources.push_back(createNonSecureVideoCodecResource());
        ownedResources.push_back(createGraphicMemoryResource(100));
        ClientInfoParcel onlyClientInfo{.pid = static_cast<int32_t>(kLowPriorityPid),
                                       .uid = static_cast<int32_t>(onlyUid),
                                       .id = getId(onlyClient),
                                       .name = "none"};
        mService->addResource(onlyClientInfo, onlyClient, ownedResources);

        // Reclaim an image codec instead of the video codec that is owned, but also reclaim
        // graphics memory, which will trigger the reclaim.
        std::vector<MediaResourceParcel> reclaimResources;
        reclaimResources.push_back(createNonSecureImageCodecResource());
        reclaimResources.push_back(createGraphicMemoryResource(100));
        ClientInfoParcel highPriorityClient{.pid = static_cast<int32_t>(kHighPriorityPid),
                                            .uid = static_cast<int32_t>(kTestUid2),
                                            .id = 0,
                                            .name = "none"};
        CHECK_STATUS_TRUE(mService->reclaimResource(highPriorityClient, reclaimResources, &result));

        // Verify that the video codec resources (including the needed graphic memory) is reclaimed
        EXPECT_TRUE(toTestClient(onlyClient)->checkIfReclaimedAndReset());
    }

    void testReclaimResourcesFromMarkedClients_removesBiggestMarkedClientForSomeResources() {
        // this test only uses one pid and one uid
        const int onlyPid = kTestPid1;
        const int onlyUid = kTestUid1;

        // secure video codec
        const auto smallSecureVideoMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largeSecureVideoMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largestSecureVideoActiveClient = createTestClient(onlyPid, onlyUid);
        ClientInfoParcel clientA{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(smallSecureVideoMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientB{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largeSecureVideoMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientC{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largestSecureVideoActiveClient),
                                 .name = "none"};
        {
            std::vector<MediaResourceParcel> resources;
            resources.push_back(createSecureVideoCodecResource(1));
            mService->addResource(clientA, smallSecureVideoMarkedClient, resources);
            resources.clear();
            resources.push_back(createSecureVideoCodecResource(2));
            mService->addResource(clientB, largeSecureVideoMarkedClient, resources);
            resources.clear();
            resources.push_back(createSecureVideoCodecResource(3));
            mService->addResource(clientC, largestSecureVideoActiveClient, resources);
        }
        mService->markClientForPendingRemoval(clientA);
        mService->markClientForPendingRemoval(clientB);
        // don't mark the largest client

        // non-secure video codec
        const auto smallNonSecureVideoMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largeNonSecureVideoMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largestNonSecureVideoActiveClient = createTestClient(onlyPid, onlyUid);
        ClientInfoParcel clientD{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(smallNonSecureVideoMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientE{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largeNonSecureVideoMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientF{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largestNonSecureVideoActiveClient),
                                 .name = "none"};
        {
            std::vector<MediaResourceParcel> resources;
            resources.push_back(createNonSecureVideoCodecResource(1));
            mService->addResource(clientD, smallNonSecureVideoMarkedClient, resources);
            resources.clear();
            resources.push_back(createNonSecureVideoCodecResource(2));
            mService->addResource(clientE, largeNonSecureVideoMarkedClient, resources);
            resources.clear();
            resources.push_back(createNonSecureVideoCodecResource(3));
            mService->addResource(clientF, largestNonSecureVideoActiveClient, resources);
        }
        mService->markClientForPendingRemoval(clientD);
        mService->markClientForPendingRemoval(clientE);
        // don't mark the largest client

        // secure audio codec
        const auto smallSecureAudioMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largeSecureAudioMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largestSecureAudioActiveClient = createTestClient(onlyPid, onlyUid);
        ClientInfoParcel clientG{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(smallSecureAudioMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientH{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largeSecureAudioMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientI{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largestSecureVideoActiveClient),
                                 .name = "none"};
        {
            std::vector<MediaResourceParcel> resources;
            resources.push_back(createSecureAudioCodecResource(1));
            mService->addResource(clientG, smallSecureAudioMarkedClient, resources);
            resources.clear();
            resources.push_back(createSecureAudioCodecResource(2));
            mService->addResource(clientH, largeSecureAudioMarkedClient, resources);
            resources.clear();
            resources.push_back(createSecureAudioCodecResource(3));
            mService->addResource(clientI, largestSecureVideoActiveClient, resources);
        }
        mService->markClientForPendingRemoval(clientG);
        mService->markClientForPendingRemoval(clientH);
        // don't mark the largest client

        // non-secure audio codec
        const auto smallNonSecureAudioMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largeNonSecureAudioMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largestNonSecureAudioActiveClient = createTestClient(onlyPid, onlyUid);
        ClientInfoParcel clientJ{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(smallNonSecureAudioMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientK{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largeNonSecureAudioMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientL{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largestNonSecureAudioActiveClient),
                                 .name = "none"};
        {
            std::vector<MediaResourceParcel> resources;
            resources.push_back(createNonSecureAudioCodecResource(1));
            mService->addResource(clientJ, smallNonSecureAudioMarkedClient, resources);
            resources.clear();
            resources.push_back(createNonSecureAudioCodecResource(2));
            mService->addResource(clientK, largeNonSecureAudioMarkedClient, resources);
            resources.clear();
            resources.push_back(createNonSecureAudioCodecResource(3));
            mService->addResource(clientL, largestNonSecureAudioActiveClient, resources);
        }
        mService->markClientForPendingRemoval(clientJ);
        mService->markClientForPendingRemoval(clientK);
        // don't mark the largest client

        // secure image codec
        const auto smallSecureImageMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largeSecureImageMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largestSecureImageActiveClient = createTestClient(onlyPid, onlyUid);
        ClientInfoParcel clientM{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(smallSecureImageMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientN{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largeSecureImageMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientO{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largestSecureImageActiveClient),
                                 .name = "none"};
        {
            std::vector<MediaResourceParcel> resources;
            resources.push_back(createSecureImageCodecResource(1));
            mService->addResource(clientM, smallSecureImageMarkedClient, resources);
            resources.clear();
            resources.push_back(createSecureImageCodecResource(2));
            mService->addResource(clientN, largeSecureImageMarkedClient, resources);
            resources.clear();
            resources.push_back(createSecureImageCodecResource(3));
            mService->addResource(clientO, largestSecureImageActiveClient, resources);
        }
        mService->markClientForPendingRemoval(clientM);
        mService->markClientForPendingRemoval(clientN);
        // don't mark the largest client

        // non-secure image codec
        const auto smallNonSecureImageMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largeNonSecureImageMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largestNonSecureImageActiveClient = createTestClient(onlyPid, onlyUid);
        ClientInfoParcel clientP{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(smallNonSecureImageMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientQ{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largeNonSecureImageMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientR{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largestNonSecureImageActiveClient),
                                 .name = "none"};
        {
            std::vector<MediaResourceParcel> resources;
            resources.push_back(createNonSecureImageCodecResource(1));
            mService->addResource(clientP, smallNonSecureImageMarkedClient, resources);
            resources.clear();
            resources.push_back(createNonSecureImageCodecResource(2));
            mService->addResource(clientQ, largeNonSecureImageMarkedClient, resources);
            resources.clear();
            resources.push_back(createNonSecureImageCodecResource(3));
            mService->addResource(clientR, largestNonSecureImageActiveClient, resources);
        }
        mService->markClientForPendingRemoval(clientP);
        mService->markClientForPendingRemoval(clientQ);
        // don't mark the largest client

        // graphic memory
        const auto smallGraphicMemoryMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largeGraphicMemoryMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largestGraphicMemoryActiveClient = createTestClient(onlyPid, onlyUid);
        ClientInfoParcel clientS{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(smallGraphicMemoryMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientT{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largeGraphicMemoryMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientU{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largestGraphicMemoryActiveClient),
                                 .name = "none"};
        {
            std::vector<MediaResourceParcel> resources;
            resources.push_back(createGraphicMemoryResource(100));
            mService->addResource(clientS, smallGraphicMemoryMarkedClient, resources);
            resources.clear();
            resources.push_back(createGraphicMemoryResource(200));
            mService->addResource(clientT, largeGraphicMemoryMarkedClient, resources);
            resources.clear();
            resources.push_back(createGraphicMemoryResource(300));
            mService->addResource(clientU, largestGraphicMemoryActiveClient, resources);
        }
        mService->markClientForPendingRemoval(clientS);
        mService->markClientForPendingRemoval(clientT);
        // don't mark the largest client

        // DRM session
        const auto smallDrmSessionMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largeDrmSessionMarkedClient = createTestClient(onlyPid, onlyUid);
        const auto largestDrmSessionActiveClient = createTestClient(onlyPid, onlyUid);
        ClientInfoParcel clientV{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(smallDrmSessionMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientW{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largeDrmSessionMarkedClient),
                                 .name = "none"};
        ClientInfoParcel clientX{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(largestDrmSessionActiveClient),
                                 .name = "none"};
        {
            std::vector<MediaResourceParcel> resources;
            resources.push_back(createDrmSessionResource(1));
            mService->addResource(clientV, smallDrmSessionMarkedClient, resources);
            resources.clear();
            resources.push_back(createDrmSessionResource(2));
            mService->addResource(clientW, largeDrmSessionMarkedClient, resources);
            resources.clear();
            resources.push_back(createDrmSessionResource(3));
            mService->addResource(clientX, largestDrmSessionActiveClient, resources);
        }
        mService->markClientForPendingRemoval(clientV);
        mService->markClientForPendingRemoval(clientW);
        // don't mark the largest client

        // battery
        const auto batteryMarkedClient = createTestClient(onlyPid, onlyUid);
        ClientInfoParcel clientY{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(batteryMarkedClient),
                                 .name = "none"};
        {
            std::vector<MediaResourceParcel> resources;
            resources.push_back(createBatteryResource());
            mService->addResource(clientY, batteryMarkedClient, resources);
        }
        mService->markClientForPendingRemoval(clientY);

        // CPU boost
        const auto cpuBoostMarkedClient = createTestClient(onlyPid, onlyUid);
        ClientInfoParcel clientZ{.pid = static_cast<int32_t>(onlyPid),
                                 .uid = static_cast<int32_t>(onlyUid),
                                 .id = getId(cpuBoostMarkedClient),
                                 .name = "none"};
        {
            std::vector<MediaResourceParcel> resources;
            resources.push_back(createCpuBoostResource());
            mService->addResource(clientZ, cpuBoostMarkedClient, resources);
        }
        mService->markClientForPendingRemoval(clientZ);

        // now we expect that we only reclaim resources from the biggest marked client
        EXPECT_TRUE(mService->reclaimResourcesFromClientsPendingRemoval(onlyPid).isOk());
        // secure video codec
        EXPECT_FALSE(toTestClient(smallSecureVideoMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_TRUE(toTestClient(largeSecureVideoMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_FALSE(toTestClient(largestSecureVideoActiveClient)->checkIfReclaimedAndReset());
        // non-secure video codec
        EXPECT_FALSE(toTestClient(smallNonSecureVideoMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_TRUE(toTestClient(largeNonSecureVideoMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_FALSE(toTestClient(largestNonSecureVideoActiveClient)->checkIfReclaimedAndReset());
        // secure audio codec
        EXPECT_FALSE(toTestClient(smallSecureAudioMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_TRUE(toTestClient(largeSecureAudioMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_FALSE(toTestClient(largestSecureAudioActiveClient)->checkIfReclaimedAndReset());
        // non-secure audio codec
        EXPECT_FALSE(toTestClient(smallNonSecureAudioMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_TRUE(toTestClient(largeNonSecureAudioMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_FALSE(toTestClient(largestNonSecureAudioActiveClient)->checkIfReclaimedAndReset());
        // secure image codec
        EXPECT_FALSE(toTestClient(smallSecureImageMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_TRUE(toTestClient(largeSecureImageMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_FALSE(toTestClient(largestSecureImageActiveClient)->checkIfReclaimedAndReset());
        // non-secure image codec
        EXPECT_FALSE(toTestClient(smallNonSecureImageMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_TRUE(toTestClient(largeNonSecureImageMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_FALSE(toTestClient(largestNonSecureImageActiveClient)->checkIfReclaimedAndReset());
        // graphic memory
        EXPECT_FALSE(toTestClient(smallGraphicMemoryMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_TRUE(toTestClient(largeGraphicMemoryMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_FALSE(toTestClient(largestGraphicMemoryActiveClient)->checkIfReclaimedAndReset());
        // DRM session
        EXPECT_FALSE(toTestClient(smallDrmSessionMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_TRUE(toTestClient(largeDrmSessionMarkedClient)->checkIfReclaimedAndReset());
        EXPECT_FALSE(toTestClient(largestDrmSessionActiveClient)->checkIfReclaimedAndReset());
        // battery is not expected to be reclaimed when marked as pending removal
        EXPECT_FALSE(toTestClient(batteryMarkedClient)->checkIfReclaimedAndReset());
        // CPU boost is not expected to be reclaimed when marked as pending removal
        EXPECT_FALSE(toTestClient(cpuBoostMarkedClient)->checkIfReclaimedAndReset());
    }

    inline void initClientConfigParcel(bool encoder, bool hw,
                                       int32_t width, int32_t height,
                                       int64_t id,
                                       const ClientInfoParcel& clientInfo,
                                       ClientConfigParcel& clientConfig) {
        clientConfig.codecType = hw? MediaResource::SubType::kHwVideoCodec :
                                     MediaResource::SubType::kSwVideoCodec;
        clientConfig.isEncoder = encoder;
        clientConfig.width = width;
        clientConfig.height = height;
        clientConfig.timeStamp = systemTime(SYSTEM_TIME_MONOTONIC) / 1000LL;
        clientConfig.id = id;
        clientConfig.clientInfo = clientInfo;
    }

    void testConcurrentCodecs() {
        std::shared_ptr<IResourceManagerClient> testClient4 =
            createTestClient(kTestPid1, kTestUid1);
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
        ClientInfoParcel client4Info{.pid = static_cast<int32_t>(kTestPid1),
                                     .uid = static_cast<int32_t>(kTestUid1),
                                     .id = getId(testClient4),
                                     .name = "none"};
        ClientConfigParcel client1Config;
        ClientConfigParcel client2Config;
        ClientConfigParcel client3Config;
        ClientConfigParcel client4Config;

        // HW Video Encoder @ 1080P.
        initClientConfigParcel(true, true, 1920, 1080, 11111111,
                               client1Info, client1Config);
        // HW Video Decoder @ 4K.
        initClientConfigParcel(true, true, 2160, 3840, 22222222,
                               client2Info, client2Config);
        // SW Video Encoder @ 1080P.
        initClientConfigParcel(true, true, 1920, 1080, 33333333,
                               client3Info, client3Config);
        // SW Video Decoder @ 4K.
        initClientConfigParcel(true, true, 2160, 3840, 44444444,
                               client4Info, client4Config);

        // Start client1 at 1080P.
        mService->notifyClientStarted(client1Config);
        long peakPixelCountP1 = mService->getPeakConcurrentPixelCount(kTestPid1);
        long currentPixelCountP1 = mService->getCurrentConcurrentPixelCount(kTestPid1);
        EXPECT_TRUE(peakPixelCountP1 = client1Config.width * client1Config.height);
        EXPECT_TRUE(currentPixelCountP1 = client1Config.width * client1Config.height);

        // Stop client1.
        mService->notifyClientStopped(client1Config);
        peakPixelCountP1 = mService->getPeakConcurrentPixelCount(kTestPid1);
        currentPixelCountP1 = mService->getCurrentConcurrentPixelCount(kTestPid1);
        EXPECT_TRUE(peakPixelCountP1 == client1Config.width * client1Config.height);
        EXPECT_TRUE(currentPixelCountP1 == 0);

        // Start client1 at 1080P.
        mService->notifyClientStarted(client1Config);
        // Start client2 at 4K.
        mService->notifyClientStarted(client2Config);

        // Verify the Peak and Current Concurrent pixel count for both the process
        // (kTestPid1, kTestPid2)
        peakPixelCountP1 = mService->getPeakConcurrentPixelCount(kTestPid1);
        currentPixelCountP1 = mService->getCurrentConcurrentPixelCount(kTestPid1);
        long peakPixelCountP2 = mService->getPeakConcurrentPixelCount(kTestPid2);
        long currentPixelCountP2 = mService->getCurrentConcurrentPixelCount(kTestPid2);
        EXPECT_TRUE(peakPixelCountP1 == client1Config.width * client1Config.height);
        EXPECT_TRUE(currentPixelCountP1 == client1Config.width * client1Config.height);
        EXPECT_TRUE(peakPixelCountP2 == client2Config.width * client2Config.height);
        EXPECT_TRUE(currentPixelCountP2 == client2Config.width * client2Config.height);

        // Start client3 at 1080P.
        mService->notifyClientStarted(client3Config);
        // Start client4 at 4K.
        mService->notifyClientStarted(client4Config);

        // Verify the Peak and Current Concurrent pixel count for both the process
        // (kTestPid1, kTestPid2)
        peakPixelCountP1 = mService->getPeakConcurrentPixelCount(kTestPid1);
        currentPixelCountP1 = mService->getCurrentConcurrentPixelCount(kTestPid1);
        peakPixelCountP2 = mService->getPeakConcurrentPixelCount(kTestPid2);
        currentPixelCountP2 = mService->getCurrentConcurrentPixelCount(kTestPid2);
        EXPECT_TRUE(peakPixelCountP1 ==
            (client1Config.width * client1Config.height +
             client4Config.width * client4Config.height));
        EXPECT_TRUE(currentPixelCountP1 ==
            (client1Config.width * client1Config.height +
             client4Config.width * client4Config.height));
        EXPECT_TRUE(peakPixelCountP2 ==
            (client2Config.width * client2Config.height +
             client3Config.width * client3Config.height));
        EXPECT_TRUE(currentPixelCountP2 ==
            (client2Config.width * client2Config.height +
             client3Config.width * client3Config.height));

        // Stop client4
        mService->notifyClientStopped(client4Config);
        currentPixelCountP1 = mService->getCurrentConcurrentPixelCount(kTestPid1);
        EXPECT_TRUE(currentPixelCountP1 == client1Config.width * client1Config.height);

        // Stop client1
        mService->notifyClientStopped(client1Config);

        // Stop client2
        mService->notifyClientStopped(client2Config);
        currentPixelCountP2 = mService->getCurrentConcurrentPixelCount(kTestPid2);
        EXPECT_TRUE(currentPixelCountP2 == client3Config.width * client3Config.height);
        // Stop client3
        mService->notifyClientStopped(client3Config);

        // Verify the Peak and Current Concurrent pixel count for both the process
        // (kTestPid1, kTestPid2)
        peakPixelCountP1 = mService->getPeakConcurrentPixelCount(kTestPid1);
        currentPixelCountP1 = mService->getCurrentConcurrentPixelCount(kTestPid1);
        peakPixelCountP2 = mService->getPeakConcurrentPixelCount(kTestPid2);
        currentPixelCountP2 = mService->getCurrentConcurrentPixelCount(kTestPid2);
        EXPECT_TRUE(peakPixelCountP1 ==
            (client1Config.width * client1Config.height +
             client4Config.width * client4Config.height));
        EXPECT_TRUE(currentPixelCountP1 == 0);
        EXPECT_TRUE(peakPixelCountP2 ==
            (client2Config.width * client2Config.height +
             client3Config.width * client3Config.height));
        EXPECT_TRUE(currentPixelCountP2 == 0);
    }

    void addNonSecureVideoCodecResource(std::shared_ptr<IResourceManagerClient>& client,
                                        std::vector<ClientInfoParcel>& infos) {
        std::vector<MediaResourceParcel> resources;
        resources.push_back(createNonSecureVideoCodecResource(1));

        TestClient* testClient = toTestClient(client);
        ClientInfoParcel clientInfo {.pid = static_cast<int32_t>(testClient->pid()),
                                     .uid = static_cast<int32_t>(testClient->uid()),
                                     .id = getId(client),
                                     .name = "none",
                                     .importance = testClient->clientImportance()};
        mService->addResource(clientInfo, client, resources);
        infos.push_back(clientInfo);
    }

    bool doReclaimResource(const ClientInfoParcel& clientInfo) {
        bool result = false;
        std::vector<MediaResourceParcel> reclaimResources;
        reclaimResources.push_back(createNonSecureVideoCodecResource(1));
        bool success = mService->reclaimResource(clientInfo, reclaimResources, &result).isOk();
        return success && result;
    }

    // Verifies the resource reclaim policies
    // - this verifies the reclaim policies based on:
    //   - process priority (oom score)
    //   - client priority
    void testReclaimPolicies() {
        // Create 3 clients with codec importance high, mid and low for a low
        // priority pid.
        std::vector<std::shared_ptr<IResourceManagerClient>> lowPriPidClients;
        lowPriPidClients.push_back(
            createTestClient(kLowPriorityPid, kTestUid1, kHighestCodecImportance));
        lowPriPidClients.push_back(
            createTestClient(kLowPriorityPid, kTestUid1, kMidCodecImportance));
        lowPriPidClients.push_back(
            createTestClient(kLowPriorityPid, kTestUid1, kLowestCodecImportance));

        // Create 3 clients with codec importance high, mid and low for a high
        // priority pid.
        std::vector<std::shared_ptr<IResourceManagerClient>> highPriPidClients;
        highPriPidClients.push_back(
            createTestClient(kHighPriorityPid, kTestUid2, kHighestCodecImportance));
        highPriPidClients.push_back(
            createTestClient(kHighPriorityPid, kTestUid2, kMidCodecImportance));
        highPriPidClients.push_back(
            createTestClient(kHighPriorityPid, kTestUid2, kLowestCodecImportance));

        // Add non secure video codec resources for all the 3 clients of low priority pid.
        std::vector<ClientInfoParcel> lowPriPidClientInfos;
        for (auto& client : lowPriPidClients) {
            addNonSecureVideoCodecResource(client, lowPriPidClientInfos);
        }
        // Add non secure video codec resources for all the 3 clients of high priority pid.
        std::vector<ClientInfoParcel> highPriPidClientInfos;
        for (auto& client : highPriPidClients) {
            addNonSecureVideoCodecResource(client, highPriPidClientInfos);
        }

        // 1. Set reclaim policy as "Process Priority".
        // - A process should be reclaiming from:
        //    - a lower priority process if there is any
        //    - else fail.
        mService->setReclaimPolicy(true /*process priority*/, false /*codec importance*/);

        // 1.A:
        // - high priority process should be able to reclaim successfully.
        // - A process should be reclaiming from the low priority process.
        EXPECT_TRUE(doReclaimResource(highPriPidClientInfos[0]));
        // Verify that the high priority pid's clients are untouched.
        bool success = true;
        for (auto& client : highPriPidClients) {
            if (toTestClient(client)->checkIfReclaimedAndReset()) {
                success = false;
                break;
            }
        }
        EXPECT_TRUE(success);
        // Verify that the one of the client from the low priority pid has been reclaimed.
        success = false;
        for (auto& client : lowPriPidClients) {
            if (toTestClient(client)->checkIfReclaimedAndReset()) {
                success = true;
                break;
            }
        }
        EXPECT_TRUE(success);

        // 1.B:
        // - low priority process should fail to reclaim.
        EXPECT_FALSE(doReclaimResource(lowPriPidClientInfos[0]));

        // 2. Set reclaim policy as "Client Importance".
        // - A process should be reclaiming from:
        //    - a lower priority client from the same process if any
        //    - else fail.
        mService->setReclaimPolicy(false /*process priority*/, true /*codec importance*/);

        // 2.A:
        // - high priority process should be able to reclaim successfully.
        // - Process should be reclaiming from a lower priority client from the
        // same process.
        EXPECT_TRUE(doReclaimResource(highPriPidClientInfos[0]));
        // Verify that the low priority pid's clients are untouched.
        success = true;
        for (auto& client : lowPriPidClients) {
            if (toTestClient(client)->checkIfReclaimedAndReset()) {
                success = false;
                break;
            }
        }
        EXPECT_TRUE(success);
        // Verify that the one of the low priority client from the high priority
        // pid has been reclaimed.
        success = false;
        for (auto& client : highPriPidClients) {
            if (toTestClient(client)->checkIfReclaimedAndReset()) {
                success = true;
                break;
            }
        }
        EXPECT_TRUE(success);

        // 2.B:
        // - high priority process should be able to reclaim successfully.
        // - Process should be reclaiming from a lower priority client from the
        // same process.
        EXPECT_TRUE(doReclaimResource(lowPriPidClientInfos[0]));
        // Verify that the high priority pid's clients are untouched.
        success = true;
        for (auto& client : highPriPidClients) {
            if (toTestClient(client)->checkIfReclaimedAndReset()) {
                success = false;
                break;
            }
        }
        EXPECT_TRUE(success);
        // Verify that the one of the low priority client from the low priority
        // pid has been reclaimed.
        success = false;
        for (auto& client : lowPriPidClients) {
            if (toTestClient(client)->checkIfReclaimedAndReset()) {
                success = true;
                break;
            }
        }
        EXPECT_TRUE(success);

        // 2.C:
        // - lowest priority client from high priority process should fail to reclaim.
        EXPECT_FALSE(doReclaimResource(highPriPidClientInfos[2]));

        // 2.D:
        // - lowest priority client from low priority process should fail to reclaim.
        EXPECT_FALSE(doReclaimResource(lowPriPidClientInfos[2]));

        // 3. Set reclaim policy as "Process Priority and Client Importance".
        // - A process should be reclaiming from:
        //    - a lower priority process if there is any
        //    - else a lower priority client from the same process if any
        //    - else fail.
        mService->setReclaimPolicy(true /*process priority*/, true /*codec importance*/);

        // Remove all clients from the low priority process so that we have
        // only one process (with high priority) with all the resources.
        for (const auto& clientInfo : lowPriPidClientInfos) {
            mService->removeClient(clientInfo);
        }
        lowPriPidClientInfos.clear();
        lowPriPidClients.clear();
        // 3.A:
        // - high priority process should be able to reclaim successfully.
        EXPECT_TRUE(doReclaimResource(highPriPidClientInfos[0]));
        // Verify that the one of the client from the high priority pid has been reclaimed.
        success = false;
        for (auto& client : highPriPidClients) {
            if (toTestClient(client)->checkIfReclaimedAndReset()) {
                success = true;
                break;
            }
        }
        EXPECT_TRUE(success);

        // 3.B, set the policy back to ReclaimPolicyProcessPriority
        mService->setReclaimPolicy(true /*process priority*/, false /*codec importance*/);

        // Since there is only one process, the reclaim should fail.
        EXPECT_FALSE(doReclaimResource(highPriPidClientInfos[0]));

        // 4. Set reclaim policy as "Process Priority and Client Importance".
        // - A process should be reclaiming from:
        //    - from a lower priority process if there are any
        //    - else from a lower priority client from the same process if there are any
        //    - else fail.
        mService->setReclaimPolicy(true /*process priority*/, true /*codec importance*/);

        // Remove all clients from the high priority process so that we can
        // start a new/fresh resource allocation.
        for (const auto& clientInfo : highPriPidClientInfos) {
            mService->removeClient(clientInfo);
        }
        highPriPidClientInfos.clear();
        highPriPidClients.clear();

        // Create 3 clients with codec importance high for a low priority pid.
        lowPriPidClients.push_back(
            createTestClient(kLowPriorityPid, kTestUid1, kHighestCodecImportance));
        lowPriPidClients.push_back(
            createTestClient(kLowPriorityPid, kTestUid1, kHighestCodecImportance));
        lowPriPidClients.push_back(
            createTestClient(kLowPriorityPid, kTestUid1, kHighestCodecImportance));

        // Create 3 clients with codec importance low for a high priority pid.
        highPriPidClients.push_back(
            createTestClient(kHighPriorityPid, kTestUid2, kLowestCodecImportance));
        highPriPidClients.push_back(
            createTestClient(kHighPriorityPid, kTestUid2, kLowestCodecImportance));
        highPriPidClients.push_back(
            createTestClient(kHighPriorityPid, kTestUid2, kLowestCodecImportance));

        // Add non secure video codec resources for all the 3 clients of low priority pid.
        for (auto& client : lowPriPidClients) {
            addNonSecureVideoCodecResource(client, lowPriPidClientInfos);
        }
        // Add non secure video codec resources for all the 3 clients of high priority pid.
        for (auto& client : highPriPidClients) {
            addNonSecureVideoCodecResource(client, highPriPidClientInfos);
        }

        // 4.A:
        // - high priority process should be able to reclaim successfully.
        EXPECT_TRUE(doReclaimResource(highPriPidClientInfos[0]));
        // Since all clients are of same priority with in high priority process,
        // none of the clients should be reclaimed.
        success = true;
        for (auto& client : highPriPidClients) {
            if (toTestClient(client)->checkIfReclaimedAndReset()) {
                success = false;
                break;
            }
        }
        EXPECT_TRUE(success);
        // Verify that the one of the client from the low priority pid has been reclaimed.
        success = false;
        for (auto& client : lowPriPidClients) {
            if (toTestClient(client)->checkIfReclaimedAndReset()) {
                success = true;
                break;
            }
        }
        EXPECT_TRUE(success);

        // 4.B, set the policy back to ReclaimPolicyProcessPriority
        // If low priority process tries to reclaim, it should fail as there
        // aren't any lower priority clients or lower priority processes.
        EXPECT_FALSE(doReclaimResource(lowPriPidClientInfos[0]));
    }
};

class ResourceManagerServiceNewTest : public ResourceManagerServiceTest {
public:
    ResourceManagerServiceNewTest(bool newRM = true) : ResourceManagerServiceTest(newRM) {}
};

TEST_F(ResourceManagerServiceTest, config) {
    testConfig();
}

TEST_F(ResourceManagerServiceTest, addResource) {
    addResource();
}

TEST_F(ResourceManagerServiceTest, combineResource) {
    testCombineResource();
}

TEST_F(ResourceManagerServiceTest, combineResourceNegative) {
    testCombineResourceWithNegativeValues();
}

TEST_F(ResourceManagerServiceTest, removeResource) {
    testRemoveResource();
}

TEST_F(ResourceManagerServiceTest, removeClient) {
    testRemoveClient();
}

TEST_F(ResourceManagerServiceTest, reclaimResource) {
    testReclaimResourceSecure();
    testReclaimResourceNonSecure();
}

TEST_F(ResourceManagerServiceTest, getAllClients_l) {
    testGetAllClients();
}

TEST_F(ResourceManagerServiceTest, getLowestPriorityBiggestClient_l) {
    testGetLowestPriorityBiggestClient();
}

TEST_F(ResourceManagerServiceTest, getLowestPriorityPid_l) {
    testGetLowestPriorityPid();
}

TEST_F(ResourceManagerServiceTest, isCallingPriorityHigher_l) {
    testIsCallingPriorityHigher();
}

TEST_F(ResourceManagerServiceTest, batteryStats) {
    testBatteryStats();
}

TEST_F(ResourceManagerServiceTest, cpusetBoost) {
    testCpusetBoost();
}

TEST_F(ResourceManagerServiceTest, overridePid) {
    testOverridePid();
}

TEST_F(ResourceManagerServiceTest, markClientForPendingRemoval) {
    testMarkClientForPendingRemoval();
}

TEST_F(ResourceManagerServiceTest, reclaimResources_withVideoCodec_reclaimsOnlyVideoCodec) {
    testReclaimResources_withVideoCodec_reclaimsOnlyVideoCodec();
}

TEST_F(ResourceManagerServiceTest, reclaimResources_withAudioCodec_reclaimsOnlyAudioCodec) {
    testReclaimResources_withAudioCodec_reclaimsOnlyAudioCodec();
}

TEST_F(ResourceManagerServiceTest, reclaimResources_withImageCodec_reclaimsOnlyImageCodec) {
    testReclaimResources_withImageCodec_reclaimsOnlyImageCodec();
}

TEST_F(ResourceManagerServiceTest, reclaimResources_whenPartialResourceMatch_reclaims) {
    testReclaimResources_whenPartialResourceMatch_reclaims();
}

TEST_F(ResourceManagerServiceTest,
        reclaimResourcesFromMarkedClients_removesBiggestMarkedClientForSomeResources) {
    testReclaimResourcesFromMarkedClients_removesBiggestMarkedClientForSomeResources();
}

TEST_F(ResourceManagerServiceTest, concurrentCodecs) {
    testConcurrentCodecs();
}

/////// test cases for ResourceManagerServiceNew ////
TEST_F(ResourceManagerServiceNewTest, config) {
    testConfig();
}

TEST_F(ResourceManagerServiceNewTest, addResource) {
    addResource();
}

TEST_F(ResourceManagerServiceNewTest, combineResource) {
    testCombineResource();
}

TEST_F(ResourceManagerServiceNewTest, combineResourceNegative) {
    testCombineResourceWithNegativeValues();
}

TEST_F(ResourceManagerServiceNewTest, removeResource) {
    testRemoveResource();
}

TEST_F(ResourceManagerServiceNewTest, removeClient) {
    testRemoveClient();
}

TEST_F(ResourceManagerServiceNewTest, reclaimResource) {
    testReclaimResourceSecure();
    testReclaimResourceNonSecure();
}

TEST_F(ResourceManagerServiceNewTest, getAllClients_l) {
    testGetAllClients();
}

TEST_F(ResourceManagerServiceNewTest, getLowestPriorityBiggestClient_l) {
    testGetLowestPriorityBiggestClient();
}

TEST_F(ResourceManagerServiceNewTest, getLowestPriorityPid_l) {
    testGetLowestPriorityPid();
}

TEST_F(ResourceManagerServiceNewTest, isCallingPriorityHigher_l) {
    testIsCallingPriorityHigher();
}

TEST_F(ResourceManagerServiceNewTest, batteryStats) {
    testBatteryStats();
}

TEST_F(ResourceManagerServiceNewTest, cpusetBoost) {
    testCpusetBoost();
}

TEST_F(ResourceManagerServiceNewTest, overridePid) {
    testOverridePid();
}

TEST_F(ResourceManagerServiceNewTest, markClientForPendingRemoval) {
    testMarkClientForPendingRemoval();
}

TEST_F(ResourceManagerServiceNewTest, reclaimResources_withVideoCodec_reclaimsOnlyVideoCodec) {
    testReclaimResources_withVideoCodec_reclaimsOnlyVideoCodec();
}

TEST_F(ResourceManagerServiceNewTest, reclaimResources_withAudioCodec_reclaimsOnlyAudioCodec) {
    testReclaimResources_withAudioCodec_reclaimsOnlyAudioCodec();
}

TEST_F(ResourceManagerServiceNewTest, reclaimResources_withImageCodec_reclaimsOnlyImageCodec) {
    testReclaimResources_withImageCodec_reclaimsOnlyImageCodec();
}

TEST_F(ResourceManagerServiceNewTest, reclaimResources_whenPartialResourceMatch_reclaims) {
    testReclaimResources_whenPartialResourceMatch_reclaims();
}

TEST_F(ResourceManagerServiceNewTest,
        reclaimResourcesFromMarkedClients_removesBiggestMarkedClientForSomeResources) {
    testReclaimResourcesFromMarkedClients_removesBiggestMarkedClientForSomeResources();
}

TEST_F(ResourceManagerServiceNewTest, concurrentCodecs) {
    testConcurrentCodecs();
}

TEST_F(ResourceManagerServiceNewTest, reclaimPolicies) {
    testReclaimPolicies();
}

} // namespace android
