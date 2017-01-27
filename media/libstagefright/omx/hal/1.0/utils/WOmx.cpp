/*
 * Copyright 2016, The Android Open Source Project
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

#include "WOmx.h"
#include "WOmxNode.h"
#include "WOmxObserver.h"
#include "WOmxBufferProducer.h"
#include "WGraphicBufferSource.h"
#include "Conversion.h"

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace utils {

// LWOmx
LWOmx::LWOmx(sp<IOmx> const& base) : mBase(base) {
}

status_t LWOmx::listNodes(List<IOMX::ComponentInfo>* list) {
    status_t fnStatus;
    status_t transStatus = toStatusT(mBase->listNodes(
            [&fnStatus, list](
                    Status status,
                    hidl_vec<IOmx::ComponentInfo> const& nodeList) {
                fnStatus = toStatusT(status);
                list->clear();
                for (size_t i = 0; i < nodeList.size(); ++i) {
                    auto newInfo = list->insert(
                            list->end(), IOMX::ComponentInfo());
                    convertTo(&*newInfo, nodeList[i]);
                }
            }));
    return transStatus == NO_ERROR ? fnStatus : transStatus;
}

status_t LWOmx::allocateNode(
        char const* name,
        sp<IOMXObserver> const& observer,
        sp<IOMXNode>* omxNode) {
    status_t fnStatus;
    status_t transStatus = toStatusT(mBase->allocateNode(
            name, new TWOmxObserver(observer),
            [&fnStatus, omxNode](Status status, sp<IOmxNode> const& node) {
                fnStatus = toStatusT(status);
                *omxNode = new LWOmxNode(node);
            }));
    return transStatus == NO_ERROR ? fnStatus : transStatus;
}

status_t LWOmx::createInputSurface(
        sp<::android::IGraphicBufferProducer>* bufferProducer,
        sp<::android::IGraphicBufferSource>* bufferSource) {
    status_t fnStatus;
    status_t transStatus = toStatusT(mBase->createInputSurface(
            [&fnStatus, bufferProducer, bufferSource] (
                    Status status,
                    sp<IOmxBufferProducer> const& tProducer,
                    sp<IGraphicBufferSource> const& tSource) {
                fnStatus = toStatusT(status);
                *bufferProducer = new LWOmxBufferProducer(tProducer);
                *bufferSource = new LWGraphicBufferSource(tSource);
            }));
    return transStatus == NO_ERROR ? fnStatus : transStatus;
}

::android::IBinder* LWOmx::onAsBinder() {
    return nullptr;
}

// TWOmx
TWOmx::TWOmx(sp<IOMX> const& base) : mBase(base) {
}

Return<void> TWOmx::listNodes(listNodes_cb _hidl_cb) {
    List<IOMX::ComponentInfo> lList;
    Status status = toStatus(mBase->listNodes(&lList));

    hidl_vec<IOmx::ComponentInfo> tList;
    tList.resize(lList.size());
    size_t i = 0;
    for (auto const& lInfo : lList) {
        convertTo(&(tList[i++]), lInfo);
    }
    _hidl_cb(status, tList);
    return Void();
}

Return<void> TWOmx::allocateNode(
        const hidl_string& name,
        const sp<IOmxObserver>& observer,
        allocateNode_cb _hidl_cb) {
    sp<IOMXNode> omxNode;
    Status status = toStatus(mBase->allocateNode(
            name, new LWOmxObserver(observer), &omxNode));
    _hidl_cb(status, new TWOmxNode(omxNode));
    return Void();
}

Return<void> TWOmx::createInputSurface(createInputSurface_cb _hidl_cb) {
    sp<::android::IGraphicBufferProducer> lProducer;
    sp<::android::IGraphicBufferSource> lSource;
    status_t status = mBase->createInputSurface(&lProducer, &lSource);
    _hidl_cb(toStatus(status),
             new TWOmxBufferProducer(lProducer),
             new TWGraphicBufferSource(lSource));
    return Void();
}

}  // namespace utils
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
