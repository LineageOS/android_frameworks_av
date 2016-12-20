#include "WOmx.h"
#include "WOmxNode.h"
#include "WOmxObserver.h"
#include "Conversion.h"

namespace android {
namespace hardware {
namespace media {
namespace omx {
namespace V1_0 {
namespace implementation {

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
        sp<::android::IGraphicBufferProducer>* /* bufferProducer */,
        sp<::android::IGraphicBufferSource>* /* bufferSource */) {
    // TODO: Implement.
    return INVALID_OPERATION;
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

// TODO: Add createInputSurface().

}  // namespace implementation
}  // namespace V1_0
}  // namespace omx
}  // namespace media
}  // namespace hardware
}  // namespace android
