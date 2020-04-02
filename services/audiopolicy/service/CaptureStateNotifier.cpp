#include "CaptureStateNotifier.h"

#define LOG_TAG "CaptureStateNotifier"

#include <android/media/ICaptureStateListener.h>
#include <binder/IBinder.h>
#include <utils/Log.h>

namespace android {

using media::ICaptureStateListener;

class CaptureStateNotifier::DeathRecipient : public IBinder::DeathRecipient {
public:
    DeathRecipient(CaptureStateNotifier* notifier) : mNotifier(notifier) {}

    void binderDied(const wp<IBinder>&) override {
        mNotifier->binderDied();
    }

private:
    CaptureStateNotifier* const mNotifier;
};

CaptureStateNotifier::CaptureStateNotifier(bool initialActive) {
    mActive = initialActive;
}

CaptureStateNotifier::~CaptureStateNotifier() {
    LOG_ALWAYS_FATAL_IF(mListener != nullptr);
}

bool CaptureStateNotifier::RegisterListener(const sp<ICaptureStateListener>& listener) {
    std::lock_guard<std::mutex> _l(mMutex);
    LOG_ALWAYS_FATAL_IF(mListener != nullptr);

    ALOGI("Registering a listener");
    mListener = listener;
    sp<IBinder> binder = IInterface::asBinder(mListener);
    binder->linkToDeath(new DeathRecipient(this));
    return mActive;
}

void CaptureStateNotifier::setCaptureState(bool active) {
    std::lock_guard<std::mutex> _l(mMutex);
    mActive = active;
    if (mListener) {
        mListener->setCaptureState(active);
    }
}

void CaptureStateNotifier::binderDied() {
    std::lock_guard<std::mutex> _l(mMutex);
    mListener.clear();
    ALOGI("Listener binder died");
}

}  // namespace android