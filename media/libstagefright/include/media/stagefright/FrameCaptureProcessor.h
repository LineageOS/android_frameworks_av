/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef FRAME_CAPTURE_PROCESSOR_H_
#define FRAME_CAPTURE_PROCESSOR_H_

#include <media/stagefright/foundation/ABase.h>
#include <media/stagefright/foundation/AHandler.h>

namespace android {

struct AMessage;
class GraphicBuffer;
class Rect;

namespace renderengine {
class RenderEngine;
struct LayerSettings;
}

/*
 * Process a decoded graphic buffer through RenderEngine to
 * convert it to sRGB.
 *
 * This class is a singleton that holds one instance of RenderEngine
 * and its event queue (on which the GL context runs). The RenderEngine
 * is created upon the first getInstance().
 */
class FrameCaptureProcessor : public AHandler {

public:

    struct Layer : public RefBase {
        virtual void getLayerSettings(
                const Rect &sourceCrop, uint32_t textureName,
                renderengine::LayerSettings *layerSettings) = 0;
    };

    static sp<FrameCaptureProcessor> getInstance();

    status_t capture(
            const sp<Layer> &layer,
            const Rect &sourceCrop, const sp<GraphicBuffer> &outBuffer);

protected:
    virtual ~FrameCaptureProcessor();
    void onMessageReceived(const sp<AMessage> &msg);

private:
    FrameCaptureProcessor();

    enum {
        kWhatCreate,
        kWhatCapture,
    };

    static Mutex sLock;
    static sp<FrameCaptureProcessor> sInstance GUARDED_BY(sLock);

    constexpr static float sDefaultMaxLumiance = 500.0f;

    status_t mInitStatus;
    sp<ALooper> mLooper;
    std::unique_ptr<renderengine::RenderEngine> mRE;
    uint32_t mTextureName;

    static status_t PostAndAwaitResponse(
            const sp<AMessage> &msg, sp<AMessage> *response);
    static void PostReplyWithError(
            const sp<AReplyToken> &replyID, status_t err);

    status_t initCheck() { return mInitStatus; }
    void createRenderEngine();

    // message handlers
    status_t onCreate();
    status_t onCapture(const sp<Layer> &layer,
            const Rect &sourceCrop, const sp<GraphicBuffer> &outBuffer);

    DISALLOW_EVIL_CONSTRUCTORS(FrameCaptureProcessor);
};

}  // namespace android

#endif  // FRAME_CAPTURE_PROCESSOR_H_
