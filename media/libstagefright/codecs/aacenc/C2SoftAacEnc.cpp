/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_NDEBUG 0
#define LOG_TAG "C2SoftAacEnc"
#include <utils/Log.h>

#include <inttypes.h>

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>
#include <media/stagefright/foundation/hexdump.h>

#include "C2SoftAacEnc.h"

namespace android {

C2SoftAacEnc::C2SoftAacEnc(
        const char *name,
        c2_node_id_t id)
    : SimpleC2Component(
            SimpleC2Interface::Builder(name, id)
            .inputFormat(C2FormatAudio)
            .outputFormat(C2FormatCompressed)
            .build()),
      mAACEncoder(NULL),
      mNumChannels(1),
      mSampleRate(44100),
      mBitRate(64000),
      mSBRMode(-1),
      mSBRRatio(0),
      mAACProfile(AOT_AAC_LC),
      mNumBytesPerInputFrame(0u),
      mOutBufferSize(0u),
      mSentCodecSpecificData(false),
      mInputSize(0),
      mInputTimeUs(-1ll),
      mSignalledError(false) {
}

C2SoftAacEnc::~C2SoftAacEnc() {
    onReset();
}

c2_status_t C2SoftAacEnc::onInit() {
    status_t err = initEncoder();
    return err == OK ? C2_OK : C2_CORRUPTED;
}

status_t C2SoftAacEnc::initEncoder() {
    if (AACENC_OK != aacEncOpen(&mAACEncoder, 0, 0)) {
        ALOGE("Failed to init AAC encoder");
        return UNKNOWN_ERROR;
    }
    return setAudioParams();
}

c2_status_t C2SoftAacEnc::onStop() {
    mSentCodecSpecificData = false;
    mInputSize = 0u;
    mInputTimeUs = -1ll;
    mSignalledError = false;
    return C2_OK;
}

void C2SoftAacEnc::onReset() {
    (void)onStop();
    aacEncClose(&mAACEncoder);
}

void C2SoftAacEnc::onRelease() {
    // no-op
}

c2_status_t C2SoftAacEnc::onFlush_sm() {
    mSentCodecSpecificData = false;
    mInputSize = 0u;
    return C2_OK;
}

static CHANNEL_MODE getChannelMode(uint32_t nChannels) {
    CHANNEL_MODE chMode = MODE_INVALID;
    switch (nChannels) {
        case 1: chMode = MODE_1; break;
        case 2: chMode = MODE_2; break;
        case 3: chMode = MODE_1_2; break;
        case 4: chMode = MODE_1_2_1; break;
        case 5: chMode = MODE_1_2_2; break;
        case 6: chMode = MODE_1_2_2_1; break;
        default: chMode = MODE_INVALID;
    }
    return chMode;
}

//static AUDIO_OBJECT_TYPE getAOTFromProfile(OMX_U32 profile) {
//    if (profile == OMX_AUDIO_AACObjectLC) {
//        return AOT_AAC_LC;
//    } else if (profile == OMX_AUDIO_AACObjectHE) {
//        return AOT_SBR;
//    } else if (profile == OMX_AUDIO_AACObjectHE_PS) {
//        return AOT_PS;
//    } else if (profile == OMX_AUDIO_AACObjectLD) {
//        return AOT_ER_AAC_LD;
//    } else if (profile == OMX_AUDIO_AACObjectELD) {
//        return AOT_ER_AAC_ELD;
//    } else {
//        ALOGW("Unsupported AAC profile - defaulting to AAC-LC");
//        return AOT_AAC_LC;
//    }
//}

status_t C2SoftAacEnc::setAudioParams() {
    // We call this whenever sample rate, number of channels, bitrate or SBR mode change
    // in reponse to setParameter calls.

    ALOGV("setAudioParams: %u Hz, %u channels, %u bps, %i sbr mode, %i sbr ratio",
         mSampleRate, mNumChannels, mBitRate, mSBRMode, mSBRRatio);

    if (AACENC_OK != aacEncoder_SetParam(mAACEncoder, AACENC_AOT, mAACProfile)) {
        ALOGE("Failed to set AAC encoder parameters");
        return UNKNOWN_ERROR;
    }

    if (AACENC_OK != aacEncoder_SetParam(mAACEncoder, AACENC_SAMPLERATE, mSampleRate)) {
        ALOGE("Failed to set AAC encoder parameters");
        return UNKNOWN_ERROR;
    }
    if (AACENC_OK != aacEncoder_SetParam(mAACEncoder, AACENC_BITRATE, mBitRate)) {
        ALOGE("Failed to set AAC encoder parameters");
        return UNKNOWN_ERROR;
    }
    if (AACENC_OK != aacEncoder_SetParam(mAACEncoder, AACENC_CHANNELMODE,
            getChannelMode(mNumChannels))) {
        ALOGE("Failed to set AAC encoder parameters");
        return UNKNOWN_ERROR;
    }
    if (AACENC_OK != aacEncoder_SetParam(mAACEncoder, AACENC_TRANSMUX, TT_MP4_RAW)) {
        ALOGE("Failed to set AAC encoder parameters");
        return UNKNOWN_ERROR;
    }

    if (mSBRMode != -1 && mAACProfile == AOT_ER_AAC_ELD) {
        if (AACENC_OK != aacEncoder_SetParam(mAACEncoder, AACENC_SBR_MODE, mSBRMode)) {
            ALOGE("Failed to set AAC encoder parameters");
            return UNKNOWN_ERROR;
        }
    }

    /* SBR ratio parameter configurations:
       0: Default configuration wherein SBR ratio is configured depending on audio object type by
          the FDK.
       1: Downsampled SBR (default for ELD)
       2: Dualrate SBR (default for HE-AAC)
     */
    if (AACENC_OK != aacEncoder_SetParam(mAACEncoder, AACENC_SBR_RATIO, mSBRRatio)) {
        ALOGE("Failed to set AAC encoder parameters");
        return UNKNOWN_ERROR;
    }

    return OK;
}

void C2SoftAacEnc::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {
    work->worklets_processed = 0u;

    if (mSignalledError) {
        return;
    }
    bool eos = (work->input.flags & C2BufferPack::FLAG_END_OF_STREAM) != 0;

    if (!mSentCodecSpecificData) {
        // The very first thing we want to output is the codec specific
        // data.

        if (AACENC_OK != aacEncEncode(mAACEncoder, NULL, NULL, NULL, NULL)) {
            ALOGE("Unable to initialize encoder for profile / sample-rate / bit-rate / channels");
            // TODO: notify(OMX_EventError, OMX_ErrorUndefined, 0, NULL);
            mSignalledError = true;
            return;
        }

        uint32_t actualBitRate = aacEncoder_GetParam(mAACEncoder, AACENC_BITRATE);
        if (mBitRate != actualBitRate) {
            ALOGW("Requested bitrate %u unsupported, using %u", mBitRate, actualBitRate);
        }

        AACENC_InfoStruct encInfo;
        if (AACENC_OK != aacEncInfo(mAACEncoder, &encInfo)) {
            ALOGE("Failed to get AAC encoder info");
            // TODO: notify(OMX_EventError, OMX_ErrorUndefined, 0, NULL);
            mSignalledError = true;
            return;
        }

        std::unique_ptr<C2StreamCsdInfo::output> csd =
            C2StreamCsdInfo::output::alloc_unique(encInfo.confSize, 0u);
        // TODO: check NO_MEMORY
        memcpy(csd->m.value, encInfo.confBuf, encInfo.confSize);
        ALOGV("put csd");
#if defined(LOG_NDEBUG) && !LOG_NDEBUG
        hexdump(csd->m.value, csd->flexCount());
#endif
        work->worklets.front()->output.infos.push_back(std::move(csd));

        mOutBufferSize = encInfo.maxOutBufBytes;
        mNumBytesPerInputFrame = encInfo.frameLength * mNumChannels * sizeof(int16_t);
        mInputTimeUs = work->input.ordinal.timestamp;

        mSentCodecSpecificData = true;
    }

    C2ReadView view = work->input.buffers[0]->data().linearBlocks().front().map().get();
    uint64_t timestamp = mInputTimeUs;

    size_t numFrames = (view.capacity() + mInputSize + (eos ? mNumBytesPerInputFrame - 1 : 0))
            / mNumBytesPerInputFrame;
    ALOGV("capacity = %u; mInputSize = %zu; numFrames = %zu", view.capacity(), mInputSize, numFrames);

    std::shared_ptr<C2LinearBlock> block;
    std::unique_ptr<C2WriteView> wView;
    uint8_t *outPtr = nullptr;
    size_t outAvailable = 0u;

    if (numFrames) {
        C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
        // TODO: error handling, proper usage, etc.
        c2_status_t err = pool->fetchLinearBlock(mOutBufferSize * numFrames, usage, &block);
        if (err != C2_OK) {
            ALOGE("err = %d", err);
        }

        wView.reset(new C2WriteView(block->map().get()));
        outPtr = wView->data();
        outAvailable = wView->size();
    }

    AACENC_InArgs inargs;
    AACENC_OutArgs outargs;
    memset(&inargs, 0, sizeof(inargs));
    memset(&outargs, 0, sizeof(outargs));
    inargs.numInSamples = view.capacity() / sizeof(int16_t);

    void* inBuffer[]        = { (unsigned char *)view.data() };
    INT   inBufferIds[]     = { IN_AUDIO_DATA };
    INT   inBufferSize[]    = { (INT)view.capacity() };
    INT   inBufferElSize[]  = { sizeof(int16_t) };

    AACENC_BufDesc inBufDesc;
    inBufDesc.numBufs           = sizeof(inBuffer) / sizeof(void*);
    inBufDesc.bufs              = (void**)&inBuffer;
    inBufDesc.bufferIdentifiers = inBufferIds;
    inBufDesc.bufSizes          = inBufferSize;
    inBufDesc.bufElSizes        = inBufferElSize;

    void* outBuffer[]       = { outPtr };
    INT   outBufferIds[]    = { OUT_BITSTREAM_DATA };
    INT   outBufferSize[]   = { 0 };
    INT   outBufferElSize[] = { sizeof(UCHAR) };

    AACENC_BufDesc outBufDesc;
    outBufDesc.numBufs           = sizeof(outBuffer) / sizeof(void*);
    outBufDesc.bufs              = (void**)&outBuffer;
    outBufDesc.bufferIdentifiers = outBufferIds;
    outBufDesc.bufSizes          = outBufferSize;
    outBufDesc.bufElSizes        = outBufferElSize;

    // Encode the mInputFrame, which is treated as a modulo buffer
    AACENC_ERROR encoderErr = AACENC_OK;
    size_t nOutputBytes = 0;

    while (encoderErr == AACENC_OK && inargs.numInSamples > 0) {
        memset(&outargs, 0, sizeof(outargs));

        outBuffer[0] = outPtr;
        outBufferSize[0] = outAvailable - nOutputBytes;

        encoderErr = aacEncEncode(mAACEncoder,
                                  &inBufDesc,
                                  &outBufDesc,
                                  &inargs,
                                  &outargs);

        if (encoderErr == AACENC_OK) {
            if (outargs.numOutBytes > 0) {
                mInputSize = 0;
                int consumed = ((view.capacity() / sizeof(int16_t)) - inargs.numInSamples);
                mInputTimeUs = work->input.ordinal.timestamp
                        + (consumed * 1000000ll / mNumChannels / mSampleRate);
            } else {
                mInputSize += outargs.numInSamples * sizeof(int16_t);
                mInputTimeUs += outargs.numInSamples * 1000000ll / mNumChannels / mSampleRate;
            }
            outPtr += outargs.numOutBytes;
            nOutputBytes += outargs.numOutBytes;

            if (outargs.numInSamples > 0) {
                inBuffer[0] = (int16_t *)inBuffer[0] + outargs.numInSamples;
                inBufferSize[0] -= outargs.numInSamples * sizeof(int16_t);
                inargs.numInSamples -= outargs.numInSamples;
            }
        }
        ALOGV("nOutputBytes = %zu; inargs.numInSamples = %d", nOutputBytes, inargs.numInSamples);
    }

    if (eos && inBufferSize[0] > 0) {
        memset(&outargs, 0, sizeof(outargs));

        outBuffer[0] = outPtr;
        outBufferSize[0] = outAvailable - nOutputBytes;

        // Flush
        inargs.numInSamples = -1;

        (void)aacEncEncode(mAACEncoder,
                           &inBufDesc,
                           &outBufDesc,
                           &inargs,
                           &outargs);

        nOutputBytes += outargs.numOutBytes;
    }

    work->worklets.front()->output.flags =
        (C2BufferPack::flags_t)(eos ? C2BufferPack::FLAG_END_OF_STREAM : 0);
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->worklets.front()->output.ordinal.timestamp = timestamp;
    work->worklets_processed = 1u;
    if (nOutputBytes) {
        work->worklets.front()->output.buffers.push_back(
                createLinearBuffer(block, 0, nOutputBytes));
    } else {
        work->worklets.front()->output.buffers.emplace_back(nullptr);
    }

#if 0
    ALOGI("sending %d bytes of data (time = %lld us, flags = 0x%08lx)",
          nOutputBytes, mInputTimeUs, outHeader->nFlags);

    hexdump(outHeader->pBuffer + outHeader->nOffset, outHeader->nFilledLen);
#endif
}

c2_status_t C2SoftAacEnc::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    switch (drainMode) {
        case DRAIN_COMPONENT_NO_EOS:  // fall-through
        case NO_DRAIN:
            // no-op
            return C2_OK;
        case DRAIN_CHAIN:
            return C2_OMITTED;
        case DRAIN_COMPONENT_WITH_EOS:
            break;
        default:
            return C2_BAD_VALUE;
    }

    (void)pool;
    mSentCodecSpecificData = false;
    mInputSize = 0u;

    // TODO: we don't have any pending work at this time to drain.
    return C2_OK;
}

class C2SoftAacEncFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id, std::shared_ptr<C2Component>* const component,
            std::function<void(::android::C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftAacEnc("aacenc", id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id, std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(::android::C2ComponentInterface*)> deleter) override {
        *interface =
                SimpleC2Interface::Builder("aacenc", id, deleter)
                .inputFormat(C2FormatAudio)
                .outputFormat(C2FormatCompressed)
                .build();
        return C2_OK;
    }

    virtual ~C2SoftAacEncFactory() override = default;
};

}  // namespace android

extern "C" ::android::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftAacEncFactory();
}

extern "C" void DestroyCodec2Factory(::android::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
