/*
 * Copyright (C) 2017 The Android Open Source Project
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
#define LOG_TAG "C2SoftAac"
#include <utils/Log.h>

#include "C2SoftAac.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <cutils/properties.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <media/stagefright/foundation/hexdump.h>
#include <media/stagefright/MediaErrors.h>
#include <utils/misc.h>

#include <inttypes.h>
#include <math.h>
#include <numeric>

#define FILEREAD_MAX_LAYERS 2

#define DRC_DEFAULT_MOBILE_REF_LEVEL 64  /* 64*-0.25dB = -16 dB below full scale for mobile conf */
#define DRC_DEFAULT_MOBILE_DRC_CUT   127 /* maximum compression of dynamic range for mobile conf */
#define DRC_DEFAULT_MOBILE_DRC_BOOST 127 /* maximum compression of dynamic range for mobile conf */
#define DRC_DEFAULT_MOBILE_DRC_HEAVY 1   /* switch for heavy compression for mobile conf */
#define DRC_DEFAULT_MOBILE_ENC_LEVEL (-1) /* encoder target level; -1 => the value is unknown, otherwise dB step value (e.g. 64 for -16 dB) */
#define MAX_CHANNEL_COUNT            8  /* maximum number of audio channels that can be decoded */
// names of properties that can be used to override the default DRC settings
#define PROP_DRC_OVERRIDE_REF_LEVEL  "aac_drc_reference_level"
#define PROP_DRC_OVERRIDE_CUT        "aac_drc_cut"
#define PROP_DRC_OVERRIDE_BOOST      "aac_drc_boost"
#define PROP_DRC_OVERRIDE_HEAVY      "aac_drc_heavy"
#define PROP_DRC_OVERRIDE_ENC_LEVEL "aac_drc_enc_target_level"

namespace android {

constexpr char kComponentName[] = "c2.google.aac.decoder";

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatAudio)
            .inputMediaType(MEDIA_MIMETYPE_AUDIO_AAC)
            .outputMediaType(MEDIA_MIMETYPE_AUDIO_RAW)
            .build();
}

C2SoftAac::C2SoftAac(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mAACDecoder(NULL),
      mStreamInfo(NULL),
      mIsADTS(false),
      mSignalledError(false),
      mOutputDelayRingBuffer(NULL) {
}

C2SoftAac::~C2SoftAac() {
    onRelease();
}

c2_status_t C2SoftAac::onInit() {
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_CORRUPTED;
}

c2_status_t C2SoftAac::onStop() {
    drainDecoder();
    // reset the "configured" state
    mOutputDelayCompensated = 0;
    mOutputDelayRingBufferWritePos = 0;
    mOutputDelayRingBufferReadPos = 0;
    mOutputDelayRingBufferFilled = 0;
    mBuffersInfo.clear();

    // To make the codec behave the same before and after a reset, we need to invalidate the
    // streaminfo struct. This does that:
    mStreamInfo->sampleRate = 0; // TODO: mStreamInfo is read only

    mSignalledError = false;

    return C2_OK;
}

void C2SoftAac::onReset() {
    (void)onStop();
}

void C2SoftAac::onRelease() {
    if (mAACDecoder) {
        aacDecoder_Close(mAACDecoder);
        mAACDecoder = NULL;
    }
    if (mOutputDelayRingBuffer) {
        delete[] mOutputDelayRingBuffer;
        mOutputDelayRingBuffer = NULL;
    }
}

status_t C2SoftAac::initDecoder() {
    ALOGV("initDecoder()");
    status_t status = UNKNOWN_ERROR;
    mAACDecoder = aacDecoder_Open(TT_MP4_ADIF, /* num layers */ 1);
    if (mAACDecoder != NULL) {
        mStreamInfo = aacDecoder_GetStreamInfo(mAACDecoder);
        if (mStreamInfo != NULL) {
            status = OK;
        }
    }

    mOutputDelayCompensated = 0;
    mOutputDelayRingBufferSize = 2048 * MAX_CHANNEL_COUNT * kNumDelayBlocksMax;
    mOutputDelayRingBuffer = new short[mOutputDelayRingBufferSize];
    mOutputDelayRingBufferWritePos = 0;
    mOutputDelayRingBufferReadPos = 0;
    mOutputDelayRingBufferFilled = 0;

    if (mAACDecoder == NULL) {
        ALOGE("AAC decoder is null. TODO: Can not call aacDecoder_SetParam in the following code");
    }

    //aacDecoder_SetParam(mAACDecoder, AAC_PCM_LIMITER_ENABLE, 0);

    //init DRC wrapper
    mDrcWrap.setDecoderHandle(mAACDecoder);
    mDrcWrap.submitStreamData(mStreamInfo);

    // for streams that contain metadata, use the mobile profile DRC settings unless overridden by platform properties
    // TODO: change the DRC settings depending on audio output device type (HDMI, loadspeaker, headphone)
    char value[PROPERTY_VALUE_MAX];
    //  DRC_PRES_MODE_WRAP_DESIRED_TARGET
    if (property_get(PROP_DRC_OVERRIDE_REF_LEVEL, value, NULL)) {
        unsigned refLevel = atoi(value);
        ALOGV("AAC decoder using desired DRC target reference level of %d instead of %d", refLevel,
                DRC_DEFAULT_MOBILE_REF_LEVEL);
        mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_TARGET, refLevel);
    } else {
        mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_TARGET, DRC_DEFAULT_MOBILE_REF_LEVEL);
    }
    //  DRC_PRES_MODE_WRAP_DESIRED_ATT_FACTOR
    if (property_get(PROP_DRC_OVERRIDE_CUT, value, NULL)) {
        unsigned cut = atoi(value);
        ALOGV("AAC decoder using desired DRC attenuation factor of %d instead of %d", cut,
                DRC_DEFAULT_MOBILE_DRC_CUT);
        mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_ATT_FACTOR, cut);
    } else {
        mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_ATT_FACTOR, DRC_DEFAULT_MOBILE_DRC_CUT);
    }
    //  DRC_PRES_MODE_WRAP_DESIRED_BOOST_FACTOR
    if (property_get(PROP_DRC_OVERRIDE_BOOST, value, NULL)) {
        unsigned boost = atoi(value);
        ALOGV("AAC decoder using desired DRC boost factor of %d instead of %d", boost,
                DRC_DEFAULT_MOBILE_DRC_BOOST);
        mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_BOOST_FACTOR, boost);
    } else {
        mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_BOOST_FACTOR, DRC_DEFAULT_MOBILE_DRC_BOOST);
    }
    //  DRC_PRES_MODE_WRAP_DESIRED_HEAVY
    if (property_get(PROP_DRC_OVERRIDE_HEAVY, value, NULL)) {
        unsigned heavy = atoi(value);
        ALOGV("AAC decoder using desried DRC heavy compression switch of %d instead of %d", heavy,
                DRC_DEFAULT_MOBILE_DRC_HEAVY);
        mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_HEAVY, heavy);
    } else {
        mDrcWrap.setParam(DRC_PRES_MODE_WRAP_DESIRED_HEAVY, DRC_DEFAULT_MOBILE_DRC_HEAVY);
    }
    // DRC_PRES_MODE_WRAP_ENCODER_TARGET
    if (property_get(PROP_DRC_OVERRIDE_ENC_LEVEL, value, NULL)) {
        unsigned encoderRefLevel = atoi(value);
        ALOGV("AAC decoder using encoder-side DRC reference level of %d instead of %d",
                encoderRefLevel, DRC_DEFAULT_MOBILE_ENC_LEVEL);
        mDrcWrap.setParam(DRC_PRES_MODE_WRAP_ENCODER_TARGET, encoderRefLevel);
    } else {
        mDrcWrap.setParam(DRC_PRES_MODE_WRAP_ENCODER_TARGET, DRC_DEFAULT_MOBILE_ENC_LEVEL);
    }

    // By default, the decoder creates a 5.1 channel downmix signal.
    // For seven and eight channel input streams, enable 6.1 and 7.1 channel output
    aacDecoder_SetParam(mAACDecoder, AAC_PCM_MAX_OUTPUT_CHANNELS, -1);

    return status;
}

bool C2SoftAac::outputDelayRingBufferPutSamples(INT_PCM *samples, int32_t numSamples) {
    if (numSamples == 0) {
        return true;
    }
    if (outputDelayRingBufferSpaceLeft() < numSamples) {
        ALOGE("RING BUFFER WOULD OVERFLOW");
        return false;
    }
    if (mOutputDelayRingBufferWritePos + numSamples <= mOutputDelayRingBufferSize
            && (mOutputDelayRingBufferReadPos <= mOutputDelayRingBufferWritePos
                    || mOutputDelayRingBufferReadPos > mOutputDelayRingBufferWritePos + numSamples)) {
        // faster memcopy loop without checks, if the preconditions allow this
        for (int32_t i = 0; i < numSamples; i++) {
            mOutputDelayRingBuffer[mOutputDelayRingBufferWritePos++] = samples[i];
        }

        if (mOutputDelayRingBufferWritePos >= mOutputDelayRingBufferSize) {
            mOutputDelayRingBufferWritePos -= mOutputDelayRingBufferSize;
        }
    } else {
        ALOGV("slow C2SoftAac::outputDelayRingBufferPutSamples()");

        for (int32_t i = 0; i < numSamples; i++) {
            mOutputDelayRingBuffer[mOutputDelayRingBufferWritePos] = samples[i];
            mOutputDelayRingBufferWritePos++;
            if (mOutputDelayRingBufferWritePos >= mOutputDelayRingBufferSize) {
                mOutputDelayRingBufferWritePos -= mOutputDelayRingBufferSize;
            }
        }
    }
    mOutputDelayRingBufferFilled += numSamples;
    return true;
}

int32_t C2SoftAac::outputDelayRingBufferGetSamples(INT_PCM *samples, int32_t numSamples) {

    if (numSamples > mOutputDelayRingBufferFilled) {
        ALOGE("RING BUFFER WOULD UNDERRUN");
        return -1;
    }

    if (mOutputDelayRingBufferReadPos + numSamples <= mOutputDelayRingBufferSize
            && (mOutputDelayRingBufferWritePos < mOutputDelayRingBufferReadPos
                    || mOutputDelayRingBufferWritePos >= mOutputDelayRingBufferReadPos + numSamples)) {
        // faster memcopy loop without checks, if the preconditions allow this
        if (samples != 0) {
            for (int32_t i = 0; i < numSamples; i++) {
                samples[i] = mOutputDelayRingBuffer[mOutputDelayRingBufferReadPos++];
            }
        } else {
            mOutputDelayRingBufferReadPos += numSamples;
        }
        if (mOutputDelayRingBufferReadPos >= mOutputDelayRingBufferSize) {
            mOutputDelayRingBufferReadPos -= mOutputDelayRingBufferSize;
        }
    } else {
        ALOGV("slow C2SoftAac::outputDelayRingBufferGetSamples()");

        for (int32_t i = 0; i < numSamples; i++) {
            if (samples != 0) {
                samples[i] = mOutputDelayRingBuffer[mOutputDelayRingBufferReadPos];
            }
            mOutputDelayRingBufferReadPos++;
            if (mOutputDelayRingBufferReadPos >= mOutputDelayRingBufferSize) {
                mOutputDelayRingBufferReadPos -= mOutputDelayRingBufferSize;
            }
        }
    }
    mOutputDelayRingBufferFilled -= numSamples;
    return numSamples;
}

int32_t C2SoftAac::outputDelayRingBufferSamplesAvailable() {
    return mOutputDelayRingBufferFilled;
}

int32_t C2SoftAac::outputDelayRingBufferSpaceLeft() {
    return mOutputDelayRingBufferSize - outputDelayRingBufferSamplesAvailable();
}

void C2SoftAac::drainRingBuffer(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool,
        bool eos) {
    while (!mBuffersInfo.empty() && outputDelayRingBufferSamplesAvailable()
            >= mStreamInfo->frameSize * mStreamInfo->numChannels) {
        Info &outInfo = mBuffersInfo.front();
        ALOGV("outInfo.frameIndex = %" PRIu64, outInfo.frameIndex);
        int samplesize = mStreamInfo->numChannels * sizeof(int16_t);

        int available = outputDelayRingBufferSamplesAvailable();
        int numFrames = outInfo.decodedSizes.size();
        int numSamples = numFrames * (mStreamInfo->frameSize * mStreamInfo->numChannels);
        if (available < numSamples) {
            if (eos) {
                numSamples = available;
            } else {
                break;
            }
        }
        ALOGV("%d samples available (%d), or %d frames",
                numSamples, available, numFrames);
        ALOGV("getting %d from ringbuffer", numSamples);

        std::shared_ptr<C2LinearBlock> block;
        std::function<void(const std::unique_ptr<C2Work>&)> fillWork =
            [&block, numSamples, pool, this]()
                    -> std::function<void(const std::unique_ptr<C2Work>&)> {
                auto fillEmptyWork = [](const std::unique_ptr<C2Work> &work, c2_status_t err) {
                    work->result = err;
                    work->worklets.front()->output.flags = work->input.flags;
                    work->worklets.front()->output.buffers.clear();
                    work->worklets.front()->output.ordinal = work->input.ordinal;
                    work->workletsProcessed = 1u;
                };

                using namespace std::placeholders;
                if (numSamples == 0) {
                    return std::bind(fillEmptyWork, _1, C2_OK);
                }

                // TODO: error handling, proper usage, etc.
                C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
                c2_status_t err = pool->fetchLinearBlock(
                        numSamples * sizeof(int16_t), usage, &block);
                if (err != C2_OK) {
                    ALOGD("failed to fetch a linear block (%d)", err);
                    mSignalledError = true;
                    return std::bind(fillEmptyWork, _1, C2_NO_MEMORY);
                }
                C2WriteView wView = block->map().get();
                // TODO
                INT_PCM *outBuffer = reinterpret_cast<INT_PCM *>(wView.data());
                int32_t ns = outputDelayRingBufferGetSamples(outBuffer, numSamples);
                if (ns != numSamples) {
                    ALOGE("not a complete frame of samples available");
                    mSignalledError = true;
                    return std::bind(fillEmptyWork, _1, C2_CORRUPTED);
                }
                return [buffer = createLinearBuffer(block)](const std::unique_ptr<C2Work> &work) {
                    work->result = C2_OK;
                    work->worklets.front()->output.flags = work->input.flags;
                    work->worklets.front()->output.buffers.clear();
                    work->worklets.front()->output.buffers.push_back(buffer);
                    work->worklets.front()->output.ordinal = work->input.ordinal;
                    work->workletsProcessed = 1u;
                };
            }();

        if (work && work->input.ordinal.frameIndex == c2_cntr64_t(outInfo.frameIndex)) {
            fillWork(work);
        } else {
            finish(outInfo.frameIndex, fillWork);
        }

        ALOGV("out timestamp %" PRIu64 " / %u", outInfo.timestamp, block ? block->capacity() : 0);
        mBuffersInfo.pop_front();
    }
}

void C2SoftAac::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {
    work->workletsProcessed = 0u;
    work->result = C2_OK;
    if (mSignalledError) {
        return;
    }

    UCHAR* inBuffer[FILEREAD_MAX_LAYERS];
    UINT inBufferLength[FILEREAD_MAX_LAYERS] = {0};
    UINT bytesValid[FILEREAD_MAX_LAYERS] = {0};

    INT_PCM tmpOutBuffer[2048 * MAX_CHANNEL_COUNT];
    C2ReadView view = work->input.buffers[0]->data().linearBlocks().front().map().get();
    size_t offset = 0u;
    size_t size = view.capacity();

    bool eos = (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0;
    bool codecConfig = (work->input.flags & C2FrameData::FLAG_CODEC_CONFIG) != 0;

    //TODO
#if 0
    if (mInputBufferCount == 0 && !codecConfig) {
        ALOGW("first buffer should have FLAG_CODEC_CONFIG set");
        codecConfig = true;
    }
#endif
    if (codecConfig) {
        // const_cast because of libAACdec method signature.
        inBuffer[0] = const_cast<UCHAR *>(view.data() + offset);
        inBufferLength[0] = size;

        AAC_DECODER_ERROR decoderErr =
            aacDecoder_ConfigRaw(mAACDecoder,
                                 inBuffer,
                                 inBufferLength);

        if (decoderErr != AAC_DEC_OK) {
            ALOGE("aacDecoder_ConfigRaw decoderErr = 0x%4.4x", decoderErr);
            mSignalledError = true;
            // TODO: error
            return;
        }

        work->worklets.front()->output.ordinal = work->input.ordinal;
        work->worklets.front()->output.buffers.clear();

        return;
    }

    Info inInfo;
    inInfo.frameIndex = work->input.ordinal.frameIndex.peeku();
    inInfo.timestamp = work->input.ordinal.timestamp.peeku();
    inInfo.bufferSize = size;
    inInfo.decodedSizes.clear();
    while (size > 0u) {
        ALOGV("size = %zu", size);
        if (mIsADTS) {
            size_t adtsHeaderSize = 0;
            // skip 30 bits, aac_frame_length follows.
            // ssssssss ssssiiip ppffffPc ccohCCll llllllll lll?????

            const uint8_t *adtsHeader = view.data() + offset;

            bool signalError = false;
            if (size < 7) {
                ALOGE("Audio data too short to contain even the ADTS header. "
                        "Got %zu bytes.", size);
                hexdump(adtsHeader, size);
                signalError = true;
            } else {
                bool protectionAbsent = (adtsHeader[1] & 1);

                unsigned aac_frame_length =
                    ((adtsHeader[3] & 3) << 11)
                    | (adtsHeader[4] << 3)
                    | (adtsHeader[5] >> 5);

                if (size < aac_frame_length) {
                    ALOGE("Not enough audio data for the complete frame. "
                            "Got %zu bytes, frame size according to the ADTS "
                            "header is %u bytes.",
                            size, aac_frame_length);
                    hexdump(adtsHeader, size);
                    signalError = true;
                } else {
                    adtsHeaderSize = (protectionAbsent ? 7 : 9);
                    if (aac_frame_length < adtsHeaderSize) {
                        signalError = true;
                    } else {
                        // const_cast because of libAACdec method signature.
                        inBuffer[0] = const_cast<UCHAR *>(adtsHeader + adtsHeaderSize);
                        inBufferLength[0] = aac_frame_length - adtsHeaderSize;

                        offset += adtsHeaderSize;
                        size -= adtsHeaderSize;
                    }
                }
            }

            if (signalError) {
                mSignalledError = true;
                // TODO: notify(OMX_EventError, OMX_ErrorStreamCorrupt, ERROR_MALFORMED, NULL);
                return;
            }
        } else {
            // const_cast because of libAACdec method signature.
            inBuffer[0] = const_cast<UCHAR *>(view.data() + offset);
            inBufferLength[0] = size;
        }

        // Fill and decode
        bytesValid[0] = inBufferLength[0];

        INT prevSampleRate = mStreamInfo->sampleRate;
        INT prevNumChannels = mStreamInfo->numChannels;

        aacDecoder_Fill(mAACDecoder,
                        inBuffer,
                        inBufferLength,
                        bytesValid);

        // run DRC check
        mDrcWrap.submitStreamData(mStreamInfo);
        mDrcWrap.update();

        UINT inBufferUsedLength = inBufferLength[0] - bytesValid[0];
        size -= inBufferUsedLength;
        offset += inBufferUsedLength;

        AAC_DECODER_ERROR decoderErr;
        do {
            if (outputDelayRingBufferSpaceLeft() <
                    (mStreamInfo->frameSize * mStreamInfo->numChannels)) {
                ALOGV("skipping decode: not enough space left in ringbuffer");
                break;
            }

            int numConsumed = mStreamInfo->numTotalBytes;
            decoderErr = aacDecoder_DecodeFrame(mAACDecoder,
                                       tmpOutBuffer,
                                       2048 * MAX_CHANNEL_COUNT,
                                       0 /* flags */);

            numConsumed = mStreamInfo->numTotalBytes - numConsumed;

            if (decoderErr == AAC_DEC_NOT_ENOUGH_BITS) {
                break;
            }
            inInfo.decodedSizes.push_back(numConsumed);

            if (decoderErr != AAC_DEC_OK) {
                ALOGW("aacDecoder_DecodeFrame decoderErr = 0x%4.4x", decoderErr);
            }

            if (bytesValid[0] != 0) {
                ALOGE("bytesValid[0] != 0 should never happen");
                mSignalledError = true;
                // TODO: notify(OMX_EventError, OMX_ErrorUndefined, 0, NULL);
                return;
            }

            size_t numOutBytes =
                mStreamInfo->frameSize * sizeof(int16_t) * mStreamInfo->numChannels;

            if (decoderErr == AAC_DEC_OK) {
                if (!outputDelayRingBufferPutSamples(tmpOutBuffer,
                        mStreamInfo->frameSize * mStreamInfo->numChannels)) {
                    mSignalledError = true;
                    // TODO: notify(OMX_EventError, OMX_ErrorUndefined, decoderErr, NULL);
                    return;
                }
            } else {
                ALOGW("AAC decoder returned error 0x%4.4x, substituting silence", decoderErr);

                memset(tmpOutBuffer, 0, numOutBytes); // TODO: check for overflow

                if (!outputDelayRingBufferPutSamples(tmpOutBuffer,
                        mStreamInfo->frameSize * mStreamInfo->numChannels)) {
                    mSignalledError = true;
                    // TODO: notify(OMX_EventError, OMX_ErrorUndefined, decoderErr, NULL);
                    return;
                }

                // Discard input buffer.
                size = 0;

                aacDecoder_SetParam(mAACDecoder, AAC_TPDEC_CLEAR_BUFFER, 1);

                // After an error, replace bufferSize with the sum of the
                // decodedSizes to resynchronize the in/out lists.
                inInfo.decodedSizes.pop_back();
                inInfo.bufferSize = std::accumulate(
                        inInfo.decodedSizes.begin(), inInfo.decodedSizes.end(), 0);

                // fall through
            }

            /*
             * AAC+/eAAC+ streams can be signalled in two ways: either explicitly
             * or implicitly, according to MPEG4 spec. AAC+/eAAC+ is a dual
             * rate system and the sampling rate in the final output is actually
             * doubled compared with the core AAC decoder sampling rate.
             *
             * Explicit signalling is done by explicitly defining SBR audio object
             * type in the bitstream. Implicit signalling is done by embedding
             * SBR content in AAC extension payload specific to SBR, and hence
             * requires an AAC decoder to perform pre-checks on actual audio frames.
             *
             * Thus, we could not say for sure whether a stream is
             * AAC+/eAAC+ until the first data frame is decoded.
             */
            if (!mStreamInfo->sampleRate || !mStreamInfo->numChannels) {
                // TODO:
#if 0
                if ((mInputBufferCount > 2) && (mOutputBufferCount <= 1)) {
                    ALOGW("Invalid AAC stream");
                    mSignalledError = true;
                    // TODO: notify(OMX_EventError, OMX_ErrorUndefined, decoderErr, NULL);
                    return false;
                }
#endif
            }
            ALOGV("size = %zu", size);
        } while (decoderErr == AAC_DEC_OK);
    }

    int32_t outputDelay = mStreamInfo->outputDelay * mStreamInfo->numChannels;

    mBuffersInfo.push_back(std::move(inInfo));

    if (!eos && mOutputDelayCompensated < outputDelay) {
        // discard outputDelay at the beginning
        int32_t toCompensate = outputDelay - mOutputDelayCompensated;
        int32_t discard = outputDelayRingBufferSamplesAvailable();
        if (discard > toCompensate) {
            discard = toCompensate;
        }
        int32_t discarded = outputDelayRingBufferGetSamples(0, discard);
        mOutputDelayCompensated += discarded;
        return;
    }

    if (eos) {
        drainInternal(DRAIN_COMPONENT_WITH_EOS, pool, work);
    } else {
        drainRingBuffer(work, pool, false /* not EOS */);
    }
}

c2_status_t C2SoftAac::drainInternal(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool,
        const std::unique_ptr<C2Work> &work) {
    if (drainMode == NO_DRAIN) {
        ALOGW("drain with NO_DRAIN: no-op");
        return C2_OK;
    }
    if (drainMode == DRAIN_CHAIN) {
        ALOGW("DRAIN_CHAIN not supported");
        return C2_OMITTED;
    }

    bool eos = (drainMode == DRAIN_COMPONENT_WITH_EOS);

    drainDecoder();
    drainRingBuffer(work, pool, eos);

    if (eos) {
        auto fillEmptyWork = [](const std::unique_ptr<C2Work> &work) {
            work->worklets.front()->output.flags = work->input.flags;
            work->worklets.front()->output.buffers.clear();
            work->worklets.front()->output.ordinal = work->input.ordinal;
            work->workletsProcessed = 1u;
        };
        while (mBuffersInfo.size() > 1u) {
            finish(mBuffersInfo.front().frameIndex, fillEmptyWork);
            mBuffersInfo.pop_front();
        }
        if (work->workletsProcessed == 0u) {
            fillEmptyWork(work);
        }
        mBuffersInfo.clear();
    }

    return C2_OK;
}

c2_status_t C2SoftAac::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    return drainInternal(drainMode, pool, nullptr);
}

c2_status_t C2SoftAac::onFlush_sm() {
    drainDecoder();
    mBuffersInfo.clear();

    int avail;
    while ((avail = outputDelayRingBufferSamplesAvailable()) > 0) {
        if (avail > mStreamInfo->frameSize * mStreamInfo->numChannels) {
            avail = mStreamInfo->frameSize * mStreamInfo->numChannels;
        }
        int32_t ns = outputDelayRingBufferGetSamples(0, avail);
        if (ns != avail) {
            ALOGW("not a complete frame of samples available");
            break;
        }
    }
    mOutputDelayRingBufferReadPos = mOutputDelayRingBufferWritePos;

    return C2_OK;
}

void C2SoftAac::drainDecoder() {
    // flush decoder until outputDelay is compensated
    while (mOutputDelayCompensated > 0) {
        // a buffer big enough for MAX_CHANNEL_COUNT channels of decoded HE-AAC
        INT_PCM tmpOutBuffer[2048 * MAX_CHANNEL_COUNT];

        // run DRC check
        mDrcWrap.submitStreamData(mStreamInfo);
        mDrcWrap.update();

        AAC_DECODER_ERROR decoderErr =
            aacDecoder_DecodeFrame(mAACDecoder,
                                   tmpOutBuffer,
                                   2048 * MAX_CHANNEL_COUNT,
                                   AACDEC_FLUSH);
        if (decoderErr != AAC_DEC_OK) {
            ALOGW("aacDecoder_DecodeFrame decoderErr = 0x%4.4x", decoderErr);
        }

        int32_t tmpOutBufferSamples = mStreamInfo->frameSize * mStreamInfo->numChannels;
        if (tmpOutBufferSamples > mOutputDelayCompensated) {
            tmpOutBufferSamples = mOutputDelayCompensated;
        }
        outputDelayRingBufferPutSamples(tmpOutBuffer, tmpOutBufferSamples);

        mOutputDelayCompensated -= tmpOutBufferSamples;
    }
}

class C2SoftAacDecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftAac(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftAacDecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftAacDecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
