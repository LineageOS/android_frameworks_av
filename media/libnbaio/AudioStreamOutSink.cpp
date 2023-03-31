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

#define LOG_TAG "AudioStreamOutSink"
//#define LOG_NDEBUG 0

#include <utils/Log.h>
#include <audio_utils/clock.h>
#include <media/audiohal/StreamHalInterface.h>
#include <media/nbaio/AudioStreamOutSink.h>

namespace android {

AudioStreamOutSink::AudioStreamOutSink(sp<StreamOutHalInterface> stream) :
        NBAIO_Sink(),
        mStream(stream),
        mStreamBufferSizeBytes(0)
{
    ALOG_ASSERT(stream != 0);
}

AudioStreamOutSink::~AudioStreamOutSink()
{
    mStream.clear();
}

ssize_t AudioStreamOutSink::negotiate(const NBAIO_Format offers[], size_t numOffers,
                                      NBAIO_Format counterOffers[], size_t& numCounterOffers)
{
    if (!Format_isValid(mFormat)) {
        status_t result;
        result = mStream->getBufferSize(&mStreamBufferSizeBytes);
        if (result != OK) return result;
        audio_config_base_t config = AUDIO_CONFIG_BASE_INITIALIZER;
        result = mStream->getAudioProperties(&config);
        if (result != OK) return result;
        mFormat = Format_from_SR_C(config.sample_rate,
                audio_channel_count_from_out_mask(config.channel_mask), config.format);
        mFrameSize = Format_frameSize(mFormat);

        // update format for MEL computation
        auto processor = mMelProcessor.load();
        if (processor) {
            processor->updateAudioFormat(config.sample_rate,
                                         audio_channel_count_from_out_mask(config.channel_mask),
                                         config.format);
        }
    }
    return NBAIO_Sink::negotiate(offers, numOffers, counterOffers, numCounterOffers);
}

ssize_t AudioStreamOutSink::write(const void *buffer, size_t count)
{
    if (!mNegotiated) {
        return NEGOTIATE;
    }
    ALOG_ASSERT(Format_isValid(mFormat));
    size_t written;
    status_t ret = mStream->write(buffer, count * mFrameSize, &written);
    if (ret == OK && written > 0) {
        // Send to MelProcessor for sound dose measurement.
        auto processor = mMelProcessor.load();
        if (processor) {
            processor->process(buffer, written);
        }

        written /= mFrameSize;
        mFramesWritten += written;

        return written;
    } else {
        // FIXME verify HAL implementations are returning the correct error codes e.g. WOULD_BLOCK
        ALOGE_IF(ret != OK, "Error while writing data to HAL: %d", ret);
        return ret;
    }
}

status_t AudioStreamOutSink::getTimestamp(ExtendedTimestamp &timestamp)
{
    uint64_t position64;
    struct timespec time;
    if (mStream->getPresentationPosition(&position64, &time) != OK) {
        return INVALID_OPERATION;
    }
    timestamp.mPosition[ExtendedTimestamp::LOCATION_KERNEL] = position64;
    timestamp.mTimeNs[ExtendedTimestamp::LOCATION_KERNEL] = audio_utils_ns_from_timespec(&time);
    return OK;
}

void AudioStreamOutSink::startMelComputation(const sp<audio_utils::MelProcessor>& processor)
{
    ALOGV("%s start mel computation for device %d", __func__, processor->getDeviceId());

    mMelProcessor.store(processor);
    if (processor) {
        // update format for MEL computation
        processor->updateAudioFormat(mFormat.mSampleRate,
                                     mFormat.mChannelCount,
                                     mFormat.mFormat);
        processor->resume();
    }

}

void AudioStreamOutSink::stopMelComputation()
{
    auto melProcessor = mMelProcessor.load();
    if (melProcessor != nullptr) {
        ALOGV("%s pause mel computation for device %d", __func__, melProcessor->getDeviceId());
        melProcessor->pause();
    }
}

}   // namespace android
