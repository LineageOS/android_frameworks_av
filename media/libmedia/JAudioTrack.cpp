/*
 * Copyright 2018 The Android Open Source Project
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

#define LOG_TAG "JAudioTrack"

#include "media/JAudioAttributes.h"
#include "media/JAudioFormat.h"
#include "media/JAudioTrack.h"

#include <android_runtime/AndroidRuntime.h>
#include <media/AudioResamplerPublic.h>

namespace android {

// TODO: Add NULL && Exception checks after every JNI call.
JAudioTrack::JAudioTrack(                             // < Usages of the arguments are below >
        audio_stream_type_t streamType,               // AudioAudioAttributes
        uint32_t sampleRate,                          // AudioFormat && bufferSizeInBytes
        audio_format_t format,                        // AudioFormat && bufferSizeInBytes
        audio_channel_mask_t channelMask,             // AudioFormat && bufferSizeInBytes
        size_t frameCount,                            // bufferSizeInBytes
        audio_session_t sessionId,                    // AudioTrack
        const audio_attributes_t* pAttributes,        // AudioAttributes
        float maxRequiredSpeed) {                     // bufferSizeInBytes

    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jclass jAudioTrackCls = env->FindClass("android/media/AudioTrack");

    maxRequiredSpeed = std::min(std::max(maxRequiredSpeed, 1.0f), AUDIO_TIMESTRETCH_SPEED_MAX);

    int bufferSizeInBytes = 0;
    if (sampleRate == 0 || frameCount > 0) {
        // Manually calculate buffer size.
        bufferSizeInBytes = audio_channel_count_from_out_mask(channelMask)
                * audio_bytes_per_sample(format) * (frameCount > 0 ? frameCount : 1);
    } else if (sampleRate > 0) {
        // Call Java AudioTrack::getMinBufferSize().
        jmethodID jGetMinBufferSize =
                env->GetStaticMethodID(jAudioTrackCls, "getMinBufferSize", "(III)I");
        bufferSizeInBytes = env->CallStaticIntMethod(jAudioTrackCls, jGetMinBufferSize,
                sampleRate, outChannelMaskFromNative(channelMask), audioFormatFromNative(format));
    }
    bufferSizeInBytes = (int) (bufferSizeInBytes * maxRequiredSpeed);

    // Create a Java AudioTrack object through its Builder.
    jclass jBuilderCls = env->FindClass("android/media/AudioTrack$Builder");
    jmethodID jBuilderCtor = env->GetMethodID(jBuilderCls, "<init>", "()V");
    jobject jBuilderObj = env->NewObject(jBuilderCls, jBuilderCtor);

    jmethodID jSetAudioAttributes = env->GetMethodID(jBuilderCls, "setAudioAttributes",
            "(Landroid/media/AudioAttributes;)Landroid/media/AudioTrack$Builder;");
    jBuilderObj = env->CallObjectMethod(jBuilderObj, jSetAudioAttributes,
            JAudioAttributes::createAudioAttributesObj(env, pAttributes, streamType));

    jmethodID jSetAudioFormat = env->GetMethodID(jBuilderCls, "setAudioFormat",
            "(Landroid/media/AudioFormat;)Landroid/media/AudioTrack$Builder;");
    jBuilderObj = env->CallObjectMethod(jBuilderObj, jSetAudioFormat,
            JAudioFormat::createAudioFormatObj(env, sampleRate, format, channelMask));

    jmethodID jSetBufferSizeInBytes = env->GetMethodID(jBuilderCls, "setBufferSizeInBytes",
            "(I)Landroid/media/AudioTrack$Builder;");
    jBuilderObj = env->CallObjectMethod(jBuilderObj, jSetBufferSizeInBytes, bufferSizeInBytes);

    // We only use streaming mode of Java AudioTrack.
    jfieldID jModeStream = env->GetStaticFieldID(jAudioTrackCls, "MODE_STREAM", "I");
    jint transferMode = env->GetStaticIntField(jAudioTrackCls, jModeStream);
    jmethodID jSetTransferMode = env->GetMethodID(jBuilderCls, "setTransferMode",
            "(I)Landroid/media/AudioTrack$Builder;");
    jBuilderObj = env->CallObjectMethod(jBuilderObj, jSetTransferMode,
            transferMode /* Java AudioTrack::MODE_STREAM */);

    if (sessionId != 0) {
        jmethodID jSetSessionId = env->GetMethodID(jBuilderCls, "setSessionId",
                "(I)Landroid/media/AudioTrack$Builder;");
        jBuilderObj = env->CallObjectMethod(jBuilderObj, jSetSessionId, sessionId);
    }

    jmethodID jBuild = env->GetMethodID(jBuilderCls, "build", "()Landroid/media/AudioTrack;");
    mAudioTrackObj = env->CallObjectMethod(jBuilderObj, jBuild);
}

void JAudioTrack::stop() {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jclass jAudioTrackCls = env->FindClass("android/media/AudioTrack");
    jmethodID jStop = env->GetMethodID(jAudioTrackCls, "stop", "()V");
    env->CallVoidMethod(mAudioTrackObj, jStop);
}

} // namespace android
