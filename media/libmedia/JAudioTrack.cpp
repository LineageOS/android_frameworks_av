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

#include <android_media_AudioErrors.h>
#include <android_runtime/AndroidRuntime.h>
#include <media/AudioResamplerPublic.h>

namespace android {

// TODO: Store Java class/methodID as a member variable in the class.
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
    mAudioTrackCls = (jclass) env->NewGlobalRef(jAudioTrackCls);

    maxRequiredSpeed = std::min(std::max(maxRequiredSpeed, 1.0f), AUDIO_TIMESTRETCH_SPEED_MAX);

    int bufferSizeInBytes = 0;
    if (sampleRate == 0 || frameCount > 0) {
        // Manually calculate buffer size.
        bufferSizeInBytes = audio_channel_count_from_out_mask(channelMask)
                * audio_bytes_per_sample(format) * (frameCount > 0 ? frameCount : 1);
    } else if (sampleRate > 0) {
        // Call Java AudioTrack::getMinBufferSize().
        jmethodID jGetMinBufferSize =
                env->GetStaticMethodID(mAudioTrackCls, "getMinBufferSize", "(III)I");
        bufferSizeInBytes = env->CallStaticIntMethod(mAudioTrackCls, jGetMinBufferSize,
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
    jfieldID jModeStream = env->GetStaticFieldID(mAudioTrackCls, "MODE_STREAM", "I");
    jint transferMode = env->GetStaticIntField(mAudioTrackCls, jModeStream);
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

JAudioTrack::~JAudioTrack() {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    env->DeleteGlobalRef(mAudioTrackCls);
}

size_t JAudioTrack::frameCount() {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jGetBufferSizeInFrames = env->GetMethodID(
            mAudioTrackCls, "getBufferSizeInFrames", "()I");
    return env->CallIntMethod(mAudioTrackObj, jGetBufferSizeInFrames);
}

size_t JAudioTrack::channelCount() {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jGetChannelCount = env->GetMethodID(mAudioTrackCls, "getChannelCount", "()I");
    return env->CallIntMethod(mAudioTrackObj, jGetChannelCount);
}

status_t JAudioTrack::getPosition(uint32_t *position) {
    if (position == NULL) {
        return BAD_VALUE;
    }

    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jGetPlaybackHeadPosition = env->GetMethodID(
            mAudioTrackCls, "getPlaybackHeadPosition", "()I");
    *position = env->CallIntMethod(mAudioTrackObj, jGetPlaybackHeadPosition);

    return NO_ERROR;
}

status_t JAudioTrack::setAuxEffectSendLevel(float level) {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jSetAuxEffectSendLevel = env->GetMethodID(
            mAudioTrackCls, "setAuxEffectSendLevel", "(F)I");
    int result = env->CallIntMethod(mAudioTrackObj, jSetAuxEffectSendLevel, level);
    return javaToNativeStatus(result);
}

status_t JAudioTrack::attachAuxEffect(int effectId) {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jAttachAuxEffect = env->GetMethodID(mAudioTrackCls, "attachAuxEffect", "(I)I");
    int result = env->CallIntMethod(mAudioTrackObj, jAttachAuxEffect, effectId);
    return javaToNativeStatus(result);
}

status_t JAudioTrack::setVolume(float left, float right) {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    // TODO: Java setStereoVolume is deprecated. Do we really need this method?
    jmethodID jSetStereoVolume = env->GetMethodID(mAudioTrackCls, "setStereoVolume", "(FF)I");
    int result = env->CallIntMethod(mAudioTrackObj, jSetStereoVolume, left, right);
    return javaToNativeStatus(result);
}

status_t JAudioTrack::setVolume(float volume) {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jSetVolume = env->GetMethodID(mAudioTrackCls, "setVolume", "(F)I");
    int result = env->CallIntMethod(mAudioTrackObj, jSetVolume, volume);
    return javaToNativeStatus(result);
}

status_t JAudioTrack::start() {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jPlay = env->GetMethodID(mAudioTrackCls, "play", "()V");
    // TODO: Should we catch the Java IllegalStateException from play()?
    env->CallVoidMethod(mAudioTrackObj, jPlay);
    return NO_ERROR;
}

void JAudioTrack::stop() {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jStop = env->GetMethodID(mAudioTrackCls, "stop", "()V");
    env->CallVoidMethod(mAudioTrackObj, jStop);
    // TODO: Should we catch IllegalStateException?
}

// TODO: Is the right implementation?
bool JAudioTrack::stopped() const {
    return !isPlaying();
}

void JAudioTrack::flush() {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jFlush = env->GetMethodID(mAudioTrackCls, "flush", "()V");
    env->CallVoidMethod(mAudioTrackObj, jFlush);
}

void JAudioTrack::pause() {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jPause = env->GetMethodID(mAudioTrackCls, "pause", "()V");
    env->CallVoidMethod(mAudioTrackObj, jPause);
    // TODO: Should we catch IllegalStateException?
}

bool JAudioTrack::isPlaying() const {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jGetPlayState = env->GetMethodID(mAudioTrackCls, "getPlayState", "()I");
    int currentPlayState = env->CallIntMethod(mAudioTrackObj, jGetPlayState);

    // TODO: In Java AudioTrack, there is no STOPPING state.
    // This means while stopping, isPlaying() will return different value in two class.
    //  - in existing native AudioTrack: true
    //  - in JAudioTrack: false
    // If not okay, also modify the implementation of stopped().
    jfieldID jPlayStatePlaying = env->GetStaticFieldID(mAudioTrackCls, "PLAYSTATE_PLAYING", "I");
    int statePlaying = env->GetStaticIntField(mAudioTrackCls, jPlayStatePlaying);
    return currentPlayState == statePlaying;
}

uint32_t JAudioTrack::getSampleRate() {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jGetSampleRate = env->GetMethodID(mAudioTrackCls, "getSampleRate", "()I");
    return env->CallIntMethod(mAudioTrackObj, jGetSampleRate);
}

audio_format_t JAudioTrack::format() {
    JNIEnv *env = AndroidRuntime::getJNIEnv();
    jmethodID jGetAudioFormat = env->GetMethodID(mAudioTrackCls, "getAudioFormat", "()I");
    int javaFormat = env->CallIntMethod(mAudioTrackObj, jGetAudioFormat);
    return audioFormatToNative(javaFormat);
}

status_t JAudioTrack::javaToNativeStatus(int javaStatus) {
    switch (javaStatus) {
    case AUDIO_JAVA_SUCCESS:
        return NO_ERROR;
    case AUDIO_JAVA_BAD_VALUE:
        return BAD_VALUE;
    case AUDIO_JAVA_INVALID_OPERATION:
        return INVALID_OPERATION;
    case AUDIO_JAVA_PERMISSION_DENIED:
        return PERMISSION_DENIED;
    case AUDIO_JAVA_NO_INIT:
        return NO_INIT;
    case AUDIO_JAVA_WOULD_BLOCK:
        return WOULD_BLOCK;
    case AUDIO_JAVA_DEAD_OBJECT:
        return DEAD_OBJECT;
    default:
        return UNKNOWN_ERROR;
    }
}

} // namespace android
