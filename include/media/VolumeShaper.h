/*
 * Copyright 2017 The Android Open Source Project
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

#ifndef ANDROID_VOLUME_SHAPER_H
#define ANDROID_VOLUME_SHAPER_H

#include <cmath>
#include <list>
#include <math.h>
#include <sstream>

#include <binder/Parcel.h>
#include <media/Interpolator.h>
#include <utils/Mutex.h>
#include <utils/RefBase.h>

#pragma push_macro("LOG_TAG")
#undef LOG_TAG
#define LOG_TAG "VolumeShaper"

// turn on VolumeShaper logging
#if 0
#define VS_LOG ALOGD
#else
#define VS_LOG(...)
#endif

namespace android {

// The native VolumeShaper class mirrors the java VolumeShaper class;
// in addition, the native class contains implementation for actual operation.
//
// VolumeShaper methods are not safe for multiple thread access.
// Use VolumeHandler for thread-safe encapsulation of multiple VolumeShapers.
//
// Classes below written are to avoid naked pointers so there are no
// explicit destructors required.

class VolumeShaper {
public:
    using S = float;
    using T = float;

    static const int kSystemIdMax = 16;

    // VolumeShaper::Status is equivalent to status_t if negative
    // but if non-negative represents the id operated on.
    // It must be expressible as an int32_t for binder purposes.
    using Status = status_t;

    class Configuration : public Interpolator<S, T>, public RefBase {
    public:
        /* VolumeShaper.Configuration derives from the Interpolator class and adds
         * parameters relating to the volume shape.
         */

        // TODO document as per VolumeShaper.java flags.

        // must match with VolumeShaper.java in frameworks/base
        enum Type : int32_t {
            TYPE_ID,
            TYPE_SCALE,
        };

        // must match with VolumeShaper.java in frameworks/base
        enum OptionFlag : int32_t {
            OPTION_FLAG_NONE           = 0,
            OPTION_FLAG_VOLUME_IN_DBFS = (1 << 0),
            OPTION_FLAG_CLOCK_TIME     = (1 << 1),

            OPTION_FLAG_ALL            = (OPTION_FLAG_VOLUME_IN_DBFS | OPTION_FLAG_CLOCK_TIME),
        };

        // bring to derived class; must match with VolumeShaper.java in frameworks/base
        using InterpolatorType = Interpolator<S, T>::InterpolatorType;

        Configuration()
            : Interpolator<S, T>()
            , mType(TYPE_SCALE)
            , mOptionFlags(OPTION_FLAG_NONE)
            , mDurationMs(1000.)
            , mId(-1) {
        }

        explicit Configuration(const Configuration &configuration)
            : Interpolator<S, T>(*static_cast<const Interpolator<S, T> *>(&configuration))
            , mType(configuration.mType)
            , mOptionFlags(configuration.mOptionFlags)
            , mDurationMs(configuration.mDurationMs)
            , mId(configuration.mId) {
        }

        Type getType() const {
            return mType;
        }

        status_t setType(Type type) {
            switch (type) {
            case TYPE_ID:
            case TYPE_SCALE:
                mType = type;
                return NO_ERROR;
            default:
                ALOGE("invalid Type: %d", type);
                return BAD_VALUE;
            }
        }

        OptionFlag getOptionFlags() const {
            return mOptionFlags;
        }

        status_t setOptionFlags(OptionFlag optionFlags) {
            if ((optionFlags & ~OPTION_FLAG_ALL) != 0) {
                ALOGE("optionFlags has invalid bits: %#x", optionFlags);
                return BAD_VALUE;
            }
            mOptionFlags = optionFlags;
            return NO_ERROR;
        }

        double getDurationMs() const {
            return mDurationMs;
        }

        void setDurationMs(double durationMs) {
            mDurationMs = durationMs;
        }

        int32_t getId() const {
            return mId;
        }

        void setId(int32_t id) {
            mId = id;
        }

        T adjustVolume(T volume) const {
            if ((getOptionFlags() & OPTION_FLAG_VOLUME_IN_DBFS) != 0) {
                const T out = powf(10.f, volume / 10.);
                VS_LOG("in: %f  out: %f", volume, out);
                volume = out;
            }
            // clamp
            if (volume < 0.f) {
                volume = 0.f;
            } else if (volume > 1.f) {
                volume = 1.f;
            }
            return volume;
        }

        status_t checkCurve() {
            if (mType == TYPE_ID) return NO_ERROR;
            if (this->size() < 2) {
                ALOGE("curve must have at least 2 points");
                return BAD_VALUE;
            }
            if (first().first != 0.f || last().first != 1.f) {
                ALOGE("curve must start at 0.f and end at 1.f");
                return BAD_VALUE;
            }
            if ((getOptionFlags() & OPTION_FLAG_VOLUME_IN_DBFS) != 0) {
                for (const auto &pt : *this) {
                    if (!(pt.second <= 0.f) /* handle nan */) {
                        ALOGE("positive volume dbFS");
                        return BAD_VALUE;
                    }
                }
            } else {
                for (const auto &pt : *this) {
                    if (!(pt.second >= 0.f) || !(pt.second <= 1.f) /* handle nan */) {
                        ALOGE("volume < 0.f or > 1.f");
                        return BAD_VALUE;
                    }
                }
            }
            return NO_ERROR;
        }

        void clampVolume() {
            if ((mOptionFlags & OPTION_FLAG_VOLUME_IN_DBFS) != 0) {
                for (auto it = this->begin(); it != this->end(); ++it) {
                    if (!(it->second <= 0.f) /* handle nan */) {
                        it->second = 0.f;
                    }
                }
            } else {
                for (auto it = this->begin(); it != this->end(); ++it) {
                    if (!(it->second >= 0.f) /* handle nan */) {
                        it->second = 0.f;
                    } else if (!(it->second <= 1.f)) {
                        it->second = 1.f;
                    }
                }
            }
        }

        /* scaleToStartVolume() is used to set the start volume of a
         * new VolumeShaper curve, when replacing one VolumeShaper
         * with another using the "join" (volume match) option.
         *
         * It works best for monotonic volume ramps or ducks.
         */
        void scaleToStartVolume(T volume) {
            if (this->size() < 2) {
                return;
            }
            const T startVolume = first().second;
            const T endVolume = last().second;
            if (endVolume == startVolume) {
                // match with linear ramp
                const T offset = volume - startVolume;
                for (auto it = this->begin(); it != this->end(); ++it) {
                    it->second = it->second + offset * (1.f - it->first);
                }
            } else {
                const T  scale = (volume - endVolume) / (startVolume - endVolume);
                for (auto it = this->begin(); it != this->end(); ++it) {
                    it->second = scale * (it->second - endVolume) + endVolume;
                }
            }
            clampVolume();
        }

        // The parcel layout must match VolumeShaper.java
        status_t writeToParcel(Parcel *parcel) const {
            if (parcel == nullptr) return BAD_VALUE;
            return parcel->writeInt32((int32_t)mType)
                    ?: parcel->writeInt32(mId)
                    ?: mType == TYPE_ID
                        ? NO_ERROR
                        : parcel->writeInt32((int32_t)mOptionFlags)
                            ?: parcel->writeDouble(mDurationMs)
                            ?: Interpolator<S, T>::writeToParcel(parcel);
        }

        status_t readFromParcel(const Parcel &parcel) {
            int32_t type, optionFlags;
            return parcel.readInt32(&type)
                    ?: setType((Type)type)
                    ?: parcel.readInt32(&mId)
                    ?: mType == TYPE_ID
                        ? NO_ERROR
                        : parcel.readInt32(&optionFlags)
                            ?: setOptionFlags((OptionFlag)optionFlags)
                            ?: parcel.readDouble(&mDurationMs)
                            ?: Interpolator<S, T>::readFromParcel(parcel)
                            ?: checkCurve();
        }

        std::string toString() const {
            std::stringstream ss;
            ss << "mType: " << mType << std::endl;
            ss << "mId: " << mId << std::endl;
            if (mType != TYPE_ID) {
                ss << "mOptionFlags: " << mOptionFlags << std::endl;
                ss << "mDurationMs: " << mDurationMs << std::endl;
                ss << Interpolator<S, T>::toString().c_str();
            }
            return ss.str();
        }

    private:
        Type mType;
        int32_t mId;
        OptionFlag mOptionFlags;
        double mDurationMs;
    }; // Configuration

    // must match with VolumeShaper.java in frameworks/base
    // TODO document per VolumeShaper.java flags.
    class Operation : public RefBase {
    public:
        enum Flag : int32_t {
            FLAG_NONE      = 0,
            FLAG_REVERSE   = (1 << 0),
            FLAG_TERMINATE = (1 << 1),
            FLAG_JOIN      = (1 << 2),
            FLAG_DELAY     = (1 << 3),
            FLAG_CREATE_IF_NECESSARY = (1 << 4),

            FLAG_ALL       = (FLAG_REVERSE | FLAG_TERMINATE | FLAG_JOIN | FLAG_DELAY
                            | FLAG_CREATE_IF_NECESSARY),
        };

        Operation()
            : Operation(FLAG_NONE, -1 /* replaceId */) {
        }

        Operation(Flag flags, int replaceId)
            : Operation(flags, replaceId, std::numeric_limits<S>::quiet_NaN() /* xOffset */) {
        }

        explicit Operation(const Operation &operation)
            : Operation(operation.mFlags, operation.mReplaceId, operation.mXOffset) {
        }

        explicit Operation(const sp<Operation> &operation)
            : Operation(*operation.get()) {
        }

        Operation(Flag flags, int replaceId, S xOffset)
            : mFlags(flags)
            , mReplaceId(replaceId)
            , mXOffset(xOffset) {
        }

        int32_t getReplaceId() const {
            return mReplaceId;
        }

        void setReplaceId(int32_t replaceId) {
            mReplaceId = replaceId;
        }

        S getXOffset() const {
            return mXOffset;
        }

        void setXOffset(S xOffset) {
            mXOffset = xOffset;
        }

        Flag getFlags() const {
            return mFlags;
        }

        status_t setFlags(Flag flags) {
            if ((flags & ~FLAG_ALL) != 0) {
                ALOGE("flags has invalid bits: %#x", flags);
                return BAD_VALUE;
            }
            mFlags = flags;
            return NO_ERROR;
        }

        status_t writeToParcel(Parcel *parcel) const {
            if (parcel == nullptr) return BAD_VALUE;
            return parcel->writeInt32((int32_t)mFlags)
                    ?: parcel->writeInt32(mReplaceId)
                    ?: parcel->writeFloat(mXOffset);
        }

        status_t readFromParcel(const Parcel &parcel) {
            int32_t flags;
            return parcel.readInt32(&flags)
                    ?: parcel.readInt32(&mReplaceId)
                    ?: parcel.readFloat(&mXOffset)
                    ?: setFlags((Flag)flags);
        }

        std::string toString() const {
            std::stringstream ss;
            ss << "mFlags: " << mFlags << std::endl;
            ss << "mReplaceId: " << mReplaceId << std::endl;
            ss << "mXOffset: " << mXOffset << std::endl;
            return ss.str();
        }

    private:
        Flag mFlags;
        int32_t mReplaceId;
        S mXOffset;
    }; // Operation

    // must match with VolumeShaper.java in frameworks/base
    class State : public RefBase {
    public:
        State(T volume, S xOffset)
            : mVolume(volume)
            , mXOffset(xOffset) {
        }

        State()
            : State(-1.f, -1.f) { }

        T getVolume() const {
            return mVolume;
        }

        void setVolume(T volume) {
            mVolume = volume;
        }

        S getXOffset() const {
            return mXOffset;
        }

        void setXOffset(S xOffset) {
            mXOffset = xOffset;
        }

        status_t writeToParcel(Parcel *parcel) const {
            if (parcel == nullptr) return BAD_VALUE;
            return parcel->writeFloat(mVolume)
                    ?: parcel->writeFloat(mXOffset);
        }

        status_t readFromParcel(const Parcel &parcel) {
            return parcel.readFloat(&mVolume)
                     ?: parcel.readFloat(&mXOffset);
        }

        std::string toString() const {
            std::stringstream ss;
            ss << "mVolume: " << mVolume << std::endl;
            ss << "mXOffset: " << mXOffset << std::endl;
            return ss.str();
        }

    private:
        T mVolume;
        S mXOffset;
    }; // State

    template <typename R>
    class Translate {
    public:
        Translate()
            : mOffset(0)
            , mScale(1) {
        }

        R getOffset() const {
            return mOffset;
        }

        void setOffset(R offset) {
            mOffset = offset;
        }

        R getScale() const {
            return mScale;
        }

        void setScale(R scale) {
            mScale = scale;
        }

        R operator()(R in) const {
            return mScale * (in - mOffset);
        }

        std::string toString() const {
            std::stringstream ss;
            ss << "mOffset: " << mOffset << std::endl;
            ss << "mScale: " << mScale << std::endl;
            return ss.str();
        }

    private:
        R mOffset;
        R mScale;
    }; // Translate

    static int64_t convertTimespecToUs(const struct timespec &tv)
    {
        return tv.tv_sec * 1000000ll + tv.tv_nsec / 1000;
    }

    // current monotonic time in microseconds.
    static int64_t getNowUs()
    {
        struct timespec tv;
        if (clock_gettime(CLOCK_MONOTONIC, &tv) != 0) {
            return 0; // system is really sick, just return 0 for consistency.
        }
        return convertTimespecToUs(tv);
    }

    // TODO: Since we pass configuration and operation as shared pointers
    // there is a potential risk that the caller may modify these after
    // delivery.  Currently, we don't require copies made here.
    VolumeShaper(
            const sp<VolumeShaper::Configuration> &configuration,
            const sp<VolumeShaper::Operation> &operation)
        : mConfiguration(configuration) // we do not make a copy
        , mOperation(operation)         // ditto
        , mStartFrame(-1)
        , mLastVolume(T(1))
        , mLastXOffset(0.f)
        , mDelayXOffset(std::numeric_limits<S>::quiet_NaN()) {
        if (configuration.get() != nullptr
                && (getFlags() & VolumeShaper::Operation::FLAG_DELAY) == 0) {
            mLastVolume = configuration->first().second;
        }
    }

    void updatePosition(int64_t startFrame, double sampleRate) {
        double scale = (mConfiguration->last().first - mConfiguration->first().first)
                        / (mConfiguration->getDurationMs() * 0.001 * sampleRate);
        const double minScale = 1. / INT64_MAX;
        scale = std::max(scale, minScale);
        const S xOffset = std::isnan(mDelayXOffset) ? mConfiguration->first().first : mDelayXOffset;
        VS_LOG("update position: scale %lf  frameCount:%lld, sampleRate:%lf, xOffset:%f",
                scale, (long long) startFrame, sampleRate, xOffset);

        mXTranslate.setOffset(startFrame - xOffset / scale);
        mXTranslate.setScale(scale);
        VS_LOG("translate: %s", mXTranslate.toString().c_str());
    }

    // We allow a null operation here, though VolumeHandler always provides one.
    VolumeShaper::Operation::Flag getFlags() const {
        return mOperation == nullptr
                ? VolumeShaper::Operation::FLAG_NONE :mOperation->getFlags();
    }

    sp<VolumeShaper::State> getState() const {
        return new VolumeShaper::State(mLastVolume, mLastXOffset);
    }

    void setDelayXOffset(S xOffset) {
        mDelayXOffset = xOffset;
    }

    bool isStarted() const {
        return mStartFrame >= 0;
    }

    std::pair<T /* volume */, bool /* active */> getVolume(
            int64_t trackFrameCount, double trackSampleRate) {
        if ((getFlags() & VolumeShaper::Operation::FLAG_DELAY) != 0) {
            VS_LOG("delayed VolumeShaper, ignoring");
            mLastVolume = T(1);
            mLastXOffset = 0.;
            return std::make_pair(T(1), false);
        }
        const bool clockTime = (mConfiguration->getOptionFlags()
                & VolumeShaper::Configuration::OPTION_FLAG_CLOCK_TIME) != 0;
        const int64_t frameCount = clockTime ? getNowUs() : trackFrameCount;
        const double sampleRate = clockTime ? 1000000 : trackSampleRate;

        if (mStartFrame < 0) {
            updatePosition(frameCount, sampleRate);
            mStartFrame = frameCount;
        }
        VS_LOG("frameCount: %lld", (long long)frameCount);
        S x = mXTranslate((T)frameCount);
        VS_LOG("translation: %f", x);

        // handle reversal of position
        if (getFlags() & VolumeShaper::Operation::FLAG_REVERSE) {
            x = 1.f - x;
            VS_LOG("reversing to %f", x);
            if (x < mConfiguration->first().first) {
                mLastXOffset = 1.f;
                const T volume = mConfiguration->adjustVolume(
                        mConfiguration->first().second);  // persist last value
                VS_LOG("persisting volume %f", volume);
                mLastVolume = volume;
                return std::make_pair(volume, false);
            }
            if (x > mConfiguration->last().first) {
                mLastXOffset = 0.f;
                mLastVolume = 1.f;
                return std::make_pair(T(1), true); // too early
            }
        } else {
            if (x < mConfiguration->first().first) {
                mLastXOffset = 0.f;
                mLastVolume = 1.f;
                return std::make_pair(T(1), true); // too early
            }
            if (x > mConfiguration->last().first) {
                mLastXOffset = 1.f;
                const T volume = mConfiguration->adjustVolume(
                        mConfiguration->last().second);  // persist last value
                VS_LOG("persisting volume %f", volume);
                mLastVolume = volume;
                return std::make_pair(volume, false);
            }
        }
        mLastXOffset = x;
        // x contains the location on the volume curve to use.
        const T unscaledVolume = mConfiguration->findY(x);
        const T volume = mConfiguration->adjustVolume(unscaledVolume); // handle log scale
        VS_LOG("volume: %f  unscaled: %f", volume, unscaledVolume);
        mLastVolume = volume;
        return std::make_pair(volume, true);
    }

    std::string toString() const {
        std::stringstream ss;
        ss << "StartFrame: " << mStartFrame << std::endl;
        ss << mXTranslate.toString().c_str();
        if (mConfiguration.get() == nullptr) {
            ss << "VolumeShaper::Configuration: nullptr" << std::endl;
        } else {
            ss << "VolumeShaper::Configuration:" << std::endl;
            ss << mConfiguration->toString().c_str();
        }
        if (mOperation.get() == nullptr) {
            ss << "VolumeShaper::Operation: nullptr" << std::endl;
        } else {
            ss << "VolumeShaper::Operation:" << std::endl;
            ss << mOperation->toString().c_str();
        }
        return ss.str();
    }

    Translate<S> mXTranslate; // x axis translation from frames (in usec for clock time)
    sp<VolumeShaper::Configuration> mConfiguration;
    sp<VolumeShaper::Operation> mOperation;
    int64_t mStartFrame; // starting frame, non-negative when started (in usec for clock time)
    T mLastVolume;       // last computed interpolated volume (y-axis)
    S mLastXOffset;      // last computed interpolated xOffset/time (x-axis)
    S mDelayXOffset;     // delay xOffset on first volumeshaper start.
}; // VolumeShaper

// VolumeHandler combines the volume factors of multiple VolumeShapers and handles
// multiple thread access by synchronizing all public methods.
class VolumeHandler : public RefBase {
public:
    using S = float;
    using T = float;

    // A volume handler which just keeps track of active VolumeShapers does not need sampleRate.
    VolumeHandler()
        : VolumeHandler(0 /* sampleRate */) {
    }

    explicit VolumeHandler(uint32_t sampleRate)
        : mSampleRate((double)sampleRate)
        , mLastFrame(0)
        , mVolumeShaperIdCounter(VolumeShaper::kSystemIdMax)
        , mLastVolume(1.f, false) {
    }

    VolumeShaper::Status applyVolumeShaper(
            const sp<VolumeShaper::Configuration> &configuration,
            const sp<VolumeShaper::Operation> &operation) {
        VS_LOG("applyVolumeShaper:configuration: %s", configuration->toString().c_str());
        VS_LOG("applyVolumeShaper:operation: %s", operation->toString().c_str());
        AutoMutex _l(mLock);
        if (configuration == nullptr) {
            ALOGE("null configuration");
            return VolumeShaper::Status(BAD_VALUE);
        }
        if (operation == nullptr) {
            ALOGE("null operation");
            return VolumeShaper::Status(BAD_VALUE);
        }
        const int32_t id = configuration->getId();
        if (id < 0) {
            ALOGE("negative id: %d", id);
            return VolumeShaper::Status(BAD_VALUE);
        }
        VS_LOG("applyVolumeShaper id: %d", id);

        switch (configuration->getType()) {
        case VolumeShaper::Configuration::TYPE_SCALE: {
            const int replaceId = operation->getReplaceId();
            if (replaceId >= 0) {
                auto replaceIt = findId_l(replaceId);
                if (replaceIt == mVolumeShapers.end()) {
                    ALOGW("cannot find replace id: %d", replaceId);
                } else {
                    if ((replaceIt->getFlags() & VolumeShaper::Operation::FLAG_JOIN) != 0) {
                        // For join, we scale the start volume of the current configuration
                        // to match the last-used volume of the replacing VolumeShaper.
                        auto state = replaceIt->getState();
                        if (state->getXOffset() >= 0) { // valid
                            const T volume = state->getVolume();
                            ALOGD("join: scaling start volume to %f", volume);
                            configuration->scaleToStartVolume(volume);
                        }
                    }
                    (void)mVolumeShapers.erase(replaceIt);
                }
                operation->setReplaceId(-1);
            }
            // check if we have another of the same id.
            auto oldIt = findId_l(id);
            if (oldIt != mVolumeShapers.end()) {
                if ((operation->getFlags()
                        & VolumeShaper::Operation::FLAG_CREATE_IF_NECESSARY) != 0) {
                    // TODO: move the case to a separate function.
                    goto HANDLE_TYPE_ID; // no need to create, take over existing id.
                }
                ALOGW("duplicate id, removing old %d", id);
                (void)mVolumeShapers.erase(oldIt);
            }
            // create new VolumeShaper
            mVolumeShapers.emplace_back(configuration, operation);
        }
        // fall through to handle the operation
        HANDLE_TYPE_ID:
        case VolumeShaper::Configuration::TYPE_ID: {
            VS_LOG("trying to find id: %d", id);
            auto it = findId_l(id);
            if (it == mVolumeShapers.end()) {
                VS_LOG("couldn't find id: %d", id);
                return VolumeShaper::Status(INVALID_OPERATION);
            }
            if ((it->getFlags() & VolumeShaper::Operation::FLAG_TERMINATE) != 0) {
                VS_LOG("terminate id: %d", id);
                mVolumeShapers.erase(it);
                break;
            }
            const bool clockTime = (it->mConfiguration->getOptionFlags()
                    & VolumeShaper::Configuration::OPTION_FLAG_CLOCK_TIME) != 0;
            if ((it->getFlags() & VolumeShaper::Operation::FLAG_REVERSE) !=
                    (operation->getFlags() & VolumeShaper::Operation::FLAG_REVERSE)) {
                const int64_t frameCount = clockTime ? VolumeShaper::getNowUs() : mLastFrame;
                const S x = it->mXTranslate((T)frameCount);
                VS_LOG("reverse translation: %f", x);
                // reflect position
                S target = 1.f - x;
                if (target < it->mConfiguration->first().first) {
                    VS_LOG("clamp to start - begin immediately");
                    target = 0.;
                }
                VS_LOG("target reverse: %f", target);
                it->mXTranslate.setOffset(it->mXTranslate.getOffset()
                        + (x - target) / it->mXTranslate.getScale());
            }
            const S xOffset = operation->getXOffset();
            if (!std::isnan(xOffset)) {
                const int64_t frameCount = clockTime ? VolumeShaper::getNowUs() : mLastFrame;
                const S x = it->mXTranslate((T)frameCount);
                VS_LOG("xOffset translation: %f", x);
                const S target = xOffset; // offset
                VS_LOG("xOffset target x offset: %f", target);
                it->mXTranslate.setOffset(it->mXTranslate.getOffset()
                        + (x - target) / it->mXTranslate.getScale());
                it->setDelayXOffset(xOffset);
            }
            it->mOperation = operation; // replace the operation
        } break;
        }
        return VolumeShaper::Status(id);
    }

    sp<VolumeShaper::State> getVolumeShaperState(int id) {
        AutoMutex _l(mLock);
        auto it = findId_l(id);
        if (it == mVolumeShapers.end()) {
            VS_LOG("cannot find state for id: %d", id);
            return nullptr;
        }
        return it->getState();
    }

    // getVolume() is not const, as it updates internal state.
    // Once called, any VolumeShapers not already started begin running.
    std::pair<T /* volume */, bool /* active */> getVolume(int64_t trackFrameCount) {
        AutoMutex _l(mLock);
        mLastFrame = trackFrameCount;
        T volume(1);
        size_t activeCount = 0;
        for (auto it = mVolumeShapers.begin(); it != mVolumeShapers.end();) {
            std::pair<T, bool> shaperVolume =
                    it->getVolume(trackFrameCount, mSampleRate);
            volume *= shaperVolume.first;
            activeCount += shaperVolume.second;
            ++it;
        }
        mLastVolume = std::make_pair(volume, activeCount != 0);
        return mLastVolume;
    }

    // Used by a client side VolumeHandler to ensure all the VolumeShapers
    // indicate that they have been started.  Upon a change in audioserver
    // output sink, this information is used for restoration of the server side
    // VolumeHandler.
    void setStarted() {
        (void)getVolume(mLastFrame);  // getVolume() will start the individual VolumeShapers.
    }

    std::pair<T /* volume */, bool /* active */> getLastVolume() const {
        AutoMutex _l(mLock);
        return mLastVolume;
    }

    std::string toString() const {
        AutoMutex _l(mLock);
        std::stringstream ss;
        ss << "mSampleRate: " << mSampleRate << std::endl;
        ss << "mLastFrame: " << mLastFrame << std::endl;
        for (const auto &shaper : mVolumeShapers) {
            ss << shaper.toString().c_str();
        }
        return ss.str();
    }

    void forall(const std::function<VolumeShaper::Status (const VolumeShaper &)> &lambda) {
        AutoMutex _l(mLock);
        VS_LOG("forall: mVolumeShapers.size() %zu", mVolumeShapers.size());
        for (const auto &shaper : mVolumeShapers) {
            VolumeShaper::Status status = lambda(shaper);
            VS_LOG("forall applying lambda on shaper (%p): %d", &shaper, (int)status);
        }
    }

    void reset() {
        AutoMutex _l(mLock);
        mVolumeShapers.clear();
        mLastFrame = 0;
        // keep mVolumeShaperIdCounter as is.
    }

    // Sets the configuration id if necessary - This is based on the counter
    // internal to the VolumeHandler.
    void setIdIfNecessary(const sp<VolumeShaper::Configuration> &configuration) {
        if (configuration->getType() == VolumeShaper::Configuration::TYPE_SCALE) {
            const int id = configuration->getId();
            if (id == -1) {
                // Reassign to a unique id, skipping system ids.
                AutoMutex _l(mLock);
                while (true) {
                    if (mVolumeShaperIdCounter == INT32_MAX) {
                        mVolumeShaperIdCounter = VolumeShaper::kSystemIdMax;
                    } else {
                        ++mVolumeShaperIdCounter;
                    }
                    if (findId_l(mVolumeShaperIdCounter) != mVolumeShapers.end()) {
                        continue; // collision with an existing id.
                    }
                    configuration->setId(mVolumeShaperIdCounter);
                    ALOGD("setting id to %d", mVolumeShaperIdCounter);
                    break;
                }
            }
        }
    }

private:
    std::list<VolumeShaper>::iterator findId_l(int32_t id) {
        std::list<VolumeShaper>::iterator it = mVolumeShapers.begin();
        for (; it != mVolumeShapers.end(); ++it) {
            if (it->mConfiguration->getId() == id) {
                break;
            }
        }
        return it;
    }

    mutable Mutex mLock;
    double mSampleRate; // in samples (frames) per second
    int64_t mLastFrame; // logging purpose only, 0 on start
    int32_t mVolumeShaperIdCounter; // a counter to return a unique volume shaper id.
    std::pair<T /* volume */, bool /* active */> mLastVolume;
    std::list<VolumeShaper> mVolumeShapers; // list provides stable iterators on erase
}; // VolumeHandler

} // namespace android

#pragma pop_macro("LOG_TAG")

#endif // ANDROID_VOLUME_SHAPER_H
