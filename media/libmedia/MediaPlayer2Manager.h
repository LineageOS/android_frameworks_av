/*
**
** Copyright 2017, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#ifndef ANDROID_MEDIAPLAYER2MANAGER_H
#define ANDROID_MEDIAPLAYER2MANAGER_H

#include <arpa/inet.h>

#include <utils/threads.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#include <media/MediaPlayer2Engine.h>
#include <media/MediaPlayer2Interface.h>
#include <media/Metadata.h>
#include <media/stagefright/foundation/ABase.h>

#include <system/audio.h>

namespace android {

struct AudioPlaybackRate;
class AudioTrack;
struct AVSyncSettings;
class IDataSource;
struct MediaHTTPService;
class MediaPlayer2EngineClient;

#define CALLBACK_ANTAGONIZER 0
#if CALLBACK_ANTAGONIZER
class Antagonizer {
public:
    Antagonizer(
            MediaPlayer2Base::NotifyCallback cb,
            const wp<MediaPlayer2Engine> &client);
    void start() { mActive = true; }
    void stop() { mActive = false; }
    void kill();
private:
    static const int interval;
    Antagonizer();
    static int callbackThread(void *cookie);
    Mutex                            mLock;
    Condition                        mCondition;
    bool                             mExit;
    bool                             mActive;
    wp<MediaPlayer2Engine>           mClient;
    MediaPlayer2Base::NotifyCallback mCb;
};
#endif

class MediaPlayer2Manager {
    class Client;

    class AudioOutput : public MediaPlayer2Base::AudioSink
    {
        class CallbackData;

     public:
                                AudioOutput(
                                        audio_session_t sessionId,
                                        uid_t uid,
                                        int pid,
                                        const audio_attributes_t * attr,
                                        const sp<AudioSystem::AudioDeviceCallback>& deviceCallback);
        virtual                 ~AudioOutput();

        virtual bool            ready() const { return mTrack != 0; }
        virtual ssize_t         bufferSize() const;
        virtual ssize_t         frameCount() const;
        virtual ssize_t         channelCount() const;
        virtual ssize_t         frameSize() const;
        virtual uint32_t        latency() const;
        virtual float           msecsPerFrame() const;
        virtual status_t        getPosition(uint32_t *position) const;
        virtual status_t        getTimestamp(AudioTimestamp &ts) const;
        virtual int64_t         getPlayedOutDurationUs(int64_t nowUs) const;
        virtual status_t        getFramesWritten(uint32_t *frameswritten) const;
        virtual audio_session_t getSessionId() const;
        virtual uint32_t        getSampleRate() const;
        virtual int64_t         getBufferDurationInUs() const;

        virtual status_t        open(
                uint32_t sampleRate, int channelCount, audio_channel_mask_t channelMask,
                audio_format_t format, int bufferCount,
                AudioCallback cb, void *cookie,
                audio_output_flags_t flags = AUDIO_OUTPUT_FLAG_NONE,
                const audio_offload_info_t *offloadInfo = NULL,
                bool doNotReconnect = false,
                uint32_t suggestedFrameCount = 0);

        virtual status_t        start();
        virtual ssize_t         write(const void* buffer, size_t size, bool blocking = true);
        virtual void            stop();
        virtual void            flush();
        virtual void            pause();
        virtual void            close();
                void            setAudioStreamType(audio_stream_type_t streamType);
        virtual audio_stream_type_t getAudioStreamType() const { return mStreamType; }
                void            setAudioAttributes(const audio_attributes_t * attributes);

                void            setVolume(float left, float right);
        virtual status_t        setPlaybackRate(const AudioPlaybackRate& rate);
        virtual status_t        getPlaybackRate(AudioPlaybackRate* rate /* nonnull */);

                status_t        setAuxEffectSendLevel(float level);
                status_t        attachAuxEffect(int effectId);
        virtual status_t        dump(int fd, const Vector<String16>& args) const;

        static bool             isOnEmulator();
        static int              getMinBufferCount();
                void            setNextOutput(const sp<AudioOutput>& nextOutput);
                void            switchToNextOutput();
        virtual bool            needsTrailingPadding() { return mNextOutput == NULL; }
        virtual status_t        setParameters(const String8& keyValuePairs);
        virtual String8         getParameters(const String8& keys);

        virtual media::VolumeShaper::Status applyVolumeShaper(
                                        const sp<media::VolumeShaper::Configuration>& configuration,
                                        const sp<media::VolumeShaper::Operation>& operation) override;
        virtual sp<media::VolumeShaper::State> getVolumeShaperState(int id) override;

        // AudioRouting
        virtual status_t        setOutputDevice(audio_port_handle_t deviceId);
        virtual status_t        getRoutedDeviceId(audio_port_handle_t* deviceId);
        virtual status_t        enableAudioDeviceCallback(bool enabled);

    private:
        static void             setMinBufferCount();
        static void             CallbackWrapper(
                int event, void *me, void *info);
               void             deleteRecycledTrack_l();
               void             close_l();
           status_t             updateTrack();

        sp<AudioTrack>          mTrack;
        sp<AudioTrack>          mRecycledTrack;
        sp<AudioOutput>         mNextOutput;
        AudioCallback           mCallback;
        void *                  mCallbackCookie;
        CallbackData *          mCallbackData;
        audio_stream_type_t     mStreamType;
        audio_attributes_t *    mAttributes;
        float                   mLeftVolume;
        float                   mRightVolume;
        AudioPlaybackRate       mPlaybackRate;
        uint32_t                mSampleRateHz; // sample rate of the content, as set in open()
        float                   mMsecsPerFrame;
        size_t                  mFrameSize;
        audio_session_t         mSessionId;
        uid_t                   mUid;
        int                     mPid;
        float                   mSendLevel;
        int                     mAuxEffectId;
        audio_output_flags_t    mFlags;
        sp<media::VolumeHandler>       mVolumeHandler;
        audio_port_handle_t     mSelectedDeviceId;
        audio_port_handle_t     mRoutedDeviceId;
        bool                    mDeviceCallbackEnabled;
        wp<AudioSystem::AudioDeviceCallback>        mDeviceCallback;
        mutable Mutex           mLock;

        // static variables below not protected by mutex
        static bool             mIsOnEmulator;
        static int              mMinBufferCount;  // 12 for emulator; otherwise 4

        // CallbackData is what is passed to the AudioTrack as the "user" data.
        // We need to be able to target this to a different Output on the fly,
        // so we can't use the Output itself for this.
        class CallbackData {
            friend AudioOutput;
        public:
            explicit CallbackData(AudioOutput *cookie) {
                mData = cookie;
                mSwitching = false;
            }
            AudioOutput *   getOutput() const { return mData; }
            void            setOutput(AudioOutput* newcookie) { mData = newcookie; }
            // lock/unlock are used by the callback before accessing the payload of this object
            void            lock() const { mLock.lock(); }
            void            unlock() const { mLock.unlock(); }

            // tryBeginTrackSwitch/endTrackSwitch are used when the CallbackData is handed over
            // to the next sink.

            // tryBeginTrackSwitch() returns true only if it obtains the lock.
            bool            tryBeginTrackSwitch() {
                LOG_ALWAYS_FATAL_IF(mSwitching, "tryBeginTrackSwitch() already called");
                if (mLock.tryLock() != OK) {
                    return false;
                }
                mSwitching = true;
                return true;
            }
            void            endTrackSwitch() {
                if (mSwitching) {
                    mLock.unlock();
                }
                mSwitching = false;
            }
        private:
            AudioOutput *   mData;
            mutable Mutex   mLock; // a recursive mutex might make this unnecessary.
            bool            mSwitching;
            DISALLOW_EVIL_CONSTRUCTORS(CallbackData);
        };

    }; // AudioOutput


public:
    MediaPlayer2Manager();
    virtual ~MediaPlayer2Manager();

    static MediaPlayer2Manager& get();

    // MediaPlayer2Manager interface
    virtual sp<MediaPlayer2Engine> create(const sp<MediaPlayer2EngineClient>& client,
                                          audio_session_t audioSessionId);

    virtual status_t            dump(int fd, const Vector<String16>& args);

            void                removeClient(const wp<Client>& client);
            bool                hasClient(wp<Client> client);

private:
    class Client : public MediaPlayer2Engine {
        // MediaPlayer2Engine interface
        virtual void            disconnect();
        virtual status_t        setVideoSurfaceTexture(
                                        const sp<IGraphicBufferProducer>& bufferProducer);
        virtual status_t        setBufferingSettings(const BufferingSettings& buffering) override;
        virtual status_t        getBufferingSettings(
                                        BufferingSettings* buffering /* nonnull */) override;
        virtual status_t        prepareAsync();
        virtual status_t        start();
        virtual status_t        stop();
        virtual status_t        pause();
        virtual status_t        isPlaying(bool* state);
        virtual status_t        setPlaybackSettings(const AudioPlaybackRate& rate);
        virtual status_t        getPlaybackSettings(AudioPlaybackRate* rate /* nonnull */);
        virtual status_t        setSyncSettings(const AVSyncSettings& rate, float videoFpsHint);
        virtual status_t        getSyncSettings(AVSyncSettings* rate /* nonnull */,
                                                float* videoFps /* nonnull */);
        virtual status_t        seekTo(
                int msec,
                MediaPlayer2SeekMode mode = MediaPlayer2SeekMode::SEEK_PREVIOUS_SYNC);
        virtual status_t        getCurrentPosition(int* msec);
        virtual status_t        getDuration(int* msec);
        virtual status_t        reset();
        virtual status_t        notifyAt(int64_t mediaTimeUs);
        virtual status_t        setAudioStreamType(audio_stream_type_t type);
        virtual status_t        setLooping(int loop);
        virtual status_t        setVolume(float leftVolume, float rightVolume);
        virtual status_t        invoke(const Parcel& request, Parcel *reply);
        virtual status_t        setMetadataFilter(const Parcel& filter);
        virtual status_t        getMetadata(bool update_only,
                                            bool apply_filter,
                                            Parcel *reply);
        virtual status_t        setAuxEffectSendLevel(float level);
        virtual status_t        attachAuxEffect(int effectId);
        virtual status_t        setParameter(int key, const Parcel &request);
        virtual status_t        getParameter(int key, Parcel *reply);
        virtual status_t        setRetransmitEndpoint(const struct sockaddr_in* endpoint);
        virtual status_t        getRetransmitEndpoint(struct sockaddr_in* endpoint);
        virtual status_t        setNextPlayer(const sp<MediaPlayer2Engine>& player);

        virtual media::VolumeShaper::Status applyVolumeShaper(
                                        const sp<media::VolumeShaper::Configuration>& configuration,
                                        const sp<media::VolumeShaper::Operation>& operation) override;
        virtual sp<media::VolumeShaper::State> getVolumeShaperState(int id) override;

        sp<MediaPlayer2Base>     createPlayer(player2_type playerType);

        virtual status_t        setDataSource(
                        const sp<MediaHTTPService> &httpService,
                        const char *url,
                        const KeyedVector<String8, String8> *headers);

        virtual status_t        setDataSource(int fd, int64_t offset, int64_t length);

        virtual status_t        setDataSource(const sp<IStreamSource> &source);
        virtual status_t        setDataSource(const sp<IDataSource> &source);


        sp<MediaPlayer2Base>     setDataSource_pre(player2_type playerType);
        status_t                setDataSource_post(const sp<MediaPlayer2Base>& p,
                                                   status_t status);

        static  void            notify(const wp<MediaPlayer2Engine> &listener, int msg,
                                       int ext1, int ext2, const Parcel *obj);

                pid_t           pid() const { return mPid; }
        virtual status_t        dump(int fd, const Vector<String16>& args);

                audio_session_t getAudioSessionId() { return mAudioSessionId; }
        // Modular DRM
        virtual status_t prepareDrm(const uint8_t uuid[16], const Vector<uint8_t>& drmSessionId);
        virtual status_t releaseDrm();
        // AudioRouting
        virtual status_t setOutputDevice(audio_port_handle_t deviceId);
        virtual status_t getRoutedDeviceId(audio_port_handle_t* deviceId);
        virtual status_t enableAudioDeviceCallback(bool enabled);

    private:
        class AudioDeviceUpdatedNotifier: public AudioSystem::AudioDeviceCallback
        {
        public:
            AudioDeviceUpdatedNotifier(const sp<MediaPlayer2Base>& listener) {
                mListener = listener;
            }
            ~AudioDeviceUpdatedNotifier() {}

            virtual void onAudioDeviceUpdate(audio_io_handle_t audioIo,
                                             audio_port_handle_t deviceId);

        private:
            wp<MediaPlayer2Base> mListener;
        };

        friend class MediaPlayer2Manager;
                                Client(pid_t pid,
                                       int32_t connId,
                                       const sp<MediaPlayer2EngineClient>& client,
                                       audio_session_t audioSessionId,
                                       uid_t uid);
                                Client();
        virtual                 ~Client();

                void            deletePlayer();

        sp<MediaPlayer2Base>     getPlayer() const { Mutex::Autolock lock(mLock); return mPlayer; }



        // @param type Of the metadata to be tested.
        // @return true if the metadata should be dropped according to
        //              the filters.
        bool shouldDropMetadata(media::Metadata::Type type) const;

        // Add a new element to the set of metadata updated. Noop if
        // the element exists already.
        // @param type Of the metadata to be recorded.
        void addNewMetadataUpdate(media::Metadata::Type type);

        // Disconnect from the currently connected ANativeWindow.
        void disconnectNativeWindow_l();

        status_t setAudioAttributes_l(const Parcel &request);

        mutable     Mutex                        mLock;
                    sp<MediaPlayer2Base>         mPlayer;
                    sp<MediaPlayer2EngineClient> mClient;
                    sp<AudioOutput>              mAudioOutput;
                    pid_t                        mPid;
                    status_t                     mStatus;
                    bool                         mLoop;
                    int32_t                      mConnId;
                    audio_session_t              mAudioSessionId;
                    audio_attributes_t *         mAudioAttributes;
                    uid_t                        mUid;
                    sp<ANativeWindow>            mConnectedWindow;
                    sp<IBinder>                  mConnectedWindowBinder;
                    struct sockaddr_in           mRetransmitEndpoint;
                    bool                         mRetransmitEndpointValid;
                    sp<Client>                   mNextClient;

        // Metadata filters.
        media::Metadata::Filter mMetadataAllow;  // protected by mLock
        media::Metadata::Filter mMetadataDrop;  // protected by mLock

        // Metadata updated. For each MEDIA_INFO_METADATA_UPDATE
        // notification we try to update mMetadataUpdated which is a
        // set: no duplicate.
        // getMetadata clears this set.
        media::Metadata::Filter mMetadataUpdated;  // protected by mLock

        sp<AudioDeviceUpdatedNotifier> mAudioDeviceUpdatedListener;
#if CALLBACK_ANTAGONIZER
                    Antagonizer*                mAntagonizer;
#endif
    }; // Client

// ----------------------------------------------------------------------------

    pid_t mPid;
    uid_t mUid;

    mutable Mutex mLock;
    SortedVector< wp<Client> > mClients;
    int32_t mNextConnId;
};

// ----------------------------------------------------------------------------

}; // namespace android

#endif // ANDROID_MEDIAPLAYER2MANAGER_H
