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

package com.android.media;

import android.Manifest.permission;
import android.app.PendingIntent;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.media.AudioAttributes;
import android.media.IMediaSession2Callback;
import android.media.MediaItem2;
import android.media.MediaPlayerBase;
import android.media.MediaPlayerBase.PlaybackListener;
import android.media.MediaSession2;
import android.media.MediaSession2.Builder;
import android.media.MediaSession2.Command;
import android.media.MediaSession2.CommandButton;
import android.media.MediaSession2.CommandGroup;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.PlaylistParams;
import android.media.MediaSession2.SessionCallback;
import android.media.PlaybackState2;
import android.media.SessionToken2;
import android.media.VolumeProvider;
import android.media.session.MediaSessionManager;
import android.media.update.MediaSession2Provider;
import android.os.Bundle;
import android.os.IBinder;
import android.os.ResultReceiver;
import android.support.annotation.GuardedBy;
import android.util.Log;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

public class MediaSession2Impl implements MediaSession2Provider {
    private static final String TAG = "MediaSession2";
    private static final boolean DEBUG = true;//Log.isLoggable(TAG, Log.DEBUG);

    private final Object mLock = new Object();

    private final MediaSession2 mInstance;
    private final Context mContext;
    private final String mId;
    private final Executor mCallbackExecutor;
    private final SessionCallback mCallback;
    private final MediaSession2Stub mSessionStub;
    private final SessionToken2 mSessionToken;
    private final List<PlaybackListenerHolder> mListeners = new ArrayList<>();

    @GuardedBy("mLock")
    private MediaPlayerBase mPlayer;
    @GuardedBy("mLock")
    private MyPlaybackListener mListener;

    /**
     * Can be only called by the {@link Builder#build()}.
     * 
     * @param instance
     * @param context
     * @param player
     * @param id
     * @param callback
     * @param volumeProvider
     * @param ratingType
     * @param sessionActivity
     */
    public MediaSession2Impl(Context context, MediaSession2 instance, MediaPlayerBase player,
            String id, VolumeProvider volumeProvider, int ratingType, PendingIntent sessionActivity,
            Executor callbackExecutor, SessionCallback callback) {
        mInstance = instance;
        // TODO(jaewan): Keep other params.

        // Argument checks are done by builder already.
        // Initialize finals first.
        mContext = context;
        mId = id;
        mCallback = callback;
        mCallbackExecutor = callbackExecutor;
        mSessionStub = new MediaSession2Stub(this);
        // Ask server to create session token for following reasons.
        //   1. Make session ID unique per package.
        //      Server can only know if the package has another process and has another session
        //      with the same id. Let server check this.
        //      Note that 'ID is unique per package' is important for controller to distinguish
        //      a session in another package.
        //   2. Easier to know the type of session.
        //      Session created here can be the session service token. In order distinguish,
        //      we need to iterate AndroidManifest.xml but it's already done by the server.
        //      Let server to create token with the type.
        MediaSessionManager manager =
                (MediaSessionManager) mContext.getSystemService(Context.MEDIA_SESSION_SERVICE);
        mSessionToken = manager.createSessionToken(mContext.getPackageName(), mId, mSessionStub);
        if (mSessionToken == null) {
            throw new IllegalStateException("Session with the same id is already used by"
                    + " another process. Use MediaController2 instead.");
        }

        setPlayerInternal(player);
    }

    // TODO(jaewan): Add explicit release() and do not remove session object with the
    //               setPlayer(null). Token can be available when player is null, and
    //               controller can also attach to session.
    @Override
    public void setPlayer_impl(MediaPlayerBase player, VolumeProvider volumeProvider)
            throws IllegalArgumentException {
        ensureCallingThread();
        if (player == null) {
            throw new IllegalArgumentException("player shouldn't be null");
        }
        setPlayerInternal(player);
    }

    private void setPlayerInternal(MediaPlayerBase player) {
        synchronized (mLock) {
            if (mPlayer == player) {
                // Player didn't changed. No-op.
                return;
            }
            if (mPlayer != null && mListener != null) {
                // This might not work for a poorly implemented player.
                mPlayer.removePlaybackListener(mListener);
            }
            mListener = new MyPlaybackListener(this, player);
            player.addPlaybackListener(mCallbackExecutor, mListener);
            mPlayer = player;
        }
        notifyPlaybackStateChangedNotLocked(player.getPlaybackState());
    }

    @Override
    public void close_impl() {
        if (mSessionStub != null) {
            if (DEBUG) {
                Log.d(TAG, "session is now unavailable, id=" + mId);
            }
            // Invalidate previously published session stub.
            mSessionStub.destroyNotLocked();
        }
        synchronized (mLock) {
            if (mPlayer != null) {
                // close can be called multiple times
                mPlayer.removePlaybackListener(mListener);
                mPlayer = null;
                return;
            }
        }
    }

    @Override
    public MediaPlayerBase getPlayer_impl() {
        return getPlayer();
    }

    // TODO(jaewan): Change this to @NonNull
    @Override
    public SessionToken2 getToken_impl() {
        return mSessionToken;
    }

    @Override
    public List<ControllerInfo> getConnectedControllers_impl() {
        return mSessionStub.getControllers();
    }

    @Override
    public void setAudioAttributes_impl(AudioAttributes attributes) {
        // implement
    }

    @Override
    public void setAudioFocusRequest_impl(int focusGain) {
        // implement
    }

    @Override
    public void play_impl() {
        ensureCallingThread();
        ensurePlayer();
        mPlayer.play();
    }

    @Override
    public void pause_impl() {
        ensureCallingThread();
        ensurePlayer();
        mPlayer.pause();
    }

    @Override
    public void stop_impl() {
        ensureCallingThread();
        ensurePlayer();
        mPlayer.stop();
    }

    @Override
    public void skipToPrevious_impl() {
        ensureCallingThread();
        ensurePlayer();
        mPlayer.skipToPrevious();
    }

    @Override
    public void skipToNext_impl() {
        ensureCallingThread();
        ensurePlayer();
        mPlayer.skipToNext();
    }

    @Override
    public void setCustomLayout_impl(ControllerInfo controller, List<CommandButton> layout) {
        ensureCallingThread();
        if (controller == null) {
            throw new IllegalArgumentException("controller shouldn't be null");
        }
        if (layout == null) {
            throw new IllegalArgumentException("layout shouldn't be null");
        }
        mSessionStub.notifyCustomLayoutNotLocked(controller, layout);
    }

    //////////////////////////////////////////////////////////////////////////////////////
    // TODO(jaewan): Implement follows
    //////////////////////////////////////////////////////////////////////////////////////
    @Override
    public void setPlayer_impl(MediaPlayerBase player) {
        // TODO(jaewan): Implement
    }

    @Override
    public void setAllowedCommands_impl(ControllerInfo controller, CommandGroup commands) {
        // TODO(jaewan): Implement
    }

    @Override
    public void notifyMetadataChanged_impl() {
        // TODO(jaewan): Implement
    }

    @Override
    public void sendCustomCommand_impl(ControllerInfo controller, Command command, Bundle args,
            ResultReceiver receiver) {
        // TODO(jaewan): Implement
    }

    @Override
    public void sendCustomCommand_impl(Command command, Bundle args) {
        // TODO(jaewan): Implement
    }

    @Override
    public void setPlaylist_impl(List<MediaItem2> playlist, PlaylistParams param) {
        // TODO(jaewan): Implement
    }

    @Override
    public void prepare_impl() {
        // TODO(jaewan): Implement
    }

    @Override
    public void fastForward_impl() {
        // TODO(jaewan): Implement
    }

    @Override
    public void rewind_impl() {
        // TODO(jaewan): Implement
    }

    @Override
    public void seekTo_impl(long pos) {
        // TODO(jaewan): Implement
    }

    @Override
    public void setCurrentPlaylistItem_impl(int index) {
        // TODO(jaewan): Implement
    }

    ///////////////////////////////////////////////////
    // Protected or private methods
    ///////////////////////////////////////////////////

    // Enforces developers to call all the methods on the initially given thread
    // because calls from the MediaController2 will be run on the thread.
    // TODO(jaewan): Should we allow calls from the multiple thread?
    //               I prefer this way because allowing multiple thread may case tricky issue like
    //               b/63446360. If the {@link #setPlayer()} with {@code null} can be called from
    //               another thread, transport controls can be called after that.
    //               That's basically the developer's mistake, but they cannot understand what's
    //               happening behind until we tell them so.
    //               If enforcing callling thread doesn't look good, we can alternatively pick
    //               1. Allow calls from random threads for all methods.
    //               2. Allow calls from random threads for all methods, except for the
    //                  {@link #setPlayer()}.
    private void ensureCallingThread() {
        // TODO(jaewan): Uncomment or remove
        /*
        if (mHandler.getLooper() != Looper.myLooper()) {
            throw new IllegalStateException("Run this on the given thread");
        }*/
    }


    private void ensurePlayer() {
        // TODO(jaewan): Should we pend command instead? Follow the decision from MP2.
        //               Alternatively we can add a API like setAcceptsPendingCommands(boolean).
        if (mPlayer == null) {
            throw new IllegalStateException("Player isn't set");
        }
    }

    private void notifyPlaybackStateChangedNotLocked(PlaybackState2 state) {
        List<PlaybackListenerHolder> listeners = new ArrayList<>();
        synchronized (mLock) {
            listeners.addAll(mListeners);
        }
        // Notify to listeners added directly to this session
        for (int i = 0; i < listeners.size(); i++) {
            listeners.get(i).postPlaybackChange(state);
        }
        // Notify to controllers as well.
        mSessionStub.notifyPlaybackStateChangedNotLocked(state);
    }

    Context getContext() {
        return mContext;
    }

    MediaSession2 getInstance() {
        return mInstance;
    }

    MediaPlayerBase getPlayer() {
        return mPlayer;
    }

    Executor getCallbackExecutor() {
        return mCallbackExecutor;
    }

    SessionCallback getCallback() {
        return mCallback;
    }

    private static class MyPlaybackListener implements MediaPlayerBase.PlaybackListener {
        private final WeakReference<MediaSession2Impl> mSession;
        private final MediaPlayerBase mPlayer;

        private MyPlaybackListener(MediaSession2Impl session, MediaPlayerBase player) {
            mSession = new WeakReference<>(session);
            mPlayer = player;
        }

        @Override
        public void onPlaybackChanged(PlaybackState2 state) {
            MediaSession2Impl session = mSession.get();
            if (mPlayer != session.mInstance.getPlayer()) {
                Log.w(TAG, "Unexpected playback state change notifications. Ignoring.",
                        new IllegalStateException());
                return;
            }
            session.notifyPlaybackStateChangedNotLocked(state);
        }
    }

    public static class ControllerInfoImpl implements ControllerInfoProvider {
        private final ControllerInfo mInstance;
        private final int mUid;
        private final String mPackageName;
        private final boolean mIsTrusted;
        private final IMediaSession2Callback mControllerBinder;

        // Flag to indicate which callbacks should be returned for the controller binder.
        // Either 0 or combination of {@link #CALLBACK_FLAG_PLAYBACK},
        // {@link #CALLBACK_FLAG_SESSION_ACTIVENESS}
        private int mFlag;

        public ControllerInfoImpl(Context context, ControllerInfo instance, int uid,
                int pid, String packageName, IMediaSession2Callback callback) {
            mInstance = instance;
            mUid = uid;
            mPackageName = packageName;

            // TODO(jaewan): Remove this workaround
            if ("com.android.server.media".equals(packageName)) {
                mIsTrusted = true;
            } else if (context.checkPermission(permission.MEDIA_CONTENT_CONTROL, pid, uid) ==
                    PackageManager.PERMISSION_GRANTED) {
                mIsTrusted = true;
            } else {
                // TODO(jaewan): Also consider enabled notification listener.
                mIsTrusted = false;
                // System apps may bind across the user so uid can be differ.
                // Skip sanity check for the system app.
                try {
                    int uidForPackage = context.getPackageManager().getPackageUid(packageName, 0);
                    if (uid != uidForPackage) {
                        throw new IllegalArgumentException("Illegal call from uid=" + uid +
                                ", pkg=" + packageName + ". Expected uid" + uidForPackage);
                    }
                } catch (NameNotFoundException e) {
                    // Rethrow exception with different name because binder methods only accept
                    // RemoteException.
                    throw new IllegalArgumentException(e);
                }
            }
            mControllerBinder = callback;
        }

        @Override
        public String getPackageName_impl() {
            return mPackageName;
        }

        @Override
        public int getUid_impl() {
            return mUid;
        }

        @Override
        public boolean isTrusted_impl() {
            return mIsTrusted;
        }

        @Override
        public int hashCode_impl() {
            return mControllerBinder.hashCode();
        }

        @Override
        public boolean equals_impl(ControllerInfoProvider obj) {
            return equals(obj);
        }

        @Override
        public int hashCode() {
            return mControllerBinder.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof ControllerInfoImpl)) {
                return false;
            }
            ControllerInfoImpl other = (ControllerInfoImpl) obj;
            return mControllerBinder.asBinder().equals(other.mControllerBinder.asBinder());
        }

        public ControllerInfo getInstance() {
            return mInstance;
        }

        public IBinder getId() {
            return mControllerBinder.asBinder();
        }

        public IMediaSession2Callback getControllerBinder() {
            return mControllerBinder;
        }

        public boolean containsFlag(int flag) {
            return (mFlag & flag) != 0;
        }

        public void addFlag(int flag) {
            mFlag |= flag;
        }

        public void removeFlag(int flag) {
            mFlag &= ~flag;
        }

        public static ControllerInfoImpl from(ControllerInfo controller) {
            return (ControllerInfoImpl) controller.getProvider();
        }
    }
}
