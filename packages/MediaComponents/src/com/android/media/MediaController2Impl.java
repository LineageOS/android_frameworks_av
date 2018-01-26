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

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.media.IMediaSession2;
import android.media.IMediaSession2Callback;
import android.media.MediaController2.PlaybackInfo;
import android.media.MediaItem2;
import android.media.MediaSession2;
import android.media.MediaSession2.Command;
import android.media.MediaSession2.CommandButton;
import android.media.MediaSession2.CommandGroup;
import android.media.MediaController2;
import android.media.MediaController2.ControllerCallback;
import android.media.MediaSession2.PlaylistParams;
import android.media.MediaSessionService2;
import android.media.PlaybackState2;
import android.media.Rating2;
import android.media.SessionToken2;
import android.media.update.MediaController2Provider;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ResultReceiver;
import android.support.annotation.GuardedBy;
import android.util.Log;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

public class MediaController2Impl implements MediaController2Provider {
    private static final String TAG = "MediaController2";
    private static final boolean DEBUG = true; // TODO(jaewan): Change

    private final MediaController2 mInstance;

    /**
     * Flag used by MediaController2Record to filter playback callback.
     */
    static final int CALLBACK_FLAG_PLAYBACK = 0x1;

    static final int REQUEST_CODE_ALL = 0;

    private final Object mLock = new Object();

    private final Context mContext;
    private final MediaSession2CallbackStub mSessionCallbackStub;
    private final SessionToken2 mToken;
    private final ControllerCallback mCallback;
    private final Executor mCallbackExecutor;
    private final IBinder.DeathRecipient mDeathRecipient;

    @GuardedBy("mLock")
    private final List<PlaybackListenerHolder> mPlaybackListeners = new ArrayList<>();
    @GuardedBy("mLock")
    private SessionServiceConnection mServiceConnection;
    @GuardedBy("mLock")
    private boolean mIsReleased;

    // Assignment should be used with the lock hold, but should be used without a lock to prevent
    // potential deadlock.
    // Postfix -Binder is added to explicitly show that it's potentially remote process call.
    // Technically -Interface is more correct, but it may misread that it's interface (vs class)
    // so let's keep this postfix until we find better postfix.
    @GuardedBy("mLock")
    private volatile IMediaSession2 mSessionBinder;

    // TODO(jaewan): Require session activeness changed listener, because controller can be
    //               available when the session's player is null.
    public MediaController2Impl(Context context, MediaController2 instance, SessionToken2 token,
            Executor executor, ControllerCallback callback) {
        mInstance = instance;

        if (context == null) {
            throw new IllegalArgumentException("context shouldn't be null");
        }
        if (token == null) {
            throw new IllegalArgumentException("token shouldn't be null");
        }
        if (callback == null) {
            throw new IllegalArgumentException("callback shouldn't be null");
        }
        if (executor == null) {
            throw new IllegalArgumentException("executor shouldn't be null");
        }
        mContext = context;
        mSessionCallbackStub = new MediaSession2CallbackStub(this);
        mToken = token;
        mCallback = callback;
        mCallbackExecutor = executor;
        mDeathRecipient = () -> {
            mInstance.close();
        };

        mSessionBinder = null;

        if (token.getSessionBinder() == null) {
            mServiceConnection = new SessionServiceConnection();
            connectToService();
        } else {
            mServiceConnection = null;
            connectToSession(token.getSessionBinder());
        }
    }

    // Should be only called by constructor.
    private void connectToService() {
        // Service. Needs to get fresh binder whenever connection is needed.
        final Intent intent = new Intent(MediaSessionService2.SERVICE_INTERFACE);
        intent.setClassName(mToken.getPackageName(), mToken.getServiceName());

        // Use bindService() instead of startForegroundService() to start session service for three
        // reasons.
        // 1. Prevent session service owner's stopSelf() from destroying service.
        //    With the startForegroundService(), service's call of stopSelf() will trigger immediate
        //    onDestroy() calls on the main thread even when onConnect() is running in another
        //    thread.
        // 2. Minimize APIs for developers to take care about.
        //    With bindService(), developers only need to take care about Service.onBind()
        //    but Service.onStartCommand() should be also taken care about with the
        //    startForegroundService().
        // 3. Future support for UI-less playback
        //    If a service wants to keep running, it should be either foreground service or
        //    bounded service. But there had been request for the feature for system apps
        //    and using bindService() will be better fit with it.
        // TODO(jaewan): Use bindServiceAsUser()??
        boolean result = mContext.bindService(intent, mServiceConnection, Context.BIND_AUTO_CREATE);
        if (!result) {
            Log.w(TAG, "bind to " + mToken + " failed");
        } else if (DEBUG) {
            Log.d(TAG, "bind to " + mToken + " success");
        }
    }

    private void connectToSession(IMediaSession2 sessionBinder) {
        try {
            sessionBinder.connect(mContext.getPackageName(), mSessionCallbackStub);
        } catch (RemoteException e) {
            Log.w(TAG, "Failed to call connection request. Framework will retry"
                    + " automatically");
        }
    }

    @Override
    public void close_impl() {
        if (DEBUG) {
            Log.d(TAG, "relese from " + mToken);
        }
        final IMediaSession2 binder;
        synchronized (mLock) {
            if (mIsReleased) {
                // Prevent re-enterance from the ControllerCallback.onDisconnected()
                return;
            }
            mIsReleased = true;
            if (mServiceConnection != null) {
                mContext.unbindService(mServiceConnection);
                mServiceConnection = null;
            }
            mPlaybackListeners.clear();
            binder = mSessionBinder;
            mSessionBinder = null;
            mSessionCallbackStub.destroy();
        }
        if (binder != null) {
            try {
                binder.asBinder().unlinkToDeath(mDeathRecipient, 0);
                binder.release(mSessionCallbackStub);
            } catch (RemoteException e) {
                // No-op.
            }
        }
        mCallbackExecutor.execute(() -> {
            mCallback.onDisconnected();
        });
    }

    IMediaSession2 getSessionBinder() {
        return mSessionBinder;
    }

    MediaSession2CallbackStub getControllerStub() {
        return mSessionCallbackStub;
    }

    Executor getCallbackExecutor() {
        return mCallbackExecutor;
    }

    @Override
    public SessionToken2 getSessionToken_impl() {
        return mToken;
    }

    @Override
    public boolean isConnected_impl() {
        final IMediaSession2 binder = mSessionBinder;
        return binder != null;
    }

    @Override
    public void play_impl() {
        sendTransportControlCommand(MediaSession2.COMMAND_CODE_PLAYBACK_START);
    }

    @Override
    public void pause_impl() {
        sendTransportControlCommand(MediaSession2.COMMAND_CODE_PLAYBACK_PAUSE);
    }

    @Override
    public void stop_impl() {
        sendTransportControlCommand(MediaSession2.COMMAND_CODE_PLAYBACK_STOP);
    }

    @Override
    public void skipToPrevious_impl() {
        sendTransportControlCommand(MediaSession2.COMMAND_CODE_PLAYBACK_SKIP_PREV_ITEM);
    }

    @Override
    public void skipToNext_impl() {
        sendTransportControlCommand(MediaSession2.COMMAND_CODE_PLAYBACK_SKIP_NEXT_ITEM);
    }

    private void sendTransportControlCommand(int commandCode) {
        sendTransportControlCommand(commandCode, 0);
    }

    private void sendTransportControlCommand(int commandCode, long arg) {
        final IMediaSession2 binder = mSessionBinder;
        if (binder != null) {
            try {
                binder.sendTransportControlCommand(mSessionCallbackStub, commandCode, arg);
            } catch (RemoteException e) {
                Log.w(TAG, "Cannot connect to the service or the session is gone", e);
            }
        } else {
            Log.w(TAG, "Session isn't active", new IllegalStateException());
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////
    // TODO(jaewan): Implement follows
    //////////////////////////////////////////////////////////////////////////////////////
    @Override
    public PendingIntent getSessionActivity_impl() {
        // TODO(jaewan): Implement
        return null;
    }

    @Override
    public int getRatingType_impl() {
        // TODO(jaewan): Implement
        return 0;
    }

    @Override
    public void setVolumeTo_impl(int value, int flags) {
        // TODO(jaewan): Implement
    }

    @Override
    public void adjustVolume_impl(int direction, int flags) {
        // TODO(jaewan): Implement
    }

    @Override
    public PlaybackInfo getPlaybackInfo_impl() {
        // TODO(jaewan): Implement
        return null;
    }

    @Override
    public void prepareFromUri_impl(Uri uri, Bundle extras) {
        // TODO(jaewan): Implement
    }

    @Override
    public void prepareFromSearch_impl(String query, Bundle extras) {
        // TODO(jaewan): Implement
    }

    @Override
    public void prepareMediaId_impl(String mediaId, Bundle extras) {
        // TODO(jaewan): Implement
    }

    @Override
    public void playFromSearch_impl(String query, Bundle extras) {
        // TODO(jaewan): Implement
    }

    @Override
    public void playFromUri_impl(String uri, Bundle extras) {
        // TODO(jaewan): Implement
    }

    @Override
    public void playFromMediaId_impl(String mediaId, Bundle extras) {
        // TODO(jaewan): Implement
    }

    @Override
    public void setRating_impl(Rating2 rating) {
        // TODO(jaewan): Implement
    }

    @Override
    public void sendCustomCommand_impl(Command command, Bundle args, ResultReceiver cb) {
        // TODO(jaewan): Implement
    }

    @Override
    public List<MediaItem2> getPlaylist_impl() {
        // TODO(jaewan): Implement
        return null;
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

    @Override
    public PlaybackState2 getPlaybackState_impl() {
        // TODO(jaewan): Implement
        return null;
    }

    @Override
    public void removePlaylistItem_impl(MediaItem2 index) {
        // TODO(jaewan): Implement
    }

    @Override
    public void addPlaylistItem_impl(int index, MediaItem2 item) {
    // TODO(jaewan): Implement
    }

    @Override
    public PlaylistParams getPlaylistParam_impl() {
        // TODO(jaewan): Implement
        return null;
    }

    ///////////////////////////////////////////////////
    // Protected or private methods
    ///////////////////////////////////////////////////
    // Should be used without a lock to prevent potential deadlock.
    private void registerCallbackForPlaybackNotLocked() {
        final IMediaSession2 binder = mSessionBinder;
        if (binder != null) {
            try {
                binder.registerCallback(mSessionCallbackStub,
                        CALLBACK_FLAG_PLAYBACK, REQUEST_CODE_ALL);
            } catch (RemoteException e) {
                Log.e(TAG, "Cannot connect to the service or the session is gone", e);
            }
        }
    }

    private void pushPlaybackStateChanges(final PlaybackState2 state) {
        synchronized (mLock) {
            for (int i = 0; i < mPlaybackListeners.size(); i++) {
                mPlaybackListeners.get(i).postPlaybackChange(state);
            }
        }
    }

    // Called when the result for connecting to the session was delivered.
    // Should be used without a lock to prevent potential deadlock.
    private void onConnectionChangedNotLocked(IMediaSession2 sessionBinder,
            CommandGroup commandGroup) {
        if (DEBUG) {
            Log.d(TAG, "onConnectionChangedNotLocked sessionBinder=" + sessionBinder
                    + ", commands=" + commandGroup);
        }
        boolean release = false;
        try {
            if (sessionBinder == null || commandGroup == null) {
                // Connection rejected.
                release = true;
                return;
            }
            boolean registerCallbackForPlaybackNeeded;
            synchronized (mLock) {
                if (mIsReleased) {
                    return;
                }
                if (mSessionBinder != null) {
                    Log.e(TAG, "Cannot be notified about the connection result many times."
                            + " Probably a bug or malicious app.");
                    release = true;
                    return;
                }
                mSessionBinder = sessionBinder;
                try {
                    // Implementation for the local binder is no-op,
                    // so can be used without worrying about deadlock.
                    mSessionBinder.asBinder().linkToDeath(mDeathRecipient, 0);
                } catch (RemoteException e) {
                    if (DEBUG) {
                        Log.d(TAG, "Session died too early.", e);
                    }
                    release = true;
                    return;
                }
                registerCallbackForPlaybackNeeded = !mPlaybackListeners.isEmpty();
            }
            // TODO(jaewan): Keep commands to prevents illegal API calls.
            mCallbackExecutor.execute(() -> {
                mCallback.onConnected(commandGroup);
            });
            if (registerCallbackForPlaybackNeeded) {
                registerCallbackForPlaybackNotLocked();
            }
        } finally {
            if (release) {
                // Trick to call release() without holding the lock, to prevent potential deadlock
                // with the developer's custom lock within the ControllerCallback.onDisconnected().
                mInstance.close();
            }
        }
    }

    // TODO(jaewan): Pull out this from the controller2, and rename it to the MediaController2Stub
    //               or MediaBrowser2Stub.
    static class MediaSession2CallbackStub extends IMediaSession2Callback.Stub {
        private final WeakReference<MediaController2Impl> mController;

        private MediaSession2CallbackStub(MediaController2Impl controller) {
            mController = new WeakReference<>(controller);
        }

        private MediaController2Impl getController() throws IllegalStateException {
            final MediaController2Impl controller = mController.get();
            if (controller == null) {
                throw new IllegalStateException("Controller is released");
            }
            return controller;
        }

        // TODO(jaewan): Refactor code to get rid of these pattern.
        private MediaBrowser2Impl getBrowser() throws IllegalStateException {
            final MediaController2Impl controller = getController();
            if (controller instanceof MediaBrowser2Impl) {
                return (MediaBrowser2Impl) controller;
            }
            return null;
        }

        public void destroy() {
            mController.clear();
        }

        @Override
        public void onPlaybackStateChanged(Bundle state) throws RuntimeException {
            final MediaController2Impl controller = getController();
            controller.pushPlaybackStateChanges(PlaybackState2.fromBundle(state));
        }

        @Override
        public void onConnectionChanged(IMediaSession2 sessionBinder, Bundle commandGroup)
                throws RuntimeException {
            final MediaController2Impl controller;
            try {
                controller = getController();
            } catch (IllegalStateException e) {
                Log.w(TAG, "Don't fail silently here. Highly likely a bug");
                return;
            }
            controller.onConnectionChangedNotLocked(
                    sessionBinder, CommandGroup.fromBundle(commandGroup));
        }

        @Override
        public void onGetRootResult(Bundle rootHints, String rootMediaId, Bundle rootExtra)
                throws RuntimeException {
            final MediaBrowser2Impl browser;
            try {
                browser = getBrowser();
            } catch (IllegalStateException e) {
                Log.w(TAG, "Don't fail silently here. Highly likely a bug");
                return;
            }
            if (browser == null) {
                // TODO(jaewan): Revisit here. Could be a bug
                return;
            }
            browser.onGetRootResult(rootHints, rootMediaId, rootExtra);
        }

        @Override
        public void onCustomLayoutChanged(List<Bundle> commandButtonlist) {
            if (commandButtonlist == null) {
                // Illegal call. Ignore
                return;
            }
            final MediaBrowser2Impl browser;
            try {
                browser = getBrowser();
            } catch (IllegalStateException e) {
                Log.w(TAG, "Don't fail silently here. Highly likely a bug");
                return;
            }
            if (browser == null) {
                // TODO(jaewan): Revisit here. Could be a bug
                return;
            }
            List<CommandButton> layout = new ArrayList<>();
            for (int i = 0; i < commandButtonlist.size(); i++) {
                CommandButton button = CommandButton.fromBundle(commandButtonlist.get(i));
                if (button != null) {
                    layout.add(button);
                }
            }
            browser.onCustomLayoutChanged(layout);
        }
    }

    // This will be called on the main thread.
    private class SessionServiceConnection implements ServiceConnection {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            // Note that it's always main-thread.
            if (DEBUG) {
                Log.d(TAG, "onServiceConnected " + name + " " + this);
            }
            // Sanity check
            if (!mToken.getPackageName().equals(name.getPackageName())) {
                Log.wtf(TAG, name + " was connected, but expected pkg="
                        + mToken.getPackageName() + " with id=" + mToken.getId());
                return;
            }
            final IMediaSession2 sessionBinder = IMediaSession2.Stub.asInterface(service);
            connectToSession(sessionBinder);
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            // Temporal lose of the binding because of the service crash. System will automatically
            // rebind, so just no-op.
            // TODO(jaewan): Really? Either disconnect cleanly or
            if (DEBUG) {
                Log.w(TAG, "Session service " + name + " is disconnected.");
            }
        }

        @Override
        public void onBindingDied(ComponentName name) {
            // Permanent lose of the binding because of the service package update or removed.
            // This SessionServiceRecord will be removed accordingly, but forget session binder here
            // for sure.
            mInstance.close();
        }
    }
}
