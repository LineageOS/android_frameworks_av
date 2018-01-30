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

import static android.media.SessionToken2.TYPE_LIBRARY_SERVICE;
import static android.media.SessionToken2.TYPE_SESSION;
import static android.media.SessionToken2.TYPE_SESSION_SERVICE;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.Manifest.permission;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.ResolveInfo;
import android.media.MediaItem2;
import android.media.MediaLibraryService2;
import android.media.MediaPlayerInterface;
import android.media.MediaPlayerInterface.PlaybackListener;
import android.media.MediaSession2;
import android.media.MediaSession2.Builder;
import android.media.MediaSession2.Command;
import android.media.MediaSession2.CommandButton;
import android.media.MediaSession2.CommandGroup;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.PlaylistParams;
import android.media.MediaSession2.SessionCallback;
import android.media.MediaSessionService2;
import android.media.PlaybackState2;
import android.media.SessionToken2;
import android.media.VolumeProvider;
import android.media.session.MediaSessionManager;
import android.media.update.MediaSession2Provider;
import android.os.Bundle;
import android.os.Process;
import android.os.IBinder;
import android.os.ResultReceiver;
import android.support.annotation.GuardedBy;
import android.text.TextUtils;
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
    private MediaPlayerInterface mPlayer;
    @GuardedBy("mLock")
    private MyPlaybackListener mListener;
    @GuardedBy("mLock")
    private PlaylistParams mPlaylistParams;
    @GuardedBy("mLock")
    private List<MediaItem2> mPlaylist;

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
    public MediaSession2Impl(Context context, MediaSession2 instance, MediaPlayerInterface player,
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

        // Infer type from the id and package name.
        String libraryService = getServiceName(context, MediaLibraryService2.SERVICE_INTERFACE, id);
        String sessionService = getServiceName(context, MediaSessionService2.SERVICE_INTERFACE, id);
        if (sessionService != null && libraryService != null) {
            throw new IllegalArgumentException("Ambiguous session type. Multiple"
                    + " session services define the same id=" + id);
        } else if (libraryService != null) {
            mSessionToken = new SessionToken2Impl(context, Process.myUid(), TYPE_LIBRARY_SERVICE,
                    mContext.getPackageName(), libraryService, id, mSessionStub).getInstance();
        } else if (sessionService != null) {
            mSessionToken = new SessionToken2Impl(context, Process.myUid(), TYPE_SESSION_SERVICE,
                    mContext.getPackageName(), sessionService, id, mSessionStub).getInstance();
        } else {
            mSessionToken = new SessionToken2Impl(context, Process.myUid(), TYPE_SESSION,
                    mContext.getPackageName(), null, id, mSessionStub).getInstance();
        }

        // Only remember player. Actual settings will be done in the initialize().
        mPlayer = player;
    }

    private static String getServiceName(Context context, String serviceAction, String id) {
        PackageManager manager = context.getPackageManager();
        Intent serviceIntent = new Intent(serviceAction);
        serviceIntent.setPackage(context.getPackageName());
        List<ResolveInfo> services = manager.queryIntentServices(serviceIntent,
                PackageManager.GET_META_DATA);
        String serviceName = null;
        if (services != null) {
            for (int i = 0; i < services.size(); i++) {
                String serviceId = SessionToken2Impl.getSessionId(services.get(i));
                if (serviceId != null && TextUtils.equals(id, serviceId)) {
                    if (services.get(i).serviceInfo == null) {
                        continue;
                    }
                    if (serviceName != null) {
                        throw new IllegalArgumentException("Ambiguous session type. Multiple"
                                + " session services define the same id=" + id);
                    }
                    serviceName = services.get(i).serviceInfo.name;
                }
            }
        }
        return serviceName;
    }

    @Override
    public void initialize() {
        synchronized (mLock) {
            setPlayerLocked(mPlayer);
        }
        // Ask server for the sanity check, and starts
        // Sanity check for making session ID unique 'per package' cannot be done in here.
        // Server can only know if the package has another process and has another session with the
        // same id. Note that 'ID is unique per package' is important for controller to distinguish
        // a session in another package.
        MediaSessionManager manager =
                (MediaSessionManager) mContext.getSystemService(Context.MEDIA_SESSION_SERVICE);
        if (!manager.onSessionCreated(mSessionToken)) {
            throw new IllegalStateException("Session with the same id is already used by"
                    + " another process. Use MediaController2 instead.");
        }
    }

    // TODO(jaewan): Add explicit release() and do not remove session object with the
    //               setPlayer(null). Token can be available when player is null, and
    //               controller can also attach to session.
    @Override
    public void setPlayer_impl(MediaPlayerInterface player, VolumeProvider volumeProvider)
            throws IllegalArgumentException {
        ensureCallingThread();
        if (player == null) {
            throw new IllegalArgumentException("player shouldn't be null");
        }
        if (player == mPlayer) {
            return;
        }
        synchronized (mLock) {
            setPlayerLocked(player);
        }
    }

    private void setPlayerLocked(MediaPlayerInterface player) {
        if (mPlayer != null && mListener != null) {
            // This might not work for a poorly implemented player.
            mPlayer.removePlaybackListener(mListener);
        }
        mPlayer = player;
        mListener = new MyPlaybackListener(this, player);
        player.addPlaybackListener(mCallbackExecutor, mListener);
    }

    @Override
    public void close_impl() {
        // Stop system service from listening this session first.
        MediaSessionManager manager =
                (MediaSessionManager) mContext.getSystemService(Context.MEDIA_SESSION_SERVICE);
        manager.onSessionDestroyed(mSessionToken);

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
            }
        }
    }

    @Override
    public MediaPlayerInterface getPlayer_impl() {
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

    @Override
    public void setPlaylistParams_impl(PlaylistParams params) {
        if (params == null) {
            throw new IllegalArgumentException("PlaylistParams should not be null!");
        }
        ensureCallingThread();
        ensurePlayer();
        synchronized (mLock) {
            mPlaylistParams = params;
        }
        mPlayer.setPlaylistParams(params);
        mSessionStub.notifyPlaylistParamsChanged(params);
    }

    @Override
    public PlaylistParams getPlaylistParams_impl() {
        // TODO: Do we need to synchronize here for preparing Controller2.setPlaybackParams?
        return mPlaylistParams;
    }

    //////////////////////////////////////////////////////////////////////////////////////
    // TODO(jaewan): Implement follows
    //////////////////////////////////////////////////////////////////////////////////////
    @Override
    public void setPlayer_impl(MediaPlayerInterface player) {
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
        mSessionStub.sendCustomCommand(controller, command, args, receiver);
    }

    @Override
    public void sendCustomCommand_impl(Command command, Bundle args) {
        mSessionStub.sendCustomCommand(command, args);
    }

    @Override
    public void setPlaylist_impl(List<MediaItem2> playlist) {
        if (playlist == null) {
            throw new IllegalArgumentException("Playlist should not be null!");
        }
        ensureCallingThread();
        ensurePlayer();
        synchronized (mLock) {
            mPlaylist = playlist;
        }
        mPlayer.setPlaylist(playlist);
        mSessionStub.notifyPlaylistChanged(playlist);
    }

    @Override
    public List<MediaItem2> getPlaylist_impl() {
        synchronized (mLock) {
            return mPlaylist;
        }
    }

    @Override
    public void prepare_impl() {
        ensureCallingThread();
        ensurePlayer();
        mPlayer.prepare();
    }

    @Override
    public void fastForward_impl() {
        ensureCallingThread();
        ensurePlayer();
        mPlayer.fastForward();
    }

    @Override
    public void rewind_impl() {
        ensureCallingThread();
        ensurePlayer();
        mPlayer.rewind();
    }

    @Override
    public void seekTo_impl(long pos) {
        ensureCallingThread();
        ensurePlayer();
        mPlayer.seekTo(pos);
    }

    @Override
    public void setCurrentPlaylistItem_impl(int index) {
        ensureCallingThread();
        ensurePlayer();
        mPlayer.setCurrentPlaylistItem(index);
    }

    @Override
    public void addPlaybackListener_impl(Executor executor, PlaybackListener listener) {
        if (executor == null) {
            throw new IllegalArgumentException("executor shouldn't be null");
        }
        if (listener == null) {
            throw new IllegalArgumentException("listener shouldn't be null");
        }
        ensureCallingThread();
        if (PlaybackListenerHolder.contains(mListeners, listener)) {
            Log.w(TAG, "listener is already added. Ignoring.");
            return;
        }
        mListeners.add(new PlaybackListenerHolder(executor, listener));
        executor.execute(() -> listener.onPlaybackChanged(getInstance().getPlaybackState()));
    }

    @Override
    public void removePlaybackListener_impl(PlaybackListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener shouldn't be null");
        }
        ensureCallingThread();
        int idx = PlaybackListenerHolder.indexOf(mListeners, listener);
        if (idx >= 0) {
            mListeners.remove(idx);
        }
    }

    @Override
    public PlaybackState2 getPlaybackState_impl() {
        ensureCallingThread();
        ensurePlayer();
        // TODO(jaewan): Is it safe to be called on any thread?
        //               Otherwise we should cache the result from listener.
        return mPlayer.getPlaybackState();
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

    MediaPlayerInterface getPlayer() {
        return mPlayer;
    }

    Executor getCallbackExecutor() {
        return mCallbackExecutor;
    }

    SessionCallback getCallback() {
        return mCallback;
    }

    private static class MyPlaybackListener implements MediaPlayerInterface.PlaybackListener {
        private final WeakReference<MediaSession2Impl> mSession;
        private final MediaPlayerInterface mPlayer;

        private MyPlaybackListener(MediaSession2Impl session, MediaPlayerInterface player) {
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

    public static final class CommandImpl implements CommandProvider {
        private static final String KEY_COMMAND_CODE
                = "android.media.media_session2.command.command_code";
        private static final String KEY_COMMAND_CUSTOM_COMMAND
                = "android.media.media_session2.command.custom_command";
        private static final String KEY_COMMAND_EXTRA
                = "android.media.media_session2.command.extra";

        private final Command mInstance;
        private final int mCommandCode;
        // Nonnull if it's custom command
        private final String mCustomCommand;
        private final Bundle mExtra;

        public CommandImpl(Command instance, int commandCode) {
            mInstance = instance;
            mCommandCode = commandCode;
            mCustomCommand = null;
            mExtra = null;
        }

        public CommandImpl(Command instance, @NonNull String action, @Nullable Bundle extra) {
            if (action == null) {
                throw new IllegalArgumentException("action shouldn't be null");
            }
            mInstance = instance;
            mCommandCode = MediaSession2.COMMAND_CODE_CUSTOM;
            mCustomCommand = action;
            mExtra = extra;
        }

        public int getCommandCode_impl() {
            return mCommandCode;
        }

        public @Nullable String getCustomCommand_impl() {
            return mCustomCommand;
        }

        public @Nullable Bundle getExtra_impl() {
            return mExtra;
        }

        /**
         * @ 7return a new Bundle instance from the Command
         */
        public Bundle toBundle_impl() {
            Bundle bundle = new Bundle();
            bundle.putInt(KEY_COMMAND_CODE, mCommandCode);
            bundle.putString(KEY_COMMAND_CUSTOM_COMMAND, mCustomCommand);
            bundle.putBundle(KEY_COMMAND_EXTRA, mExtra);
            return bundle;
        }

        /**
         * @return a new Command instance from the Bundle
         */
        public static Command fromBundle_impl(Context context, Bundle command) {
            int code = command.getInt(KEY_COMMAND_CODE);
            if (code != MediaSession2.COMMAND_CODE_CUSTOM) {
                return new Command(context, code);
            } else {
                String customCommand = command.getString(KEY_COMMAND_CUSTOM_COMMAND);
                if (customCommand == null) {
                    return null;
                }
                return new Command(context, customCommand, command.getBundle(KEY_COMMAND_EXTRA));
            }
        }

        @Override
        public boolean equals_impl(Object obj) {
            if (!(obj instanceof CommandImpl)) {
                return false;
            }
            CommandImpl other = (CommandImpl) obj;
            // TODO(jaewan): Should we also compare contents in bundle?
            //               It may not be possible if the bundle contains private class.
            return mCommandCode == other.mCommandCode
                    && TextUtils.equals(mCustomCommand, other.mCustomCommand);
        }

        @Override
        public int hashCode_impl() {
            final int prime = 31;
            return ((mCustomCommand != null)
                    ? mCustomCommand.hashCode() : 0) * prime + mCommandCode;
        }
    }

    public static class ControllerInfoImpl implements ControllerInfoProvider {
        private final ControllerInfo mInstance;
        private final int mUid;
        private final String mPackageName;
        private final boolean mIsTrusted;
        private final IMediaSession2Callback mControllerBinder;

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

        public static ControllerInfoImpl from(ControllerInfo controller) {
            return (ControllerInfoImpl) controller.getProvider();
        }
    }
}
