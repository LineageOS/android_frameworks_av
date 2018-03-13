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
import android.content.Context;
import android.media.MediaController2;
import android.media.MediaItem2;
import android.media.MediaLibraryService2.LibraryRoot;
import android.media.MediaMetadata2;
import android.media.MediaSession2;
import android.media.MediaSession2.Command;
import android.media.MediaSession2.CommandButton;
import android.media.MediaSession2.CommandGroup;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.PlaylistParams;
import android.media.PlaybackState2;
import android.media.Rating2;
import android.media.VolumeProvider2;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ResultReceiver;
import android.support.annotation.GuardedBy;
import android.text.TextUtils;
import android.util.ArrayMap;
import android.util.Log;

import com.android.media.MediaLibraryService2Impl.MediaLibrarySessionImpl;
import com.android.media.MediaSession2Impl.CommandButtonImpl;
import com.android.media.MediaSession2Impl.ControllerInfoImpl;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MediaSession2Stub extends IMediaSession2.Stub {

    static final String ARGUMENT_KEY_POSITION = "android.media.media_session2.key_position";
    static final String ARGUMENT_KEY_ITEM_INDEX = "android.media.media_session2.key_item_index";
    static final String ARGUMENT_KEY_PLAYLIST_PARAMS =
            "android.media.media_session2.key_playlist_params";

    private static final String TAG = "MediaSession2Stub";
    private static final boolean DEBUG = true; // TODO(jaewan): Rename.

    private final Object mLock = new Object();
    private final WeakReference<MediaSession2Impl> mSession;

    @GuardedBy("mLock")
    private final ArrayMap<IBinder, ControllerInfo> mControllers = new ArrayMap<>();
    @GuardedBy("mLock")
    private final Set<IBinder> mConnectingControllers = new HashSet<>();
    @GuardedBy("mLock")
    private final ArrayMap<ControllerInfo, CommandGroup> mAllowedCommandGroupMap = new ArrayMap<>();
    @GuardedBy("mLock")
    private final ArrayMap<ControllerInfo, Set<String>> mSubscriptions = new ArrayMap<>();

    public MediaSession2Stub(MediaSession2Impl session) {
        mSession = new WeakReference<>(session);
    }

    public void destroyNotLocked() {
        final List<ControllerInfo> list;
        synchronized (mLock) {
            mSession.clear();
            list = getControllers();
            mControllers.clear();
        }
        for (int i = 0; i < list.size(); i++) {
            IMediaSession2Callback controllerBinder =
                    ((ControllerInfoImpl) list.get(i).getProvider()).getControllerBinder();
            try {
                // Should be used without a lock hold to prevent potential deadlock.
                controllerBinder.onDisconnected();
            } catch (RemoteException e) {
                // Controller is gone. Should be fine because we're destroying.
            }
        }
    }

    private MediaSession2Impl getSession() {
        final MediaSession2Impl session = mSession.get();
        if (session == null && DEBUG) {
            Log.d(TAG, "Session is closed", new IllegalStateException());
        }
        return session;
    }

    private MediaLibrarySessionImpl getLibrarySession() throws IllegalStateException {
        final MediaSession2Impl session = getSession();
        if (!(session instanceof MediaLibrarySessionImpl)) {
            throw new RuntimeException("Session isn't a library session");
        }
        return (MediaLibrarySessionImpl) session;
    }

    // Get controller if the command from caller to session is able to be handled.
    private ControllerInfo getControllerIfAble(IMediaSession2Callback caller) {
        synchronized (mLock) {
            final ControllerInfo controllerInfo = mControllers.get(caller.asBinder());
            if (controllerInfo == null && DEBUG) {
                Log.d(TAG, "Controller is disconnected", new IllegalStateException());
            }
            return controllerInfo;
        }
    }

    // Get controller if the command from caller to session is able to be handled.
    private ControllerInfo getControllerIfAble(IMediaSession2Callback caller, int commandCode) {
        synchronized (mLock) {
            final ControllerInfo controllerInfo = getControllerIfAble(caller);
            if (controllerInfo == null) {
                return null;
            }
            CommandGroup allowedCommands = mAllowedCommandGroupMap.get(controllerInfo);
            if (allowedCommands == null) {
                Log.w(TAG, "Controller with null allowed commands. Ignoring",
                        new IllegalStateException());
                return null;
            }
            if (!allowedCommands.hasCommand(commandCode)) {
                if (DEBUG) {
                    Log.d(TAG, "Controller isn't allowed for command " + commandCode);
                }
                return null;
            }
            return controllerInfo;
        }
    }

    // Get controller if the command from caller to session is able to be handled.
    private ControllerInfo getControllerIfAble(IMediaSession2Callback caller, Command command) {
        synchronized (mLock) {
            final ControllerInfo controllerInfo = getControllerIfAble(caller);
            if (controllerInfo == null) {
                return null;
            }
            CommandGroup allowedCommands = mAllowedCommandGroupMap.get(controllerInfo);
            if (allowedCommands == null) {
                Log.w(TAG, "Controller with null allowed commands. Ignoring",
                        new IllegalStateException());
                return null;
            }
            if (!allowedCommands.hasCommand(command)) {
                if (DEBUG) {
                    Log.d(TAG, "Controller isn't allowed for command " + command);
                }
                return null;
            }
            return controllerInfo;
        }
    }

    // Return binder if the session is able to send a command to the controller.
    private IMediaSession2Callback getControllerBinderIfAble(ControllerInfo controller) {
        if (getSession() == null) {
            // getSession() already logged if session is closed.
            return null;
        }
        final ControllerInfoImpl impl = ControllerInfoImpl.from(controller);
        synchronized (mLock) {
            if (mControllers.get(impl.getId()) != null
                    || mConnectingControllers.contains(impl.getId())) {
                return impl.getControllerBinder();
            }
            if (DEBUG) {
                Log.d(TAG, controller + " isn't connected nor connecting",
                        new IllegalArgumentException());
            }
            return null;
        }
    }

    // Return binder if the session is able to send a command to the controller.
    private IMediaSession2Callback getControllerBinderIfAble(ControllerInfo controller,
            int commandCode) {
        synchronized (mLock) {
            CommandGroup allowedCommands = mAllowedCommandGroupMap.get(controller);
            if (allowedCommands == null) {
                Log.w(TAG, "Controller with null allowed commands. Ignoring");
                return null;
            }
            if (!allowedCommands.hasCommand(commandCode)) {
                if (DEBUG) {
                    Log.d(TAG, "Controller isn't allowed for command " + commandCode);
                }
                return null;
            }
            return getControllerBinderIfAble(controller);
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    // AIDL methods for session overrides
    //////////////////////////////////////////////////////////////////////////////////////////////
    @Override
    public void connect(final IMediaSession2Callback caller, final String callingPackage)
            throws RuntimeException {
        final MediaSession2Impl session = getSession();
        if (session == null) {
            return;
        }
        final Context context = session.getContext();
        final ControllerInfo controllerInfo = new ControllerInfo(context,
                Binder.getCallingUid(), Binder.getCallingPid(), callingPackage, caller);
        session.getCallbackExecutor().execute(() -> {
            if (getSession() == null) {
                return;
            }
            synchronized (mLock) {
                // Keep connecting controllers.
                // This helps sessions to call APIs in the onConnect() (e.g. setCustomLayout())
                // instead of pending them.
                mConnectingControllers.add(ControllerInfoImpl.from(controllerInfo).getId());
            }
            CommandGroup allowedCommands = session.getCallback().onConnect(
                    session.getInstance(), controllerInfo);
            // Don't reject connection for the request from trusted app.
            // Otherwise server will fail to retrieve session's information to dispatch
            // media keys to.
            boolean accept = allowedCommands != null || controllerInfo.isTrusted();
            if (accept) {
                ControllerInfoImpl controllerImpl = ControllerInfoImpl.from(controllerInfo);
                if (DEBUG) {
                    Log.d(TAG, "Accepting connection, controllerInfo=" + controllerInfo
                            + " allowedCommands=" + allowedCommands);
                }
                if (allowedCommands == null) {
                    // For trusted apps, send non-null allowed commands to keep connection.
                    allowedCommands = new CommandGroup(context);
                }
                synchronized (mLock) {
                    mConnectingControllers.remove(controllerImpl.getId());
                    mControllers.put(controllerImpl.getId(),  controllerInfo);
                    mAllowedCommandGroupMap.put(controllerInfo, allowedCommands);
                }
                // If connection is accepted, notify the current state to the controller.
                // It's needed because we cannot call synchronous calls between session/controller.
                // Note: We're doing this after the onConnectionChanged(), but there's no guarantee
                //       that events here are notified after the onConnected() because
                //       IMediaSession2Callback is oneway (i.e. async call) and CallbackStub will
                //       use thread poll for incoming calls.
                // TODO(jaewan): Should we protect getting playback state?
                final PlaybackState2 state = session.getInstance().getPlaybackState();
                final Bundle playbackStateBundle = (state != null) ? state.toBundle() : null;
                final Bundle playbackInfoBundle = ((MediaController2Impl.PlaybackInfoImpl)
                        session.getPlaybackInfo().getProvider()).toBundle();
                final PlaylistParams params = session.getInstance().getPlaylistParams();
                final Bundle paramsBundle = (params != null) ? params.toBundle() : null;
                final PendingIntent sessionActivity = session.getSessionActivity();
                final List<MediaItem2> playlist =
                        allowedCommands.hasCommand(MediaSession2.COMMAND_CODE_PLAYLIST_GET_LIST)
                                ? session.getInstance().getPlaylist() : null;
                final List<Bundle> playlistBundle;
                if (playlist != null) {
                    playlistBundle = new ArrayList<>();
                    // TODO(jaewan): Find a way to avoid concurrent modification exception.
                    for (int i = 0; i < playlist.size(); i++) {
                        final MediaItem2 item = playlist.get(i);
                        if (item != null) {
                            final Bundle itemBundle = item.toBundle();
                            if (itemBundle != null) {
                                playlistBundle.add(itemBundle);
                            }
                        }
                    }
                } else {
                    playlistBundle = null;
                }

                // Double check if session is still there, because close() can be called in another
                // thread.
                if (getSession() == null) {
                    return;
                }
                try {
                    caller.onConnected(MediaSession2Stub.this,
                            allowedCommands.toBundle(), playbackStateBundle, playbackInfoBundle,
                            paramsBundle, playlistBundle, sessionActivity);
                } catch (RemoteException e) {
                    // Controller may be died prematurely.
                    // TODO(jaewan): Handle here.
                }
            } else {
                synchronized (mLock) {
                    mConnectingControllers.remove(ControllerInfoImpl.from(controllerInfo).getId());
                }
                if (DEBUG) {
                    Log.d(TAG, "Rejecting connection, controllerInfo=" + controllerInfo);
                }
                try {
                    caller.onDisconnected();
                } catch (RemoteException e) {
                    // Controller may be died prematurely.
                    // Not an issue because we'll ignore it anyway.
                }
            }
        });
    }

    @Override
    public void release(final IMediaSession2Callback caller) throws RemoteException {
        ControllerInfo controller;
        synchronized (mLock) {
            controller = mControllers.remove(caller.asBinder());
            if (DEBUG) {
                Log.d(TAG, "releasing " + controller);
            }
            mSubscriptions.remove(controller);
        }
        final MediaSession2Impl session = getSession();
        if (session == null || controller == null) {
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            session.getCallback().onDisconnected(session.getInstance(), controller);
        });
    }

    @Override
    public void setVolumeTo(final IMediaSession2Callback caller, final int value, final int flags)
            throws RuntimeException {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_PLAYBACK_SET_VOLUME);
        if (session == null || controller == null) {
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller, MediaSession2.COMMAND_CODE_PLAYBACK_SET_VOLUME) == null) {
                return;
            }
            // TODO(jaewan): Sanity check.
            Command command = new Command(
                    session.getContext(), MediaSession2.COMMAND_CODE_PLAYBACK_SET_VOLUME);
            boolean accepted = session.getCallback().onCommandRequest(session.getInstance(),
                    controller, command);
            if (!accepted) {
                // Don't run rejected command.
                if (DEBUG) {
                    Log.d(TAG, "Command " + MediaSession2.COMMAND_CODE_PLAYBACK_SET_VOLUME + " from "
                            + controller + " was rejected by " + session);
                }
                return;
            }

            VolumeProvider2 volumeProvider = session.getVolumeProvider();
            if (volumeProvider == null) {
                // TODO(jaewan): Set local stream volume
            } else {
                volumeProvider.onSetVolumeTo(value);
            }
        });
    }

    @Override
    public void adjustVolume(IMediaSession2Callback caller, int direction, int flags)
            throws RuntimeException {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_PLAYBACK_SET_VOLUME);
        if (session == null || controller == null) {
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller, MediaSession2.COMMAND_CODE_PLAYBACK_SET_VOLUME) == null) {
                return;
            }
            // TODO(jaewan): Sanity check.
            Command command = new Command(
                    session.getContext(), MediaSession2.COMMAND_CODE_PLAYBACK_SET_VOLUME);
            boolean accepted = session.getCallback().onCommandRequest(session.getInstance(),
                    controller, command);
            if (!accepted) {
                // Don't run rejected command.
                if (DEBUG) {
                    Log.d(TAG, "Command " + MediaSession2.COMMAND_CODE_PLAYBACK_SET_VOLUME + " from "
                            + controller + " was rejected by " + session);
                }
                return;
            }

            VolumeProvider2 volumeProvider = session.getVolumeProvider();
            if (volumeProvider == null) {
                // TODO(jaewan): Adjust local stream volume
            } else {
                volumeProvider.onAdjustVolume(direction);
            }
        });
    }

    @Override
    public void sendTransportControlCommand(IMediaSession2Callback caller,
            int commandCode, Bundle args) throws RuntimeException {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(caller, commandCode);
        if (session == null || controller == null) {
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller, commandCode) == null) {
                return;
            }
            // TODO(jaewan): Sanity check.
            Command command = new Command(session.getContext(), commandCode);
            boolean accepted = session.getCallback().onCommandRequest(session.getInstance(),
                    controller, command);
            if (!accepted) {
                // Don't run rejected command.
                if (DEBUG) {
                    Log.d(TAG, "Command " + commandCode + " from "
                            + controller + " was rejected by " + session);
                }
                return;
            }

            switch (commandCode) {
                case MediaSession2.COMMAND_CODE_PLAYBACK_PLAY:
                    session.getInstance().play();
                    break;
                case MediaSession2.COMMAND_CODE_PLAYBACK_PAUSE:
                    session.getInstance().pause();
                    break;
                case MediaSession2.COMMAND_CODE_PLAYBACK_STOP:
                    session.getInstance().stop();
                    break;
                case MediaSession2.COMMAND_CODE_PLAYBACK_SKIP_PREV_ITEM:
                    session.getInstance().skipToPreviousItem();
                    break;
                case MediaSession2.COMMAND_CODE_PLAYBACK_SKIP_NEXT_ITEM:
                    session.getInstance().skipToNextItem();
                    break;
                case MediaSession2.COMMAND_CODE_PLAYBACK_PREPARE:
                    session.getInstance().prepare();
                    break;
                case MediaSession2.COMMAND_CODE_PLAYBACK_FAST_FORWARD:
                    session.getInstance().fastForward();
                    break;
                case MediaSession2.COMMAND_CODE_PLAYBACK_REWIND:
                    session.getInstance().rewind();
                    break;
                case MediaSession2.COMMAND_CODE_PLAYBACK_SEEK_TO:
                    session.getInstance().seekTo(args.getLong(ARGUMENT_KEY_POSITION));
                    break;
                case MediaSession2.COMMAND_CODE_PLAYLIST_SKIP_TO_PLAYLIST_ITEM:
                    // TODO(jaewan): Implement
                    /*
                    session.getInstance().skipToPlaylistItem(
                            args.getInt(ARGUMENT_KEY_ITEM_INDEX));
                    */
                    break;
                    // TODO(jaewan): Remove (b/74116823)
                    /*
                case MediaSession2.COMMAND_CODE_PLAYBACK_SET_PLAYLIST_PARAMS:
                    session.getInstance().setPlaylistParams(
                            PlaylistParams.fromBundle(session.getContext(),
                                    args.getBundle(ARGUMENT_KEY_PLAYLIST_PARAMS)));
                    break;
                    */
                default:
                    // TODO(jaewan): Resend unknown (new) commands through the custom command.
            }
        });
    }

    @Override
    public void sendCustomCommand(final IMediaSession2Callback caller, final Bundle commandBundle,
            final Bundle args, final ResultReceiver receiver) {
        final MediaSession2Impl session = getSession();
        if (session == null) {
            return;
        }
        final Command command = Command.fromBundle(session.getContext(), commandBundle);
        if (command == null) {
            Log.w(TAG, "sendCustomCommand(): Ignoring null command from "
                    + getControllerIfAble(caller));
            return;
        }
        final ControllerInfo controller = getControllerIfAble(caller, command);
        if (controller == null) {
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller, command) == null) {
                return;
            }
            session.getCallback().onCustomCommand(session.getInstance(),
                    controller, command, args, receiver);
        });
    }

    @Override
    public void prepareFromUri(final IMediaSession2Callback caller, final Uri uri,
            final Bundle extras) {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_PREPARE_FROM_URI);
        if (session == null || controller == null) {
            return;
        }
        if (uri == null) {
            Log.w(TAG, "prepareFromUri(): Ignoring null uri from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(
                    caller, MediaSession2.COMMAND_CODE_PREPARE_FROM_URI) == null) {
                return;
            }
            session.getCallback().onPrepareFromUri(session.getInstance(),
                    controller, uri, extras);
        });
    }

    @Override
    public void prepareFromSearch(final IMediaSession2Callback caller, final String query,
            final Bundle extras) {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_PREPARE_FROM_SEARCH);
        if (session == null || controller == null) {
            return;
        }
        if (TextUtils.isEmpty(query)) {
            Log.w(TAG, "prepareFromSearch(): Ignoring empty query from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(
                    caller, MediaSession2.COMMAND_CODE_PREPARE_FROM_SEARCH) == null) {
                return;
            }
            session.getCallback().onPrepareFromSearch(session.getInstance(),
                    controller, query, extras);
        });
    }

    @Override
    public void prepareFromMediaId(final IMediaSession2Callback caller, final String mediaId,
            final Bundle extras) {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_PREPARE_FROM_MEDIA_ID);
        if (session == null || controller == null) {
            return;
        }
        if (mediaId == null) {
            Log.w(TAG, "prepareFromMediaId(): Ignoring null mediaId from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(
                    caller, MediaSession2.COMMAND_CODE_PREPARE_FROM_MEDIA_ID) == null) {
                return;
            }
            session.getCallback().onPrepareFromMediaId(session.getInstance(),
                    controller, mediaId, extras);
        });
    }

    @Override
    public void playFromUri(final IMediaSession2Callback caller, final Uri uri,
            final Bundle extras) {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_PLAY_FROM_URI);
        if (session == null || controller == null) {
            return;
        }
        if (uri == null) {
            Log.w(TAG, "playFromUri(): Ignoring null uri from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(
                    caller, MediaSession2.COMMAND_CODE_PLAY_FROM_URI) == null) {
                return;
            }
            session.getCallback().onPlayFromUri(session.getInstance(), controller, uri, extras);
        });
    }

    @Override
    public void playFromSearch(final IMediaSession2Callback caller, final String query,
            final Bundle extras) {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_PLAY_FROM_SEARCH);
        if (session == null || controller == null) {
            return;
        }
        if (TextUtils.isEmpty(query)) {
            Log.w(TAG, "playFromSearch(): Ignoring empty query from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(
                    caller, MediaSession2.COMMAND_CODE_PLAY_FROM_SEARCH) == null) {
                return;
            }
            session.getCallback().onPlayFromSearch(session.getInstance(),
                    controller, query, extras);
        });
    }

    @Override
    public void playFromMediaId(final IMediaSession2Callback caller, final String mediaId,
            final Bundle extras) {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_PLAY_FROM_MEDIA_ID);
        if (session == null || controller == null) {
            return;
        }
        if (mediaId == null) {
            Log.w(TAG, "playFromMediaId(): Ignoring null mediaId from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (session == null) {
                return;
            }
            session.getCallback().onPlayFromMediaId(session.getInstance(),
                    controller, mediaId, extras);
        });
    }

    @Override
    public void setRating(final IMediaSession2Callback caller, final String mediaId,
            final Bundle ratingBundle) {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(caller);
        if (session == null || controller == null) {
            return;
        }
        if (mediaId == null) {
            Log.w(TAG, "setRating(): Ignoring null mediaId from " + controller);
            return;
        }
        if (ratingBundle == null) {
            Log.w(TAG, "setRating(): Ignoring null ratingBundle from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller) == null) {
                return;
            }
            Rating2 rating = Rating2Impl.fromBundle(session.getContext(), ratingBundle);
            if (rating == null) {
                if (ratingBundle == null) {
                    Log.w(TAG, "setRating(): Ignoring null rating from " + controller);
                    return;
                }
                return;
            }
            session.getCallback().onSetRating(session.getInstance(), controller, mediaId, rating);
        });
    }

    @Override
    public void setPlaylist(final IMediaSession2Callback caller, final List<Bundle> playlist,
            final Bundle metadata) {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_PLAYLIST_SET_LIST);
        if (session == null || controller == null) {
            return;
        }
        if (playlist == null) {
            Log.w(TAG, "setPlaylist(): Ignoring null playlist from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(
                    caller, MediaSession2.COMMAND_CODE_PLAYLIST_SET_LIST) == null) {
                return;
            }
            Command command = new Command(session.getContext(),
                    MediaSession2.COMMAND_CODE_PLAYLIST_SET_LIST);
            boolean accepted = session.getCallback().onCommandRequest(session.getInstance(),
                    controller, command);
            if (!accepted) {
                // Don't run rejected command.
                if (DEBUG) {
                    Log.d(TAG, "setPlaylist() from " + controller + " was rejected");
                }
                return;
            }
            List<MediaItem2> list = new ArrayList<>();
            for (int i = 0; i < playlist.size(); i++) {
                MediaItem2 item = MediaItem2.fromBundle(session.getContext(), playlist.get(i));
                if (item != null) {
                    list.add(item);
                }
            }
            session.getInstance().setPlaylist(list,
                    MediaMetadata2.fromBundle(session.getContext(), metadata));
        });
    }

    @Override
    public void updatePlaylistMetadata(final IMediaSession2Callback caller, final Bundle metadata) {
        final MediaSession2Impl session = getSession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_PLAYLIST_SET_LIST_METADATA);
        if (session == null || controller == null) {
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(
                    caller, MediaSession2.COMMAND_CODE_PLAYLIST_SET_LIST_METADATA) == null) {
                return;
            }
            Command command = new Command(session.getContext(),
                    MediaSession2.COMMAND_CODE_PLAYLIST_SET_LIST_METADATA);
            boolean accepted = session.getCallback().onCommandRequest(session.getInstance(),
                    controller, command);
            if (!accepted) {
                // Don't run rejected command.
                if (DEBUG) {
                    Log.d(TAG, "setPlaylist() from " + controller + " was rejected");
                }
                return;
            }
            session.getInstance().updatePlaylistMetadata(
                    MediaMetadata2.fromBundle(session.getContext(), metadata));
        });
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    // AIDL methods for LibrarySession overrides
    //////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public void getLibraryRoot(final IMediaSession2Callback caller, final Bundle rootHints)
            throws RuntimeException {
        final MediaLibrarySessionImpl session = getLibrarySession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_BROWSER);
        if (session == null || controller == null) {
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller, MediaSession2.COMMAND_CODE_BROWSER) == null) {
                return;
            }
            LibraryRoot root = session.getCallback().onGetLibraryRoot(session.getInstance(),
                    controller, rootHints);
            try {
                caller.onGetLibraryRootDone(rootHints,
                        root == null ? null : root.getRootId(),
                        root == null ? null : root.getExtras());
            } catch (RemoteException e) {
                // Controller may be died prematurely.
                // TODO(jaewan): Handle this.
            }
        });
    }

    @Override
    public void getItem(final IMediaSession2Callback caller, final String mediaId)
            throws RuntimeException {
        if (mediaId == null) {
            if (DEBUG) {
                Log.d(TAG, "mediaId shouldn't be null");
            }
            return;
        }
        final MediaLibrarySessionImpl session = getLibrarySession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_BROWSER);
        if (session == null || controller == null) {
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller, MediaSession2.COMMAND_CODE_BROWSER) == null) {
                return;
            }
            MediaItem2 result = session.getCallback().onGetItem(session.getInstance(),
                    controller, mediaId);
            try {
                caller.onGetItemDone(mediaId, result == null ? null : result.toBundle());
            } catch (RemoteException e) {
                // Controller may be died prematurely.
                // TODO(jaewan): Handle this.
            }
        });
    }

    @Override
    public void getChildren(final IMediaSession2Callback caller, final String parentId,
            final int page, final int pageSize, final Bundle extras) throws RuntimeException {
        if (parentId == null) {
            if (DEBUG) {
                Log.d(TAG, "parentId shouldn't be null");
            }
            return;
        }
        if (page < 1 || pageSize < 1) {
            if (DEBUG) {
                Log.d(TAG, "Neither page nor pageSize should be less than 1");
            }
            return;
        }
        final MediaLibrarySessionImpl session = getLibrarySession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_BROWSER);
        if (session == null || controller == null) {
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller, MediaSession2.COMMAND_CODE_BROWSER) == null) {
                return;
            }
            List<MediaItem2> result = session.getCallback().onGetChildren(session.getInstance(),
                    controller, parentId, page, pageSize, extras);
            if (result != null && result.size() > pageSize) {
                throw new IllegalArgumentException("onGetChildren() shouldn't return media items "
                        + "more than pageSize. result.size()=" + result.size() + " pageSize="
                        + pageSize);
            }
            List<Bundle> bundleList = null;
            if (result != null) {
                bundleList = new ArrayList<>();
                for (MediaItem2 item : result) {
                    bundleList.add(item == null ? null : item.toBundle());
                }
            }
            try {
                caller.onGetChildrenDone(parentId, page, pageSize, bundleList, extras);
            } catch (RemoteException e) {
                // Controller may be died prematurely.
                // TODO(jaewan): Handle this.
            }
        });
    }

    @Override
    public void search(IMediaSession2Callback caller, String query, Bundle extras) {
        final MediaLibrarySessionImpl session = getLibrarySession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_BROWSER);
        if (session == null || controller == null) {
            return;
        }
        if (TextUtils.isEmpty(query)) {
            Log.w(TAG, "search(): Ignoring empty query from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller, MediaSession2.COMMAND_CODE_BROWSER) == null) {
                return;
            }
            session.getCallback().onSearch(session.getInstance(), controller, query, extras);
        });
    }

    @Override
    public void getSearchResult(final IMediaSession2Callback caller, final String query,
            final int page, final int pageSize, final Bundle extras) {
        final MediaLibrarySessionImpl session = getLibrarySession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_BROWSER);
        if (session == null || controller == null) {
            return;
        }
        if (TextUtils.isEmpty(query)) {
            Log.w(TAG, "getSearchResult(): Ignoring empty query from " + controller);
            return;
        }
        if (page < 1 || pageSize < 1) {
            Log.w(TAG, "getSearchResult(): Ignoring negative page / pageSize."
                    + " page=" + page + " pageSize=" + pageSize + " from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller, MediaSession2.COMMAND_CODE_BROWSER) == null) {
                return;
            }
            List<MediaItem2> result = session.getCallback().onGetSearchResult(session.getInstance(),
                    controller, query, page, pageSize, extras);
            if (result != null && result.size() > pageSize) {
                throw new IllegalArgumentException("onGetSearchResult() shouldn't return media "
                        + "items more than pageSize. result.size()=" + result.size() + " pageSize="
                        + pageSize);
            }
            List<Bundle> bundleList = null;
            if (result != null) {
                bundleList = new ArrayList<>();
                for (MediaItem2 item : result) {
                    bundleList.add(item == null ? null : item.toBundle());
                }
            }

            try {
                caller.onGetSearchResultDone(query, page, pageSize, bundleList, extras);
            } catch (RemoteException e) {
                // Controller may be died prematurely.
                // TODO(jaewan): Handle this.
            }
        });
    }

    @Override
    public void subscribe(final IMediaSession2Callback caller, final String parentId,
            final Bundle option) {
        final MediaLibrarySessionImpl session = getLibrarySession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_BROWSER);
        if (session == null || controller == null) {
            return;
        }
        if (parentId == null) {
            Log.w(TAG, "subscribe(): Ignoring null parentId from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller, MediaSession2.COMMAND_CODE_BROWSER) == null) {
                return;
            }
            session.getCallback().onSubscribe(session.getInstance(),
                    controller, parentId, option);
            synchronized (mLock) {
                Set<String> subscription = mSubscriptions.get(controller);
                if (subscription == null) {
                    subscription = new HashSet<>();
                    mSubscriptions.put(controller, subscription);
                }
                subscription.add(parentId);
            }
        });
    }

    @Override
    public void unsubscribe(final IMediaSession2Callback caller, final String parentId) {
        final MediaLibrarySessionImpl session = getLibrarySession();
        final ControllerInfo controller = getControllerIfAble(
                caller, MediaSession2.COMMAND_CODE_BROWSER);
        if (session == null || controller == null) {
            return;
        }
        if (parentId == null) {
            Log.w(TAG, "unsubscribe(): Ignoring null parentId from " + controller);
            return;
        }
        session.getCallbackExecutor().execute(() -> {
            if (getControllerIfAble(caller, MediaSession2.COMMAND_CODE_BROWSER) == null) {
                return;
            }
            session.getCallback().onUnsubscribe(session.getInstance(), controller, parentId);
            synchronized (mLock) {
                mSubscriptions.remove(controller);
            }
        });
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    // APIs for MediaSession2Impl
    //////////////////////////////////////////////////////////////////////////////////////////////

    // TODO(jaewan): Need a way to get controller with permissions
    public List<ControllerInfo> getControllers() {
        ArrayList<ControllerInfo> controllers = new ArrayList<>();
        synchronized (mLock) {
            for (int i = 0; i < mControllers.size(); i++) {
                controllers.add(mControllers.valueAt(i));
            }
        }
        return controllers;
    }

    // Should be used without a lock to prevent potential deadlock.
    public void notifyPlaybackStateChangedNotLocked(PlaybackState2 state) {
        final List<ControllerInfo> list = getControllers();
        for (int i = 0; i < list.size(); i++) {
            final IMediaSession2Callback controllerBinder = getControllerBinderIfAble(list.get(i));
            if (controllerBinder == null) {
                return;
            }
            try {
                final Bundle bundle = state != null ? state.toBundle() : null;
                controllerBinder.onPlaybackStateChanged(bundle);
            } catch (RemoteException e) {
                Log.w(TAG, "Controller is gone", e);
                // TODO(jaewan): What to do when the controller is gone?
            }
        }
    }

    public void notifyCustomLayoutNotLocked(ControllerInfo controller, List<CommandButton> layout) {
        final IMediaSession2Callback controllerBinder = getControllerBinderIfAble(controller);
        if (controllerBinder == null) {
            return;
        }
        try {
            List<Bundle> layoutBundles = new ArrayList<>();
            for (int i = 0; i < layout.size(); i++) {
                Bundle bundle = ((CommandButtonImpl) layout.get(i).getProvider()).toBundle();
                if (bundle != null) {
                    layoutBundles.add(bundle);
                }
            }
            controllerBinder.onCustomLayoutChanged(layoutBundles);
        } catch (RemoteException e) {
            Log.w(TAG, "Controller is gone", e);
            // TODO(jaewan): What to do when the controller is gone?
        }
    }

    public void notifyPlaylistChangedNotLocked(List<MediaItem2> playlist, MediaMetadata2 metadata) {
        final List<Bundle> bundleList;
        if (playlist != null) {
            bundleList = new ArrayList<>();
            for (int i = 0; i < playlist.size(); i++) {
                if (playlist.get(i) != null) {
                    Bundle bundle = playlist.get(i).toBundle();
                    if (bundle != null) {
                        bundleList.add(bundle);
                    }
                }
            }
        } else {
            bundleList = null;
        }
        final Bundle metadataBundle = (metadata == null) ? null : metadata.toBundle();
        final List<ControllerInfo> list = getControllers();
        for (int i = 0; i < list.size(); i++) {
            final IMediaSession2Callback controllerBinder = getControllerBinderIfAble(
                    list.get(i), MediaSession2.COMMAND_CODE_PLAYLIST_GET_LIST);
            if (controllerBinder != null) {
                try {
                    controllerBinder.onPlaylistChanged(bundleList, metadataBundle);
                } catch (RemoteException e) {
                    Log.w(TAG, "Controller is gone", e);
                    // TODO(jaewan): What to do when the controller is gone?
                }
            } else {
                final IMediaSession2Callback binder = getControllerBinderIfAble(
                        list.get(i), MediaSession2.COMMAND_CODE_PLAYLIST_GET_LIST_METADATA);
                if (binder != null) {
                    try {
                        binder.onPlaylistMetadataChanged(metadataBundle);
                    } catch (RemoteException e) {
                        Log.w(TAG, "Controller is gone", e);
                        // TODO(jaewan): What to do when the controller is gone?
                    }
                }
            }
        }
    }

    public void notifyPlaylistMetadataChangedNotLocked(MediaMetadata2 metadata) {
        final Bundle metadataBundle = (metadata == null) ? null : metadata.toBundle();
        final List<ControllerInfo> list = getControllers();
        for (int i = 0; i < list.size(); i++) {
            final IMediaSession2Callback controllerBinder = getControllerBinderIfAble(
                    list.get(i), MediaSession2.COMMAND_CODE_PLAYLIST_GET_LIST_METADATA);
            if (controllerBinder != null) {
                try {
                    controllerBinder.onPlaylistMetadataChanged(metadataBundle);
                } catch (RemoteException e) {
                    Log.w(TAG, "Controller is gone", e);
                    // TODO(jaewan): What to do when the controller is gone?
                }
            }
        }
    }

    public void notifyPlaylistParamsChanged(MediaSession2.PlaylistParams params) {
        final List<ControllerInfo> list = getControllers();
        for (int i = 0; i < list.size(); i++) {
            final IMediaSession2Callback controllerBinder = getControllerBinderIfAble(list.get(i));
            if (controllerBinder == null) {
                return;
            }
            try {
                controllerBinder.onPlaylistParamsChanged(params.toBundle());
            } catch (RemoteException e) {
                Log.w(TAG, "Controller is gone", e);
                // TODO(jaewan): What to do when the controller is gone?
            }
        }
    }

    public void notifyPlaybackInfoChanged(MediaController2.PlaybackInfo playbackInfo) {
        final List<ControllerInfo> list = getControllers();
        for (int i = 0; i < list.size(); i++) {
            final IMediaSession2Callback controllerBinder = getControllerBinderIfAble(list.get(i));
            if (controllerBinder == null) {
                return;
            }
            try {
                controllerBinder.onPlaybackInfoChanged(((MediaController2Impl.PlaybackInfoImpl)
                        playbackInfo.getProvider()).toBundle());
            } catch (RemoteException e) {
                Log.w(TAG, "Controller is gone", e);
                // TODO(jaewan): What to do when the controller is gone?
            }
        }
    }

    public void setAllowedCommands(ControllerInfo controller, CommandGroup commands) {
        synchronized (mLock) {
            mAllowedCommandGroupMap.put(controller, commands);
        }
        final IMediaSession2Callback controllerBinder = getControllerBinderIfAble(controller);
        if (controllerBinder == null) {
            return;
        }
        try {
            controllerBinder.onAllowedCommandsChanged(commands.toBundle());
        } catch (RemoteException e) {
            Log.w(TAG, "Controller is gone", e);
            // TODO(jaewan): What to do when the controller is gone?
        }
    }

    public void sendCustomCommand(ControllerInfo controller, Command command, Bundle args,
            ResultReceiver receiver) {
        if (receiver != null && controller == null) {
            throw new IllegalArgumentException("Controller shouldn't be null if result receiver is"
                    + " specified");
        }
        if (command == null) {
            throw new IllegalArgumentException("command shouldn't be null");
        }
        sendCustomCommandInternal(controller, command, args, receiver);
    }

    public void sendCustomCommand(Command command, Bundle args) {
        if (command == null) {
            throw new IllegalArgumentException("command shouldn't be null");
        }
        final List<ControllerInfo> controllers = getControllers();
        for (int i = 0; i < controllers.size(); i++) {
            sendCustomCommand(controllers.get(i), command, args, null);
        }
    }

    private void sendCustomCommandInternal(ControllerInfo controller, Command command, Bundle args,
            ResultReceiver receiver) {
        final IMediaSession2Callback controllerBinder = getControllerBinderIfAble(controller);
        if (controllerBinder == null) {
            return;
        }
        try {
            Bundle commandBundle = command.toBundle();
            controllerBinder.onCustomCommand(commandBundle, args, receiver);
        } catch (RemoteException e) {
            Log.w(TAG, "Controller is gone", e);
            // TODO(jaewan): What to do when the controller is gone?
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    // APIs for MediaLibrarySessionImpl
    //////////////////////////////////////////////////////////////////////////////////////////////

    public void notifySearchResultChanged(ControllerInfo controller, String query, int itemCount,
            Bundle extras) {
        final IMediaSession2Callback controllerBinder = getControllerBinderIfAble(controller);
        if (controllerBinder == null) {
            return;
        }
        try {
            controllerBinder.onSearchResultChanged(query, itemCount, extras);
        } catch (RemoteException e) {
            Log.w(TAG, "Controller is gone", e);
            // TODO(jaewan): What to do when the controller is gone?
        }
    }

    public void notifyChildrenChangedNotLocked(ControllerInfo controller, String parentId,
            int itemCount, Bundle extras) {
        notifyChildrenChangedInternalNotLocked(controller, parentId, itemCount, extras);
    }

    public void notifyChildrenChangedNotLocked(String parentId, int itemCount, Bundle extras) {
        final List<ControllerInfo> controllers = getControllers();
        for (int i = 0; i < controllers.size(); i++) {
            notifyChildrenChangedInternalNotLocked(controllers.get(i), parentId, itemCount,
                    extras);
        }
    }

    public void notifyChildrenChangedInternalNotLocked(final ControllerInfo controller,
            String parentId, int itemCount, Bundle extras) {
        // Ensure subscription
        synchronized (mLock) {
            Set<String> subscriptions = mSubscriptions.get(controller);
            if (subscriptions == null || !subscriptions.contains(parentId)) {
                return;
            }
        }
        final IMediaSession2Callback controllerBinder = getControllerBinderIfAble(controller);
        if (controller == null) {
            return;
        }
        try {
            controllerBinder.onChildrenChanged(parentId, itemCount, extras);
        } catch (RemoteException e) {
            // TODO(jaewan): Handle controller removed?
        }
    }
}
