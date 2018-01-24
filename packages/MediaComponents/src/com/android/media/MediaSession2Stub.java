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

import static com.android.media.MediaController2Impl.CALLBACK_FLAG_PLAYBACK;

import android.content.Context;
import android.media.IMediaSession2;
import android.media.IMediaSession2Callback;
import android.media.MediaLibraryService2.BrowserRoot;
import android.media.MediaLibraryService2.MediaLibrarySessionCallback;
import android.media.MediaSession2;
import android.media.MediaSession2.Command;
import android.media.MediaSession2.CommandButton;
import android.media.MediaSession2.CommandGroup;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.SessionCallback;
import android.media.PlaybackState2;
import android.media.session.PlaybackState;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.RemoteException;
import android.support.annotation.GuardedBy;
import android.util.ArrayMap;
import android.util.Log;
import com.android.media.MediaSession2Impl.ControllerInfoImpl;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;

public class MediaSession2Stub extends IMediaSession2.Stub {
    private static final String TAG = "MediaSession2Stub";
    private static final boolean DEBUG = true; // TODO(jaewan): Rename.

    private final Object mLock = new Object();
    private final CommandHandler mCommandHandler;
    private final WeakReference<MediaSession2Impl> mSession;
    private final Context mContext;
    private final SessionCallback mSessionCallback;
    private final MediaLibrarySessionCallback mLibraryCallback;

    @GuardedBy("mLock")
    private final ArrayMap<IBinder, ControllerInfo> mControllers = new ArrayMap<>();

    public MediaSession2Stub(MediaSession2Impl session, SessionCallback callback) {
        mSession = new WeakReference<>(session);
        mContext = session.getContext();
        // TODO(jaewan): Should be executor from the session builder
        mCommandHandler = new CommandHandler(session.getHandler().getLooper());
        mSessionCallback = callback;
        mLibraryCallback = (callback instanceof MediaLibrarySessionCallback)
                ? (MediaLibrarySessionCallback) callback : null;
    }

    public void destroyNotLocked() {
        final List<ControllerInfo> list;
        synchronized (mLock) {
            mSession.clear();
            mCommandHandler.removeCallbacksAndMessages(null);
            list = getControllers();
            mControllers.clear();
        }
        for (int i = 0; i < list.size(); i++) {
            IMediaSession2Callback callbackBinder =
                    ((ControllerInfoImpl) list.get(i).getProvider()).getControllerBinder();
            try {
                // Should be used without a lock hold to prevent potential deadlock.
                callbackBinder.onConnectionChanged(null, null);
            } catch (RemoteException e) {
                // Controller is gone. Should be fine because we're destroying.
            }
        }
    }

    private MediaSession2Impl getSession() throws IllegalStateException {
        final MediaSession2Impl session = mSession.get();
        if (session == null) {
            throw new IllegalStateException("Session is died");
        }
        return session;
    }

    @Override
    public void connect(String callingPackage, IMediaSession2Callback callback) {
        if (callback == null) {
            // Requesting connect without callback to receive result.
            return;
        }
        ControllerInfo request = new ControllerInfo(mContext,
                Binder.getCallingUid(), Binder.getCallingPid(), callingPackage, callback);
        mCommandHandler.postConnect(request);
    }

    @Override
    public void release(IMediaSession2Callback caller) throws RemoteException {
        synchronized (mLock) {
            ControllerInfo controllerInfo = mControllers.remove(caller.asBinder());
            if (DEBUG) {
                Log.d(TAG, "releasing " + controllerInfo);
            }
        }
    }

    @Override
    public void sendCommand(IMediaSession2Callback caller, Bundle command, Bundle args)
            throws RuntimeException {
        ControllerInfo controller = getController(caller);
        if (controller == null) {
            if (DEBUG) {
                Log.d(TAG, "Command from a controller that hasn't connected. Ignore");
            }
            return;
        }
        mCommandHandler.postCommand(controller, Command.fromBundle(command), args);
    }

    @Override
    public void getBrowserRoot(IMediaSession2Callback caller, Bundle rootHints)
            throws RuntimeException {
        if (mLibraryCallback == null) {
            if (DEBUG) {
                Log.d(TAG, "Session cannot hand getBrowserRoot()");
            }
            return;
        }
        final ControllerInfo controller = getController(caller);
        if (controller == null) {
            if (DEBUG) {
                Log.d(TAG, "getBrowerRoot from a controller that hasn't connected. Ignore");
            }
            return;
        }
        mCommandHandler.postOnGetRoot(controller, rootHints);
    }

    @Deprecated
    @Override
    public Bundle getPlaybackState() throws RemoteException {
        MediaSession2Impl session = getSession();
        // TODO(jaewan): Check if mPlayer.getPlaybackState() is safe here.
        return session.getInstance().getPlayer().getPlaybackState().toBundle();
    }

    @Deprecated
    @Override
    public void registerCallback(final IMediaSession2Callback callbackBinder,
            final int callbackFlag, final int requestCode) throws RemoteException {
        // TODO(jaewan): Call onCommand() here. To do so, you should pend message.
        synchronized (mLock) {
            ControllerInfo controllerInfo = getController(callbackBinder);
            if (controllerInfo == null) {
                return;
            }
            ControllerInfoImpl.from(controllerInfo).addFlag(callbackFlag);
        }
    }

    @Deprecated
    @Override
    public void unregisterCallback(IMediaSession2Callback callbackBinder, int callbackFlag)
            throws RemoteException {
        // TODO(jaewan): Call onCommand() here. To do so, you should pend message.
        synchronized (mLock) {
            ControllerInfo controllerInfo = getController(callbackBinder);
            if (controllerInfo == null) {
                return;
            }
            ControllerInfoImpl.from(controllerInfo).removeFlag(callbackFlag);
        }
    }

    private ControllerInfo getController(IMediaSession2Callback caller) {
        synchronized (mLock) {
            return mControllers.get(caller.asBinder());
        }
    }

    public List<ControllerInfo> getControllers() {
        ArrayList<ControllerInfo> controllers = new ArrayList<>();
        synchronized (mLock) {
            for (int i = 0; i < mControllers.size(); i++) {
                controllers.add(mControllers.valueAt(i));
            }
        }
        return controllers;
    }

    public List<ControllerInfo> getControllersWithFlag(int flag) {
        ArrayList<ControllerInfo> controllers = new ArrayList<>();
        synchronized (mLock) {
            for (int i = 0; i < mControllers.size(); i++) {
                ControllerInfo controllerInfo = mControllers.valueAt(i);
                if (ControllerInfoImpl.from(controllerInfo).containsFlag(flag)) {
                    controllers.add(controllerInfo);
                }
            }
        }
        return controllers;
    }

    // Should be used without a lock to prevent potential deadlock.
    public void notifyPlaybackStateChangedNotLocked(PlaybackState2 state) {
        final List<ControllerInfo> list = getControllersWithFlag(CALLBACK_FLAG_PLAYBACK);
        for (int i = 0; i < list.size(); i++) {
            IMediaSession2Callback callbackBinder =
                    ControllerInfoImpl.from(list.get(i)).getControllerBinder();
            try {
                callbackBinder.onPlaybackStateChanged(state.toBundle());
            } catch (RemoteException e) {
                Log.w(TAG, "Controller is gone", e);
                // TODO(jaewan): What to do when the controller is gone?
            }
        }
    }

    public void notifyCustomLayoutNotLocked(ControllerInfo controller, List<CommandButton> layout) {
        // TODO(jaewan): It's OK to be called while it's connecting, but not OK if the connection
        //               is rejected. Handle the case.
        IMediaSession2Callback callbackBinder =
                ControllerInfoImpl.from(controller).getControllerBinder();
        try {
            List<Bundle> layoutBundles = new ArrayList<>();
            for (int i = 0; i < layout.size(); i++) {
                Bundle bundle = layout.get(i).toBundle();
                if (bundle != null) {
                    layoutBundles.add(bundle);
                }
            }
            callbackBinder.onCustomLayoutChanged(layoutBundles);
        } catch (RemoteException e) {
            Log.w(TAG, "Controller is gone", e);
            // TODO(jaewan): What to do when the controller is gone?
        }
    }

    // TODO(jaewan): Remove this. We should use Executor given by the session builder.
    private class CommandHandler extends Handler {
        public static final int MSG_CONNECT = 1000;
        public static final int MSG_COMMAND = 1001;
        public static final int MSG_ON_GET_ROOT = 2000;

        public CommandHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            final MediaSession2Impl session = MediaSession2Stub.this.mSession.get();
            if (session == null || session.getPlayer() == null) {
                return;
            }

            switch (msg.what) {
                case MSG_CONNECT: {
                    ControllerInfo request = (ControllerInfo) msg.obj;
                    CommandGroup allowedCommands = mSessionCallback.onConnect(request);
                    // Don't reject connection for the request from trusted app.
                    // Otherwise server will fail to retrieve session's information to dispatch
                    // media keys to.
                    boolean accept = allowedCommands != null || request.isTrusted();
                    ControllerInfoImpl impl = ControllerInfoImpl.from(request);
                    if (accept) {
                        synchronized (mLock) {
                            mControllers.put(impl.getId(), request);
                        }
                        if (allowedCommands == null) {
                            // For trusted apps, send non-null allowed commands to keep connection.
                            allowedCommands = new CommandGroup();
                        }
                    }
                    if (DEBUG) {
                        Log.d(TAG, "onConnectResult, request=" + request
                                + " accept=" + accept);
                    }
                    try {
                        impl.getControllerBinder().onConnectionChanged(
                                accept ? MediaSession2Stub.this : null,
                                allowedCommands == null ? null : allowedCommands.toBundle());
                    } catch (RemoteException e) {
                        // Controller may be died prematurely.
                    }
                    break;
                }
                case MSG_COMMAND: {
                    CommandParam param = (CommandParam) msg.obj;
                    Command command = param.command;
                    boolean accepted = mSessionCallback.onCommandRequest(
                            param.controller, command);
                    if (!accepted) {
                        // Don't run rejected command.
                        if (DEBUG) {
                            Log.d(TAG, "Command " + command + " from "
                                    + param.controller + " was rejected by " + session);
                        }
                        return;
                    }

                    switch (param.command.getCommandCode()) {
                        case MediaSession2.COMMAND_CODE_PLAYBACK_START:
                            session.getInstance().play();
                            break;
                        case MediaSession2.COMMAND_CODE_PLAYBACK_PAUSE:
                            session.getInstance().pause();
                            break;
                        case MediaSession2.COMMAND_CODE_PLAYBACK_STOP:
                            session.getInstance().stop();
                            break;
                        case MediaSession2.COMMAND_CODE_PLAYBACK_SKIP_PREV_ITEM:
                            session.getInstance().skipToPrevious();
                            break;
                        case MediaSession2.COMMAND_CODE_PLAYBACK_SKIP_NEXT_ITEM:
                            session.getInstance().skipToNext();
                            break;
                        default:
                            // TODO(jaewan): Handle custom command.
                    }
                    break;
                }
                case MSG_ON_GET_ROOT: {
                    final CommandParam param = (CommandParam) msg.obj;
                    final ControllerInfoImpl controller = ControllerInfoImpl.from(param.controller);
                    BrowserRoot root = mLibraryCallback.onGetRoot(param.controller, param.args);
                    try {
                        controller.getControllerBinder().onGetRootResult(param.args,
                                root == null ? null : root.getRootId(),
                                root == null ? null : root.getExtras());
                    } catch (RemoteException e) {
                        // Controller may be died prematurely.
                        // TODO(jaewan): Handle this.
                    }
                    break;
                }
            }
        }

        public void postConnect(ControllerInfo request) {
            obtainMessage(MSG_CONNECT, request).sendToTarget();
        }

        public void postCommand(ControllerInfo controller, Command command, Bundle args) {
            CommandParam param = new CommandParam(controller, command, args);
            obtainMessage(MSG_COMMAND, param).sendToTarget();
        }

        public void postOnGetRoot(ControllerInfo controller, Bundle rootHints) {
            CommandParam param = new CommandParam(controller, null, rootHints);
            obtainMessage(MSG_ON_GET_ROOT, param).sendToTarget();
        }
    }

    private static class CommandParam {
        public final ControllerInfo controller;
        public final Command command;
        public final Bundle args;

        private CommandParam(ControllerInfo controller, Command command, Bundle args) {
            this.controller = controller;
            this.command = command;
            this.args = args;
        }
    }
}
