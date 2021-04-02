/*
 * Copyright (C) 2020 The Android Open Source Project
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
package com.android.media.samplevideoencoder;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import android.Manifest;
import android.app.Activity;

import android.content.Context;
import android.content.pm.PackageManager;

import android.graphics.Matrix;
import android.graphics.RectF;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CameraMetadata;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.graphics.SurfaceTexture;
import android.media.MediaCodecInfo;
import android.media.MediaFormat;
import android.media.MediaRecorder;

import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.view.Surface;
import android.view.View;
import android.view.TextureView;
import android.widget.Button;
import android.widget.CheckBox;

import java.io.File;
import java.io.IOException;

import android.util.Log;
import android.util.Size;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.util.Comparator;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

public class MainActivity extends AppCompatActivity
        implements View.OnClickListener, ActivityCompat.OnRequestPermissionsResultCallback {

    private static final String TAG = "SampleVideoEncoder";
    private static final String[] RECORD_PERMISSIONS =
            {Manifest.permission.CAMERA, Manifest.permission.RECORD_AUDIO};
    private static final int REQUEST_RECORD_PERMISSIONS = 1;
    private final Semaphore mCameraOpenCloseLock = new Semaphore(1);
    private static final int VIDEO_BITRATE = 8000000 /* 8 Mbps */;
    private static final int VIDEO_FRAMERATE = 30;

    /**
     * Constant values to frame types assigned here are internal to this app.
     * These values does not correspond to the actual values defined in avc/hevc specifications.
     */
    public static final int FRAME_TYPE_I = 0;
    public static final int FRAME_TYPE_P = 1;
    public static final int FRAME_TYPE_B = 2;

    private String mMime = MediaFormat.MIMETYPE_VIDEO_AVC;
    private String mOutputVideoPath = null;

    private final boolean mIsFrontCamera = true;
    private boolean mIsCodecSoftware = false;
    private boolean mIsMediaRecorder = true;
    private boolean mIsRecording;

    private AutoFitTextureView mTextureView;
    private TextView mTextView;
    private CameraDevice mCameraDevice;
    private CameraCaptureSession mPreviewSession;
    private CaptureRequest.Builder mPreviewBuilder;
    private MediaRecorder mMediaRecorder;
    private Size mVideoSize;
    private Size mPreviewSize;

    private Handler mBackgroundHandler;
    private HandlerThread mBackgroundThread;

    private Button mStartButton;

    private int[] mFrameTypeOccurrences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final RadioGroup radioGroup_mime = findViewById(R.id.radio_group_mime);
        radioGroup_mime.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                if (checkedId == R.id.avc) {
                    mMime = MediaFormat.MIMETYPE_VIDEO_AVC;
                } else {
                    mMime = MediaFormat.MIMETYPE_VIDEO_HEVC;
                }
            }
        });

        final RadioGroup radioGroup_codec = findViewById(R.id.radio_group_codec);
        radioGroup_codec.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                mIsCodecSoftware = checkedId == R.id.sw;
            }
        });

        final CheckBox checkBox_mr = findViewById(R.id.checkBox_media_recorder);
        final CheckBox checkBox_mc = findViewById(R.id.checkBox_media_codec);
        mTextureView = findViewById(R.id.texture);
        mTextView = findViewById(R.id.textViewResults);

        checkBox_mr.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                boolean checked = ((CheckBox) v).isChecked();
                if (checked) {
                    checkBox_mc.setChecked(false);
                    mIsMediaRecorder = TRUE;
                    for (int i = 0; i < radioGroup_codec.getChildCount(); i++) {
                        radioGroup_codec.getChildAt(i).setEnabled(false);
                    }
                }
            }
        });
        checkBox_mc.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                boolean checked = ((CheckBox) v).isChecked();
                if (checked) {
                    checkBox_mr.setChecked(false);
                    mIsMediaRecorder = FALSE;
                    for (int i = 0; i < radioGroup_codec.getChildCount(); i++) {
                        radioGroup_codec.getChildAt(i).setEnabled(true);
                    }
                }
            }
        });
        mStartButton = findViewById(R.id.start_button);
        mStartButton.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.start_button) {
            mTextView.setText(null);
            if (mIsMediaRecorder) {
                if (mIsRecording) {
                    stopRecordingVideo();
                } else {
                    mStartButton.setEnabled(false);
                    startRecordingVideo();
                }
            } else {
                mStartButton.setEnabled(false);
                mOutputVideoPath = getVideoPath(MainActivity.this);
                MediaCodecSurfaceAsync codecAsyncTask = new MediaCodecSurfaceAsync(this);
                codecAsyncTask.execute(
                        "Encoding reference test vector with MediaCodec APIs using surface");
            }
        }
    }

    private static class MediaCodecSurfaceAsync extends AsyncTask<String, String, Integer> {

        private final WeakReference<MainActivity> activityReference;

        MediaCodecSurfaceAsync(MainActivity context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected Integer doInBackground(String... strings) {
            MainActivity mainActivity = activityReference.get();
            int resId = R.raw.crowd_1920x1080_25fps_4000kbps_h265;
            int encodingStatus = 1;
            MediaCodecSurfaceEncoder codecSurfaceEncoder =
                    new MediaCodecSurfaceEncoder(mainActivity.getApplicationContext(), resId,
                            mainActivity.mMime, mainActivity.mIsCodecSoftware,
                            mainActivity.mOutputVideoPath);
            try {
                encodingStatus = codecSurfaceEncoder.startEncodingSurface();
                mainActivity.mFrameTypeOccurrences = codecSurfaceEncoder.getFrameTypes();
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }
            return encodingStatus;
        }

        @Override
        protected void onPostExecute(Integer encodingStatus) {
            MainActivity mainActivity = activityReference.get();
            mainActivity.mStartButton.setEnabled(true);
            if (encodingStatus == 0) {
                Toast.makeText(mainActivity.getApplicationContext(), "Encoding Completed",
                        Toast.LENGTH_SHORT).show();
                mainActivity.mTextView.append("\n Encoded stream contains: ");
                mainActivity.mTextView.append("\n Number of I-Frames: " +
                        mainActivity.mFrameTypeOccurrences[FRAME_TYPE_I]);
                mainActivity.mTextView.append("\n Number of P-Frames: " +
                        mainActivity.mFrameTypeOccurrences[FRAME_TYPE_P]);
                mainActivity.mTextView.append("\n Number of B-Frames: " +
                        mainActivity.mFrameTypeOccurrences[FRAME_TYPE_B]);
            } else {
                Toast.makeText(mainActivity.getApplicationContext(),
                        "Error occurred while " + "encoding", Toast.LENGTH_SHORT).show();
            }
            mainActivity.mOutputVideoPath = null;
            super.onPostExecute(encodingStatus);
        }
    }

    private final TextureView.SurfaceTextureListener mSurfaceTextureListener =
            new TextureView.SurfaceTextureListener() {

                @Override
                public void onSurfaceTextureAvailable(SurfaceTexture surface, int width,
                                                      int height) {
                    openCamera(width, height);
                }

                @Override
                public void onSurfaceTextureSizeChanged(SurfaceTexture surface, int width,
                                                        int height) {
                    configureTransform(width, height);
                    Log.v(TAG, "Keeping camera preview size fixed");
                }

                @Override
                public boolean onSurfaceTextureDestroyed(SurfaceTexture surface) {
                    return true;
                }

                @Override
                public void onSurfaceTextureUpdated(SurfaceTexture surface) {
                }
            };


    private final CameraDevice.StateCallback mStateCallback = new CameraDevice.StateCallback() {

        @Override
        public void onOpened(CameraDevice cameraDevice) {
            mCameraDevice = cameraDevice;
            startPreview();
            mCameraOpenCloseLock.release();
        }

        @Override
        public void onDisconnected(CameraDevice cameraDevice) {
            mCameraOpenCloseLock.release();
            cameraDevice.close();
            mCameraDevice = null;
        }

        @Override
        public void onError(CameraDevice cameraDevice, int error) {
            mCameraOpenCloseLock.release();
            cameraDevice.close();
            mCameraDevice = null;
            Activity activity = MainActivity.this;
            activity.finish();
        }
    };

    private boolean shouldShowRequestPermissionRationale(String[] recordPermissions) {
        for (String permission : recordPermissions) {
            if (ActivityCompat.shouldShowRequestPermissionRationale(this, permission)) {
                return true;
            }
        }
        return false;
    }

    private void requestRecordPermissions() {
        if (!shouldShowRequestPermissionRationale(RECORD_PERMISSIONS)) {
            ActivityCompat.requestPermissions(this, RECORD_PERMISSIONS, REQUEST_RECORD_PERMISSIONS);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
                                           int[] grantResults) {
        if (requestCode == REQUEST_RECORD_PERMISSIONS) {
            if (grantResults.length == RECORD_PERMISSIONS.length) {
                for (int result : grantResults) {
                    if (result != PackageManager.PERMISSION_GRANTED) {
                        Log.e(TAG, "Permission is not granted");
                        break;
                    }
                }
            }
        } else {
            super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        }
    }

    @SuppressWarnings("MissingPermission")
    private void openCamera(int width, int height) {
        if (!hasPermissionGranted(RECORD_PERMISSIONS)) {
            Log.e(TAG, "Camera does not have permission to record video");
            requestRecordPermissions();
            return;
        }
        final Activity activity = MainActivity.this;
        if (activity == null || activity.isFinishing()) {
            Log.e(TAG, "Activity not found");
            return;
        }
        CameraManager manager = (CameraManager) activity.getSystemService(Context.CAMERA_SERVICE);
        try {
            Log.v(TAG, "Acquire Camera");
            if (!mCameraOpenCloseLock.tryAcquire(2500, TimeUnit.MILLISECONDS)) {
                throw new RuntimeException("Timed out waiting to lock camera opening");
            }
            Log.d(TAG, "Camera Acquired");

            String cameraId = manager.getCameraIdList()[0];
            if (mIsFrontCamera) {
                cameraId = manager.getCameraIdList()[1];
            }

            CameraCharacteristics characteristics = manager.getCameraCharacteristics(cameraId);
            StreamConfigurationMap map =
                    characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            mVideoSize = chooseVideoSize(map.getOutputSizes(MediaRecorder.class));
            mPreviewSize =
                    chooseOptimalSize(map.getOutputSizes(SurfaceTexture.class), width, height,
                            mVideoSize);
            mTextureView.setAspectRatio(mPreviewSize.getHeight(), mPreviewSize.getWidth());
            configureTransform(width, height);
            mMediaRecorder = new MediaRecorder();
            manager.openCamera(cameraId, mStateCallback, null);
        } catch (InterruptedException | CameraAccessException e) {
            e.printStackTrace();
        }
    }

    private void closeCamera() {
        try {
            mCameraOpenCloseLock.acquire();
            closePreviewSession();
            if (null != mCameraDevice) {
                mCameraDevice.close();
                mCameraDevice = null;
            }
            if (null != mMediaRecorder) {
                mMediaRecorder.release();
                mMediaRecorder = null;
            }
        } catch (InterruptedException e) {
            throw new RuntimeException("Interrupted while trying to lock camera closing.");
        } finally {
            mCameraOpenCloseLock.release();
        }
    }

    private static Size chooseVideoSize(Size[] choices) {
        for (Size size : choices) {
            if (size.getWidth() == size.getHeight() * 16 / 9 && size.getWidth() <= 1920) {
                return size;
            }
        }
        Log.e(TAG, "Couldn't find any suitable video size");
        return choices[choices.length - 1];
    }

    private static Size chooseOptimalSize(Size[] choices, int width, int height, Size aspectRatio) {
        List<Size> bigEnough = new ArrayList<>();
        int w = aspectRatio.getWidth();
        int h = aspectRatio.getHeight();
        for (Size option : choices) {
            if (option.getHeight() == option.getWidth() * h / w && option.getWidth() >= width &&
                    option.getHeight() >= height) {
                bigEnough.add(option);
            }
        }

        // Pick the smallest of those, assuming we found any
        if (bigEnough.size() > 0) {
            return Collections.min(bigEnough, new CompareSizesByArea());
        } else {
            Log.e(TAG, "Couldn't find any suitable preview size");
            return choices[0];
        }
    }

    private boolean hasPermissionGranted(String[] recordPermissions) {
        for (String permission : recordPermissions) {
            if (ActivityCompat.checkSelfPermission(MainActivity.this, permission) !=
                    PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }

    @Override
    public void onResume() {
        super.onResume();
        startBackgroundThread();
        if (mTextureView.isAvailable()) {
            openCamera(mTextureView.getWidth(), mTextureView.getHeight());
        } else {
            mTextureView.setSurfaceTextureListener(mSurfaceTextureListener);
        }
    }

    @Override
    public void onPause() {
        closeCamera();
        stopBackgroundThread();
        super.onPause();
    }

    private void startBackgroundThread() {
        mBackgroundThread = new HandlerThread("CameraBackground");
        mBackgroundThread.start();
        mBackgroundHandler = new Handler(mBackgroundThread.getLooper());
    }

    private void stopBackgroundThread() {
        mBackgroundThread.quitSafely();
        try {
            mBackgroundThread.join();
            mBackgroundThread = null;
            mBackgroundHandler = null;
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private void startRecordingVideo() {
        if (null == mCameraDevice || !mTextureView.isAvailable() || null == mPreviewSize) {
            Toast.makeText(MainActivity.this, "Cannot start recording.", Toast.LENGTH_SHORT).show();
            Log.e(TAG, "Cannot start recording.");
            return;
        }
        try {
            closePreviewSession();
            setUpMediaRecorder();
            SurfaceTexture texture = mTextureView.getSurfaceTexture();
            assert texture != null;
            texture.setDefaultBufferSize(mPreviewSize.getWidth(), mPreviewSize.getHeight());
            mPreviewBuilder = mCameraDevice.createCaptureRequest(CameraDevice.TEMPLATE_RECORD);
            List<Surface> surfaces = new ArrayList<>();

            // Set up Surface for the camera preview
            Surface previewSurface = new Surface(texture);
            surfaces.add(previewSurface);
            mPreviewBuilder.addTarget(previewSurface);

            // Set up Surface for the MediaRecorder
            Surface recorderSurface = mMediaRecorder.getSurface();
            surfaces.add(recorderSurface);
            mPreviewBuilder.addTarget(recorderSurface);

            //Start a capture session
            mCameraDevice.createCaptureSession(surfaces, new CameraCaptureSession.StateCallback() {

                @Override
                public void onConfigured(CameraCaptureSession session) {
                    mPreviewSession = session;
                    updatePreview();
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            mIsRecording = true;
                            mMediaRecorder.start();
                            mStartButton.setText(R.string.stop);
                            mStartButton.setEnabled(true);
                        }
                    });
                }

                @Override
                public void onConfigureFailed(CameraCaptureSession session) {
                    Log.e(TAG, "Failed to configure. Cannot start Recording");
                }
            }, mBackgroundHandler);
        } catch (CameraAccessException e) {
            e.printStackTrace();
        }
    }

    private void setUpMediaRecorder() {
        final Activity activity = MainActivity.this;
        if (activity == null) {
            Toast.makeText(MainActivity.this, "Error occurred while setting up the MediaRecorder",
                    Toast.LENGTH_SHORT).show();
            Log.e(TAG, "Error occurred while setting up the MediaRecorder");
            return;
        }
        try {
            mMediaRecorder.setAudioSource(MediaRecorder.AudioSource.MIC);
            mMediaRecorder.setVideoSource(MediaRecorder.VideoSource.SURFACE);
            mMediaRecorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4);
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
        if (mOutputVideoPath == null) {
            mOutputVideoPath = getVideoPath(MainActivity.this);
        }
        mMediaRecorder.setOutputFile(mOutputVideoPath);
        mMediaRecorder.setVideoEncodingBitRate(VIDEO_BITRATE);
        mMediaRecorder.setVideoFrameRate(VIDEO_FRAMERATE);
        mMediaRecorder.setVideoSize(mVideoSize.getWidth(), mVideoSize.getHeight());
        mMediaRecorder.setOrientationHint(270);
        if (mMime.equals(MediaFormat.MIMETYPE_VIDEO_HEVC)) {
            mMediaRecorder.setVideoEncoder(MediaRecorder.VideoEncoder.HEVC);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                mMediaRecorder.setVideoEncodingProfileLevel(
                        MediaCodecInfo.CodecProfileLevel.HEVCProfileMain,
                        MediaCodecInfo.CodecProfileLevel.HEVCMainTierLevel4);
            }
        } else {
            mMediaRecorder.setVideoEncoder(MediaRecorder.VideoEncoder.H264);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                mMediaRecorder.setVideoEncodingProfileLevel(
                        MediaCodecInfo.CodecProfileLevel.AVCProfileMain,
                        MediaCodecInfo.CodecProfileLevel.AVCLevel4);
            }
        }
        mMediaRecorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);
        try {
            mMediaRecorder.prepare();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getVideoPath(Activity activity) {
        File dir = activity.getApplicationContext().getExternalFilesDir(null);
        if (dir == null) {
            Log.e(TAG, "Cannot get external directory path to save output video");
            return null;
        }
        String videoPath = dir.getAbsolutePath() + "/Video-" + System.currentTimeMillis() + ".mp4";
        Log.d(TAG, "Output video is saved at: " + videoPath);
        return videoPath;
    }

    private void closePreviewSession() {
        if (mPreviewSession != null) {
            mPreviewSession.close();
            mPreviewSession = null;
        }
    }

    private void stopRecordingVideo() {
        mIsRecording = false;
        mStartButton.setText(R.string.start);
        mMediaRecorder.stop();
        mMediaRecorder.reset();
        Toast.makeText(MainActivity.this, "Recording Finished", Toast.LENGTH_SHORT).show();
        mOutputVideoPath = null;
        startPreview();
    }

    private void startPreview() {
        if (null == mCameraDevice || !mTextureView.isAvailable() || null == mPreviewSize) {
            return;
        }
        try {
            closePreviewSession();
            SurfaceTexture texture = mTextureView.getSurfaceTexture();
            assert texture != null;
            texture.setDefaultBufferSize(mPreviewSize.getWidth(), mPreviewSize.getHeight());
            mPreviewBuilder = mCameraDevice.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);

            Surface previewSurface = new Surface(texture);
            mPreviewBuilder.addTarget(previewSurface);

            mCameraDevice.createCaptureSession(Collections.singletonList(previewSurface),
                    new CameraCaptureSession.StateCallback() {

                        @Override
                        public void onConfigured(CameraCaptureSession session) {
                            mPreviewSession = session;
                            updatePreview();
                        }

                        @Override
                        public void onConfigureFailed(CameraCaptureSession session) {
                            Toast.makeText(MainActivity.this,
                                    "Configure Failed; Cannot start " + "preview",
                                    Toast.LENGTH_SHORT).show();
                            Log.e(TAG, "Configure failed; Cannot start preview");
                        }
                    }, mBackgroundHandler);
        } catch (CameraAccessException e) {
            e.printStackTrace();
        }
    }

    private void updatePreview() {
        if (mCameraDevice == null) {
            Toast.makeText(MainActivity.this, "Camera not found; Cannot update " + "preview",
                    Toast.LENGTH_SHORT).show();
            Log.e(TAG, "Camera not found; Cannot update preview");
            return;
        }
        try {
            mPreviewBuilder.set(CaptureRequest.CONTROL_MODE, CameraMetadata.CONTROL_MODE_AUTO);
            HandlerThread thread = new HandlerThread("Camera preview");
            thread.start();
            mPreviewSession.setRepeatingRequest(mPreviewBuilder.build(), null, mBackgroundHandler);
        } catch (CameraAccessException e) {
            e.printStackTrace();
        }
    }

    private void configureTransform(int viewWidth, int viewHeight) {
        Activity activity = MainActivity.this;
        if (null == mTextureView || null == mPreviewSize || null == activity) {
            return;
        }
        Matrix matrix = new Matrix();
        RectF viewRect = new RectF(0, 0, viewWidth, viewHeight);
        RectF bufferRect = new RectF(0, 0, mPreviewSize.getHeight(), mPreviewSize.getWidth());
        float centerX = viewRect.centerX();
        float centerY = viewRect.centerY();
        bufferRect.offset(centerX - bufferRect.centerX(), centerY - bufferRect.centerY());
        matrix.setRectToRect(viewRect, bufferRect, Matrix.ScaleToFit.FILL);
        float scale = Math.max((float) viewHeight / mPreviewSize.getHeight(),
                (float) viewWidth / mPreviewSize.getWidth());
        matrix.postScale(scale, scale, centerX, centerY);
        mTextureView.setTransform(matrix);
    }

    static class CompareSizesByArea implements Comparator<Size> {
        @Override
        public int compare(Size lhs, Size rhs) {
            return Long.signum((long) lhs.getWidth() * lhs.getHeight() -
                    (long) rhs.getWidth() * rhs.getHeight());
        }
    }
}
