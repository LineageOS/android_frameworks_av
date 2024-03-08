/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include <LiveDataSource.h>
#include <LiveSession.h>
#include <media/MediaHTTPConnection.h>
#include <media/MediaHTTPService.h>
#include <media/mediaplayer_common.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AHandler.h>
#include <media/stagefright/foundation/ALooper.h>
#include <media/stagefright/foundation/ALooperRoster.h>
#include <string>
#include <utils/Log.h>

using namespace std;
using namespace android;

constexpr char kFileUrlPrefix[] = "file://";
constexpr char kBinFilePrefix[] = "/data/local/tmp/";
constexpr char kBinFileSuffix[] = ".bin";
constexpr char kM3U8IndexFilePrefix[] = "/data/local/tmp/index-";
constexpr char kM3U8IndexFileSuffix[] = ".m3u8";
constexpr int64_t kOffSet = 0;
constexpr int32_t kInitialM3U8Index = 0;
constexpr int32_t kReadyMarkMs = 5000;
constexpr int32_t kPrepareMarkMs = 1500;
constexpr int32_t kErrorNoMax = -1;
constexpr int32_t kErrorNoMin = -34;
constexpr int32_t kMaxTimeUs = 1000;
constexpr int32_t kRandomStringLength = 64;
constexpr int32_t kRangeMin = 0;
constexpr int32_t kRangeMax = 1000;
constexpr int32_t kWaitTime = 100;
constexpr uint8_t kMarker[] = "_MARK";
constexpr uint8_t kM3U8MarkerSuffix[] = "_M_";
constexpr uint8_t kBinMarkerSuffix[] = "_B_";
static_assert(sizeof(kM3U8MarkerSuffix) == sizeof(kBinMarkerSuffix),
              "Marker suffix must be same size");
// All markers should be 5 bytes long ( sizeof '_MARK' is 6)
constexpr size_t kMarkerSize = (sizeof(kMarker) - 1);
// All marker types should be 3 bytes long ('_M_', '_B_')
constexpr size_t kMarkerSuffixSize = (sizeof(kM3U8MarkerSuffix) - 1);

constexpr LiveSession::StreamType kValidStreamType[] = {
    LiveSession::STREAMTYPE_AUDIO, LiveSession::STREAMTYPE_VIDEO,
    LiveSession::STREAMTYPE_SUBTITLES, LiveSession::STREAMTYPE_METADATA};

constexpr MediaSource::ReadOptions::SeekMode kValidSeekMode[] = {
    MediaSource::ReadOptions::SeekMode::SEEK_PREVIOUS_SYNC,
    MediaSource::ReadOptions::SeekMode::SEEK_NEXT_SYNC,
    MediaSource::ReadOptions::SeekMode::SEEK_CLOSEST_SYNC,
    MediaSource::ReadOptions::SeekMode::SEEK_CLOSEST,
    MediaSource::ReadOptions::SeekMode::SEEK_FRAME_INDEX};

constexpr media_track_type kValidMediaTrackType[] = {
    MEDIA_TRACK_TYPE_UNKNOWN,  MEDIA_TRACK_TYPE_VIDEO,
    MEDIA_TRACK_TYPE_AUDIO,    MEDIA_TRACK_TYPE_TIMEDTEXT,
    MEDIA_TRACK_TYPE_SUBTITLE, MEDIA_TRACK_TYPE_METADATA};

struct TestAHandler : public AHandler {
public:
  TestAHandler(std::function<void()> signalEosFunction)
      : mSignalEosFunction(signalEosFunction) {}
  virtual ~TestAHandler() {}

protected:
  void onMessageReceived(const sp<AMessage> &msg) override {
    int32_t what = -1;
    msg->findInt32("what", &what);
    switch (what) {
    case LiveSession::kWhatError:
    case LiveSession::kWhatPrepared:
    case LiveSession::kWhatPreparationFailed: {
      mSignalEosFunction();
      break;
    }
    }
    return;
  }

private:
  std::function<void()> mSignalEosFunction;
};

struct TestMediaHTTPConnection : public MediaHTTPConnection {
public:
  TestMediaHTTPConnection() {}
  virtual ~TestMediaHTTPConnection() {}

  virtual bool connect(const char * /*uri*/,
                       const KeyedVector<String8, String8> * /*headers*/) {
    return true;
  }

  virtual void disconnect() { return; }

  virtual ssize_t readAt(off64_t /*offset*/, void * /*data*/, size_t size) {
    return size;
  }

  virtual off64_t getSize() { return 0; }
  virtual status_t getMIMEType(String8 * /*mimeType*/) { return NO_ERROR; }
  virtual status_t getUri(String8 * /*uri*/) { return NO_ERROR; }

private:
  DISALLOW_EVIL_CONSTRUCTORS(TestMediaHTTPConnection);
};

struct TestMediaHTTPService : public MediaHTTPService {
public:
  TestMediaHTTPService() {}
  ~TestMediaHTTPService(){};

  virtual sp<MediaHTTPConnection> makeHTTPConnection() {
    mediaHTTPConnection = sp<TestMediaHTTPConnection>::make();
    return mediaHTTPConnection;
  }

private:
  sp<TestMediaHTTPConnection> mediaHTTPConnection = nullptr;
  DISALLOW_EVIL_CONSTRUCTORS(TestMediaHTTPService);
};

class HttpLiveFuzzer {
public:
  void process(const uint8_t *data, size_t size);
  void deInitLiveSession();
  ~HttpLiveFuzzer() { deInitLiveSession(); }

private:
  bool isMarker();
  bool isM3U8Marker(size_t position);
  bool isBinMarker(size_t position);
  bool searchForMarker();
  void initDataFile(const string& fileName, const uint8_t* data, size_t size);
  void createFiles(const uint8_t* data, size_t size);
  void invokeLiveDataSource();
  void initLiveDataSource();
  void invokeLiveSession();
  void initLiveSession();
  void invokeDequeueAccessUnit();
  void invokeConnectAsync();
  void invokeSeekTo();
  void invokeGetConfig();
  void signalEos();
  const uint8_t* mData = nullptr;
  size_t mSize = 0;
  int32_t mReadIndex = 0;
  sp<LiveDataSource> mLiveDataSource = nullptr;
  sp<LiveSession> mLiveSession = nullptr;
  sp<ALooper> mLiveLooper = nullptr;
  sp<TestMediaHTTPService> httpService = nullptr;
  sp<TestAHandler> mHandler = nullptr;
  FuzzedDataProvider *mFDP = nullptr;
  bool mEosReached = false;
  std::mutex mDownloadCompleteMutex;
  std::condition_variable mConditionalVariable;
};

bool HttpLiveFuzzer::isMarker() {
  if ((kMarkerSize <= mSize) && (mReadIndex <= mSize - kMarkerSize)) {
    return (memcmp(&mData[mReadIndex], kMarker, kMarkerSize) == 0);
  } else {
    return false;
  }
}

bool HttpLiveFuzzer::isM3U8Marker(size_t position) {
  if ((kMarkerSuffixSize <= mSize) && (position <= mSize - kMarkerSuffixSize)) {
    return (memcmp(&mData[position], kM3U8MarkerSuffix, kMarkerSuffixSize) == 0);
  } else {
    return false;
  }
}

bool HttpLiveFuzzer::isBinMarker(size_t position) {
  if ((kMarkerSuffixSize <= mSize) && (position <= mSize - kMarkerSuffixSize)) {
    return (memcmp(&mData[position], kBinMarkerSuffix, kMarkerSuffixSize) == 0);
  } else {
    return false;
  }
}

bool HttpLiveFuzzer::searchForMarker() {
  while (mReadIndex >= 0) {
    if (isMarker()) {
      return true;
    }
    --mReadIndex;
  }
  return false;
}

void HttpLiveFuzzer::initDataFile(const string& fileName, const uint8_t* data, size_t size) {
  ofstream file;
  file.open(fileName, ios::out | ios::binary);
  if (file.is_open()) {
    file.write((char*)data, size);
    file.close();
  }
}

void HttpLiveFuzzer::createFiles(const uint8_t* data, size_t size) {
  mData = data;
  mSize = size;
  mReadIndex = (size <= kMarkerSize) ? 0 : (size - kMarkerSize);
  size_t bytesRemaining = mSize;
  int m3u8fileIndex = 0;
  int binfileIndex = 0;
  while (searchForMarker()) {
    size_t location = mReadIndex + kMarkerSize;
    size_t fileSize = 0;
    if (isM3U8Marker(location)) {
      location += kMarkerSuffixSize;
      fileSize = bytesRemaining - location;
      string m3u8fileName = kM3U8IndexFilePrefix + to_string(m3u8fileIndex) + kM3U8IndexFileSuffix;
      initDataFile(m3u8fileName, &mData[location], fileSize);
      ++m3u8fileIndex;
    } else if (isBinMarker(location)) {
      location += kMarkerSuffixSize;
      fileSize = bytesRemaining - location;
      string binfileName = kBinFilePrefix + to_string(binfileIndex) + kBinFileSuffix;
      initDataFile(binfileName, &mData[location], fileSize);
      ++binfileIndex;
    }
    bytesRemaining = mReadIndex;
    --mReadIndex;
  }
  if (m3u8fileIndex == 0 && binfileIndex == 0) {
    string fileName = kM3U8IndexFilePrefix + to_string(m3u8fileIndex) + kM3U8IndexFileSuffix;
    initDataFile(fileName, mData, mSize);
    fileName = kBinFilePrefix + to_string(binfileIndex) + kBinFileSuffix;
    initDataFile(fileName, mData, mSize);
  }
}

void HttpLiveFuzzer::initLiveDataSource() {
  mLiveDataSource = sp<LiveDataSource>::make();
}

void HttpLiveFuzzer::invokeLiveDataSource() {
  initLiveDataSource();
  size_t size = mFDP->ConsumeIntegralInRange<size_t>(kRangeMin, kRangeMax);
  sp<ABuffer> buffer = new ABuffer(size);
  mLiveDataSource->queueBuffer(buffer);
  uint8_t *data = new uint8_t[size];
  mLiveDataSource->readAtNonBlocking(kOffSet, data, size);
  int32_t finalResult = mFDP->ConsumeIntegralInRange(kErrorNoMin, kErrorNoMax);
  mLiveDataSource->queueEOS(finalResult);
  mLiveDataSource->reset();
  mLiveDataSource->countQueuedBuffers();
  mLiveDataSource->initCheck();
  delete[] data;
}

void HttpLiveFuzzer::initLiveSession() {
  ALooperRoster looperRoster;
  mHandler =
      sp<TestAHandler>::make(std::bind(&HttpLiveFuzzer::signalEos, this));
  mLiveLooper = sp<ALooper>::make();
  mLiveLooper->setName("http live");
  mLiveLooper->start();
  sp<AMessage> notify = sp<AMessage>::make(0, mHandler);
  httpService = new TestMediaHTTPService();
  uint32_t flags = mFDP->ConsumeIntegral<uint32_t>();
  mLiveSession = sp<LiveSession>::make(notify, flags, httpService);
  mLiveLooper->registerHandler(mLiveSession);
  looperRoster.registerHandler(mLiveLooper, mHandler);
}

void HttpLiveFuzzer::invokeDequeueAccessUnit() {
  LiveSession::StreamType stream = mFDP->PickValueInArray(kValidStreamType);
  sp<ABuffer> buffer;
  mLiveSession->dequeueAccessUnit(stream, &buffer);
}

void HttpLiveFuzzer::invokeSeekTo() {
  int64_t timeUs = mFDP->ConsumeIntegralInRange<int64_t>(0, kMaxTimeUs);
  MediaSource::ReadOptions::SeekMode mode =
      mFDP->PickValueInArray(kValidSeekMode);
  mLiveSession->seekTo(timeUs, mode);
}

void HttpLiveFuzzer::invokeGetConfig() {
  mLiveSession->getTrackCount();
  size_t trackIndex = mFDP->ConsumeIntegral<size_t>();
  mLiveSession->getTrackInfo(trackIndex);
  media_track_type type = mFDP->PickValueInArray(kValidMediaTrackType);
  mLiveSession->getSelectedTrack(type);
  sp<MetaData> meta;
  LiveSession::StreamType stream = mFDP->PickValueInArray(kValidStreamType);
  mLiveSession->getStreamFormatMeta(stream, &meta);
  mLiveSession->getKeyForStream(stream);
  if (stream != LiveSession::STREAMTYPE_SUBTITLES) {
    mLiveSession->getSourceTypeForStream(stream);
  }
}

void HttpLiveFuzzer::invokeConnectAsync() {
  string currentFileName =
      kM3U8IndexFilePrefix + to_string(kInitialM3U8Index) + kM3U8IndexFileSuffix;
  string url = kFileUrlPrefix + currentFileName;
  string str_1 = mFDP->ConsumeRandomLengthString(kRandomStringLength);
  string str_2 = mFDP->ConsumeRandomLengthString(kRandomStringLength);

  KeyedVector<String8, String8> headers;
  headers.add(String8(str_1.c_str()), String8(str_2.c_str()));
  mLiveSession->connectAsync(url.c_str(), &headers);
}

void HttpLiveFuzzer::invokeLiveSession() {
  initLiveSession();
  BufferingSettings bufferingSettings;
  bufferingSettings.mInitialMarkMs = kPrepareMarkMs;
  bufferingSettings.mResumePlaybackMarkMs = kReadyMarkMs;
  mLiveSession->setBufferingSettings(bufferingSettings);
  invokeConnectAsync();
  std::unique_lock waitForDownloadComplete(mDownloadCompleteMutex);
  auto now = std::chrono::system_clock::now();
  mConditionalVariable.wait_until(waitForDownloadComplete, now + std::chrono::milliseconds(kWaitTime),
                                  [this] { return mEosReached; });
  if (mLiveSession->isSeekable()) {
    invokeSeekTo();
  }
  invokeDequeueAccessUnit();
  size_t index = mFDP->ConsumeIntegral<size_t>();
  bool select = mFDP->ConsumeBool();
  mLiveSession->selectTrack(index, select);
  mLiveSession->hasDynamicDuration();
  int64_t firstTimeUs =
      mFDP->ConsumeIntegralInRange<int64_t>(kRangeMin, kRangeMax);
  int64_t timeUs = mFDP->ConsumeIntegralInRange<int64_t>(kRangeMin, kRangeMax);
  int32_t discontinuitySeq = mFDP->ConsumeIntegral<int32_t>();
  mLiveSession->calculateMediaTimeUs(firstTimeUs, timeUs, discontinuitySeq);
  invokeGetConfig();
}

void HttpLiveFuzzer::process(const uint8_t *data, size_t size) {
  mFDP = new FuzzedDataProvider(data, size);
  createFiles(data, size);
  invokeLiveDataSource();
  invokeLiveSession();
  delete mFDP;
}

void HttpLiveFuzzer::deInitLiveSession() {
  if (mLiveSession != nullptr) {
    mLiveSession->disconnect();
    mLiveLooper->unregisterHandler(mLiveSession->id());
    mLiveLooper->stop();
  }
  mLiveSession.clear();
  mLiveLooper.clear();
}

void HttpLiveFuzzer::signalEos() {
  mEosReached = true;
  {
    std::lock_guard<std::mutex> waitForDownloadComplete(mDownloadCompleteMutex);
  }
  mConditionalVariable.notify_one();
  return;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  HttpLiveFuzzer httpliveFuzzer;
  httpliveFuzzer.process(data, size);
  return 0;
}
