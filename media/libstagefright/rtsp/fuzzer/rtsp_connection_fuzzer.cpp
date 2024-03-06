/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <arpa/inet.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/rtsp/ARTSPConnection.h>
#include <thread>

using namespace android;

const std::string kAuthType[] = {"Basic", "Digest"};
const std::string kTab = "\t";
const std::string kCSeq = "CSeq: ";
const std::string kSpace = " ";
const std::string kNewLine = "\n";
const std::string kBinaryHeader = "$";
const std::string kNonce = " nonce=\"\"";
const std::string kRealm = " realm=\"\"";
const std::string kHeaderBoundary = "\r\n\r\n";
const std::string kContentLength = "content-length: ";
const std::string kDefaultRequestValue = "INVALID_FORMAT";
const std::string kUrlPrefix = "rtsp://root:pass@127.0.0.1:";
const std::string kRequestMarker = "REQUEST_SENT";
const std::string kQuitResponse = "\n\n\n\n";
const std::string kRTSPVersion = "RTSP/1.0";
const std::string kValidResponse = kRTSPVersion + " 200 \n";
const std::string kAuthString = kRTSPVersion + " 401 \nwww-authenticate: ";
constexpr char kNullValue = '\0';
constexpr char kDefaultValue = '0';
constexpr int32_t kWhat = 'resp';
constexpr int32_t kMinPort = 100;
constexpr int32_t kMaxPort = 999;
constexpr int32_t kMinASCIIValue = 32;
constexpr int32_t kMaxASCIIValue = 126;
constexpr int32_t kMinContentLength = 0;
constexpr int32_t kMaxContentLength = 1000;
constexpr int32_t kBinaryVectorSize = 3;
constexpr int32_t kDefaultCseqValue = 1;
constexpr int32_t kBufferSize = 1024;
constexpr int32_t kMaxLoopRuns = 5;
constexpr int32_t kPort = 554;
constexpr int32_t kMaxBytes = 128;
constexpr int32_t kMaxThreads = 1024;

struct FuzzAHandler : public AHandler {
  public:
    FuzzAHandler(std::function<void()> signalEosFunction)
        : mSignalEosFunction(std::move(signalEosFunction)) {}
    ~FuzzAHandler() = default;

  protected:
    void onMessageReceived(const sp<AMessage>& msg) override {
        switch (msg->what()) {
            case kWhat: {
                mSignalEosFunction();
                break;
            }
        }
    }

  private:
    std::function<void()> mSignalEosFunction;
};

class RTSPConnectionFuzzer {
  public:
    RTSPConnectionFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    ~RTSPConnectionFuzzer() {
        // wait for all the threads to join the main thread
        for (auto& thread : mThreadPool) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        close(mServerFd);
    }
    void process();

  private:
    void signalEos();
    void startServer();
    void createFuzzData();
    void acceptConnection();
    void handleConnection(int32_t);
    void handleClientResponse(int32_t);
    void sendValidResponse(int32_t, int32_t);
    int32_t checkSocket(int32_t);
    size_t generateBinaryDataSize(std::string);
    bool checkValidRequestData(const AString&);
    bool mEosReached = false;
    bool mServerFailure = false;
    bool mNotifyResponseListener = false;
    int32_t mServerFd;
    std::string mFuzzData = "";
    std::string mFuzzRequestData = "";
    std::string mRequestData = kDefaultRequestValue;
    std::mutex mFuzzDataMutex;
    std::mutex mMsgPostCompleteMutex;
    std::condition_variable mConditionalVariable;
    std::vector<std::thread> mThreadPool;
    FuzzedDataProvider mFdp;
};

size_t RTSPConnectionFuzzer::generateBinaryDataSize(std::string values) {
    // computed the binary data size as done in ARTSPConnection.cpp
    uint8_t x = values[0];
    uint8_t y = values[1];
    return x << 8 | y;
}

bool RTSPConnectionFuzzer::checkValidRequestData(const AString& request) {
    if (request.find(kHeaderBoundary.c_str()) <= 0) {
        return false;
    }
    ssize_t space = request.find(kSpace.c_str());
    if (space <= 0) {
        return false;
    }
    if (request.find(kSpace.c_str(), space + 1) <= 0) {
        return false;
    }
    return true;
}

void RTSPConnectionFuzzer::createFuzzData() {
    std::unique_lock fuzzLock(mFuzzDataMutex);
    mFuzzData = "";
    mFuzzRequestData = "";
    int32_t contentLength = 0;
    if (mFdp.ConsumeBool()) {
        if (mFdp.ConsumeBool()) {
            // if we want to handle server request
            mFuzzData.append(kSpace + kSpace + kRTSPVersion);
        } else {
            // if we want to notify response listener
            mFuzzData.append(
                    kRTSPVersion + kSpace +
                    std::to_string(mFdp.ConsumeIntegralInRange<uint16_t>(kMinPort, kMaxPort)) +
                    kSpace);
        }
        mFuzzData.append(kNewLine);
        if (mFdp.ConsumeBool()) {
            contentLength =
                    mFdp.ConsumeIntegralInRange<int32_t>(kMinContentLength, kMaxContentLength);
            mFuzzData.append(kContentLength + std::to_string(contentLength) + kNewLine);
            if (mFdp.ConsumeBool()) {
                mFdp.ConsumeBool() ? mFuzzData.append(kSpace + kNewLine)
                                   : mFuzzData.append(kTab + kNewLine);
            }
        }
        // new line to break out of infinite for loop
        mFuzzData.append(kNewLine);
        if (contentLength) {
            std::string contentData = mFdp.ConsumeBytesAsString(contentLength);
            contentData.resize(contentLength, kDefaultValue);
            mFuzzData.append(contentData);
        }
    } else {
        // for binary data
        std::string randomValues(kBinaryVectorSize, kNullValue);
        for (size_t idx = 0; idx < kBinaryVectorSize; ++idx) {
            randomValues[idx] =
                    (char)mFdp.ConsumeIntegralInRange<uint8_t>(kMinASCIIValue, kMaxASCIIValue);
        }
        size_t binaryDataSize = generateBinaryDataSize(randomValues);
        std::string data = mFdp.ConsumeBytesAsString(binaryDataSize);
        data.resize(binaryDataSize, kDefaultValue);
        mFuzzData.append(kBinaryHeader + randomValues + data);
    }
    if (mFdp.ConsumeBool()) {
        mRequestData = mFdp.ConsumeRandomLengthString(kMaxBytes) + kSpace + kSpace +
                       kHeaderBoundary + mFdp.ConsumeRandomLengthString(kMaxBytes);
        // Check if Request data is valid
        if (checkValidRequestData(mRequestData.c_str())) {
            if (mFdp.ConsumeBool()) {
                if (mFdp.ConsumeBool()) {
                    // if we want to handle server request
                    mFuzzRequestData.append(kSpace + kSpace + kRTSPVersion + kNewLine);
                } else {
                    // if we want to add authentication headers
                    mNotifyResponseListener = true;
                    mFuzzRequestData.append(kAuthString);
                    if (mFdp.ConsumeBool()) {
                        // for Authentication type: Basic
                        mFuzzRequestData.append(kAuthType[0]);
                    } else {
                        // for Authentication type: Digest
                        mFuzzRequestData.append(kAuthType[1]);
                        mFuzzRequestData.append(kNonce);
                        mFuzzRequestData.append(kRealm);
                    }
                    mFuzzRequestData.append(kNewLine);
                }
            } else {
                mNotifyResponseListener = false;
                mFuzzRequestData.append(kValidResponse);
            }
        } else {
            mRequestData = kDefaultRequestValue;
        }
    } else {
        mRequestData = kDefaultRequestValue;
        mFuzzData.append(kNewLine);
    }
}

void RTSPConnectionFuzzer::signalEos() {
    mEosReached = true;
    mConditionalVariable.notify_all();
    return;
}

int32_t RTSPConnectionFuzzer::checkSocket(int32_t newSocket) {
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(newSocket, &rs);

    return select(newSocket + 1, &rs, nullptr, nullptr, &tv);
}

void RTSPConnectionFuzzer::sendValidResponse(int32_t newSocket, int32_t cseq = -1) {
    std::string validResponse = kValidResponse;
    if (cseq != -1) {
        validResponse.append(kCSeq + std::to_string(cseq));
        validResponse.append(kNewLine + kNewLine);
    } else {
        validResponse.append(kNewLine);
    }
    send(newSocket, validResponse.c_str(), validResponse.size(), 0);
}

void RTSPConnectionFuzzer::handleClientResponse(int32_t newSocket) {
    char buffer[kBufferSize] = {0};
    if (checkSocket(newSocket) == 1) {
        read(newSocket, buffer, kBufferSize);
    }
}

void RTSPConnectionFuzzer::handleConnection(int32_t newSocket) {
    std::unique_lock fuzzLock(mFuzzDataMutex);
    send(newSocket, mFuzzData.c_str(), mFuzzData.size(), 0);
    if (mFuzzData[0] == kSpace[0]) {
        handleClientResponse(newSocket);
    }

    if (mFuzzRequestData != "") {
        char buffer[kBufferSize] = {0};
        if (checkSocket(newSocket) == 1 && recv(newSocket, buffer, kBufferSize, MSG_DONTWAIT) > 0) {
            // Extract the 'CSeq' value present at the end of header
            std::string clientResponse(buffer);
            std::string header = clientResponse.substr(0, clientResponse.find(kHeaderBoundary));
            char cseq = header[header.rfind(kCSeq) + kCSeq.length()];
            int32_t cseqValue = cseq ? cseq - '0' : kDefaultCseqValue;
            std::string response = mFuzzRequestData;
            response.append(kCSeq + std::to_string(cseqValue));
            response.append(kNewLine + kNewLine);
            send(newSocket, response.data(), response.length(), 0);

            if (!mNotifyResponseListener) {
                char buffer[kBufferSize] = {0};
                if (checkSocket(newSocket) == 1) {
                    if (recv(newSocket, buffer, kBufferSize, MSG_DONTWAIT) > 0) {
                        // Extract the 'CSeq' value present at the end of header
                        std::string clientResponse(buffer);
                        std::string header =
                                clientResponse.substr(0, clientResponse.find(kHeaderBoundary));
                        char cseq = header[header.rfind(kCSeq) + kCSeq.length()];
                        int32_t cseqValue = cseq ? cseq - '0' : kDefaultCseqValue;
                        sendValidResponse(newSocket, cseqValue);
                    } else {
                        sendValidResponse(newSocket);
                    }
                }
            }
        } else {
            // If no data to read, then send a valid response
            // to release the mutex lock in fuzzer
            sendValidResponse(newSocket);
        }
    }
    send(newSocket, kQuitResponse.c_str(), kQuitResponse.size(), 0);
}

void RTSPConnectionFuzzer::startServer() {
    signal(SIGPIPE, SIG_IGN);
    mServerFd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serverAddress.sin_port = htons(kPort);

    // Get rid of "Address in use" error
    int32_t opt = 1;
    if (setsockopt(mServerFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        mServerFailure = true;
    }

    // Bind the socket and set for listening.
    if (bind(mServerFd, (struct sockaddr*)(&serverAddress), sizeof(serverAddress)) < 0) {
        mServerFailure = true;
    }

    if (listen(mServerFd, 5) < 0) {
        mServerFailure = true;
    }
}

void RTSPConnectionFuzzer::acceptConnection() {
    int32_t clientFd = accept4(mServerFd, nullptr, nullptr, SOCK_CLOEXEC);
    handleConnection(clientFd);
    close(clientFd);
}

void RTSPConnectionFuzzer::process() {
    startServer();
    if (mServerFailure) {
        return;
    }
    sp<ALooper> looper = sp<ALooper>::make();
    sp<FuzzAHandler> handler =
            sp<FuzzAHandler>::make(std::bind(&RTSPConnectionFuzzer::signalEos, this));
    sp<ARTSPConnection> rtspConnection =
            sp<ARTSPConnection>::make(mFdp.ConsumeBool(), mFdp.ConsumeIntegral<uint64_t>());
    looper->start();
    looper->registerHandler(rtspConnection);
    looper->registerHandler(handler);
    sp<AMessage> replymsg = sp<AMessage>::make(kWhat, handler);
    std::string url = kUrlPrefix + std::to_string(kPort) + "/";

    while (mFdp.remaining_bytes() && mThreadPool.size() < kMaxThreads) {
        createFuzzData();
        mThreadPool.push_back(std::thread(&RTSPConnectionFuzzer::acceptConnection, this));
        if (mFdp.ConsumeBool()) {
            rtspConnection->observeBinaryData(replymsg);
        }

        {
            rtspConnection->connect(url.c_str(), replymsg);
            std::unique_lock waitForMsgPostComplete(mMsgPostCompleteMutex);
            mConditionalVariable.wait(waitForMsgPostComplete, [this] {
                if (mEosReached == true) {
                    mEosReached = false;
                    return true;
                }
                return mEosReached;
            });
        }

        if (mRequestData != kDefaultRequestValue) {
            rtspConnection->sendRequest(mRequestData.c_str(), replymsg);
            std::unique_lock waitForMsgPostComplete(mMsgPostCompleteMutex);
            mConditionalVariable.wait(waitForMsgPostComplete, [this] {
                if (mEosReached == true) {
                    mEosReached = false;
                    return true;
                }
                return mEosReached;
            });
        }

        if (mFdp.ConsumeBool()) {
            rtspConnection->disconnect(replymsg);
            std::unique_lock waitForMsgPostComplete(mMsgPostCompleteMutex);
            mConditionalVariable.wait(waitForMsgPostComplete, [this] {
                if (mEosReached == true) {
                    mEosReached = false;
                    return true;
                }
                return mEosReached;
            });
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    RTSPConnectionFuzzer rtspFuzz(data, size);
    rtspFuzz.process();
    return 0;
}
