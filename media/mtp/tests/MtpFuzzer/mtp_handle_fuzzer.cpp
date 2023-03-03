/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <MtpDescriptors.h>
#include <MtpFfsCompatHandle.h>
#include <android-base/file.h>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <mtp.h>

using namespace android;

constexpr int32_t kMaxStringLength = 64;
constexpr int32_t kMinAPICase = 0;
constexpr int32_t kMaxMtpHandleAPI = 5;
constexpr int32_t kMinBufferSize = 0;
constexpr uint32_t kMaxMtpFileSize = 0xFFFFFFFF;
constexpr float kDataSizeFactor = 0.1;

const std::string kTempPath = "/data/local/tmp/";
const std::string kFuzzerUsbDirPath = kTempPath + "usb-ffs";
const std::string kFuzzerMtpPath = kFuzzerUsbDirPath + "/mtp";
const std::string kFuzzerPtpPath = kFuzzerUsbDirPath + "/ptp";
const std::string kFuzzerTestFile = kTempPath + "FuzzerTestDescriptorFile";
const std::string kFuzzerMtpInputFile = kTempPath + "FuzzerMtpInputFile";
const std::string kFuzzerMtpOutputFile = kTempPath + "FuzzerMtpOutputFile";

const std::string kDeviceFilePaths[] = {FFS_MTP_EP0,    FFS_MTP_EP_IN, FFS_MTP_EP_INTR,
                                        FFS_PTP_EP0,    FFS_PTP_EP_IN, FFS_PTP_EP_INTR,
                                        FFS_MTP_EP_OUT, FFS_PTP_EP_OUT};

class MtpFfsHandleFuzzer {
  public:
    MtpFfsHandleFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {
        mDataSize = kDataSizeFactor * size;
        createFiles();
    };
    void process();

    ~MtpFfsHandleFuzzer() { removeFiles(); };

  private:
    FuzzedDataProvider mFdp;
    void invokeWriteDescriptor();
    void invokeMtpFfsHandle();
    void createFiles();
    void removeFiles();
    void createDeviceFile(const char* file);
    void writeDeviceFile(const char* file);
    int32_t writeInputFile(int32_t fd);
    uint32_t mDataSize = 0;
};

int32_t MtpFfsHandleFuzzer::writeInputFile(int32_t fd) {
    uint32_t minFileSize = std::min((uint32_t)MTP_BUFFER_SIZE, mDataSize);
    uint32_t maxFileSize = std::min(mDataSize, kMaxMtpFileSize);
    std::vector<char> dataBuffer = mFdp.ConsumeBytes<char>(
            mFdp.ConsumeIntegralInRange<uint32_t>(minFileSize, maxFileSize));
    write(fd, dataBuffer.data(), dataBuffer.size());
    lseek(fd, 0, SEEK_SET);
    return dataBuffer.size();
}

void MtpFfsHandleFuzzer::createDeviceFile(const char* file) {
    int32_t fd = open(file, O_CREAT | O_RDWR | O_NONBLOCK);
    close(fd);
}

void MtpFfsHandleFuzzer::writeDeviceFile(const char* file) {
    int32_t fd = open(file, O_RDWR | O_NONBLOCK);
    writeInputFile(fd);
    close(fd);
}

void MtpFfsHandleFuzzer::createFiles() {
    mkdir(kFuzzerUsbDirPath.c_str(), 0755);
    mkdir(kFuzzerMtpPath.c_str(), 0755);
    mkdir(kFuzzerPtpPath.c_str(), 0755);

    for (auto path : kDeviceFilePaths) {
        createDeviceFile(path.c_str());
    }

    writeDeviceFile(FFS_MTP_EP_OUT);
    writeDeviceFile(FFS_PTP_EP_OUT);
}

void MtpFfsHandleFuzzer::removeFiles() {
    for (auto path : kDeviceFilePaths) {
        remove(path.c_str());
    }

    rmdir(kFuzzerMtpPath.c_str());
    rmdir(kFuzzerPtpPath.c_str());
    rmdir(kFuzzerUsbDirPath.c_str());
}

void MtpFfsHandleFuzzer::invokeWriteDescriptor() {
    while (mFdp.remaining_bytes() > 0) {
        int32_t controlFd = mFdp.ConsumeBool()
                                    ? -1 /* Invalid fd*/
                                    : open(kFuzzerTestFile.c_str(), O_CREAT | O_RDWR | O_NONBLOCK);
        std::unique_ptr<MtpFfsHandle> handle(new MtpFfsHandle(controlFd));
        handle->writeDescriptors(mFdp.ConsumeBool());
        handle->close();
        close(controlFd);
        remove(kFuzzerTestFile.c_str());
    }
}

void MtpFfsHandleFuzzer::invokeMtpFfsHandle() {
    while (mFdp.remaining_bytes() > 0) {
        int32_t controlFd = open(kFuzzerTestFile.c_str(), O_CREAT | O_RDWR | O_NONBLOCK);
        writeInputFile(controlFd);

        std::unique_ptr<IMtpHandle> handle;
        if (mFdp.ConsumeBool()) {
            std::unique_ptr<IMtpHandle> mtpCompactHandle(new MtpFfsCompatHandle(controlFd));
            handle = std::move(mtpCompactHandle);
        } else {
            std::unique_ptr<IMtpHandle> mtpHandle(new MtpFfsHandle(controlFd));
            handle = std::move(mtpHandle);
        }

        int32_t mtpHandle = mFdp.ConsumeIntegralInRange<size_t>(kMinAPICase, kMaxMtpHandleAPI);
        switch (mtpHandle) {
            case 0: {
                handle->start(mFdp.ConsumeBool());
                break;
            }
            case 1: {
                std::string data = mFdp.ConsumeRandomLengthString(MTP_BUFFER_SIZE);
                handle->write(data.c_str(), data.length());
                break;
            }
            case 2: {
                int32_t bufferSize =
                        mFdp.ConsumeIntegralInRange<size_t>(kMinBufferSize, MTP_BUFFER_SIZE);
                uint8_t buffer[bufferSize + 1];
                handle->read(buffer, bufferSize);
                break;
            }
            case 3: {
                mtp_file_range mfr;
                mfr.fd = open(kFuzzerMtpInputFile.c_str(), O_CREAT | O_RDWR | O_NONBLOCK);
                mfr.length = writeInputFile(mfr.fd);
                mfr.offset = 0; /* Offset point to the start of the file */
                mfr.command = mFdp.ConsumeIntegral<uint16_t>();
                mfr.transaction_id = mFdp.ConsumeIntegral<uint32_t>();
                handle->sendFile(mfr);
                close(mfr.fd);
                remove(kFuzzerMtpInputFile.c_str());
                break;
            }
            case 4: {
                struct mtp_event event;
                std::string dataValue = mFdp.ConsumeRandomLengthString(kMaxStringLength);
                event.data = const_cast<char*>(dataValue.c_str());
                event.length = dataValue.length();
                handle->sendEvent(event);
                break;
            }
            case 5:
            default: {
                mtp_file_range mfr;
                mfr.fd = open(kFuzzerMtpOutputFile.c_str(), O_CREAT | O_RDWR | O_NONBLOCK);
                mfr.offset = 0; /* Offset point to the start of the file */
                mfr.length = kMaxMtpFileSize;
                handle->receiveFile(mfr, mFdp.ConsumeBool());
                close(mfr.fd);
                remove(kFuzzerMtpOutputFile.c_str());
                break;
            }
        }
        handle->close();
        close(controlFd);
        remove(kFuzzerTestFile.c_str());
    }
}

void MtpFfsHandleFuzzer::process() {
    if (mFdp.ConsumeBool()) {
        invokeMtpFfsHandle();
    } else {
        invokeWriteDescriptor();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    MtpFfsHandleFuzzer mtpFfsHandleFuzzer(data, size);
    mtpFfsHandleFuzzer.process();
    return 0;
}
