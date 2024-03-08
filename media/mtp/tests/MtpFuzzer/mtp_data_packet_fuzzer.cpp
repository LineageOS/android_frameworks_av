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

#include <MtpDataPacket.h>
#include <MtpDevHandle.h>
#include <MtpPacketFuzzerUtils.h>
#include <functional>
#include <fuzzer/FuzzedDataProvider.h>
#include <utils/String16.h>

using namespace android;

class MtpDataPacketFuzzer : MtpPacketFuzzerUtils {
  public:
    MtpDataPacketFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {
        mUsbDevFsUrb = (struct usbdevfs_urb*)malloc(sizeof(struct usbdevfs_urb) +
                                                   sizeof(struct usbdevfs_iso_packet_desc));
    };
    ~MtpDataPacketFuzzer() { free(mUsbDevFsUrb); };
    void process();

  private:
    FuzzedDataProvider mFdp;
};

void MtpDataPacketFuzzer::process() {
    MtpDataPacket mtpDataPacket;
    while (mFdp.remaining_bytes() > 0) {
        auto mtpDataAPI = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() { mtpDataPacket.allocate(mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize)); },
                [&]() { mtpDataPacket.reset(); },
                [&]() {
                    mtpDataPacket.setOperationCode(mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize));
                },
                [&]() {
                    mtpDataPacket.setTransactionID(mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize));
                },
                [&]() {
                    Int8List* result = mtpDataPacket.getAInt8();
                    delete result;
                },
                [&]() {
                    Int16List* result = mtpDataPacket.getAInt16();
                    delete result;
                },
                [&]() {
                    Int32List* result = mtpDataPacket.getAInt32();
                    delete result;
                },
                [&]() {
                    Int64List* result = mtpDataPacket.getAInt64();
                    delete result;
                },
                [&]() {
                    UInt8List* result = mtpDataPacket.getAUInt8();
                    delete result;
                },
                [&]() {
                    UInt16List* result = mtpDataPacket.getAUInt16();
                    delete result;
                },
                [&]() {
                    UInt32List* result = mtpDataPacket.getAUInt32();
                    delete result;
                },
                [&]() {
                    UInt64List* result = mtpDataPacket.getAUInt64();
                    delete result;
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        std::vector<uint8_t> initData =
                                mFdp.ConsumeBytes<uint8_t>(mFdp.ConsumeIntegral<uint8_t>());
                        mtpDataPacket.putAUInt8(initData.data(), initData.size());
                    } else {
                        mtpDataPacket.putAUInt8(nullptr, 0);
                    }
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        size_t size = mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize);
                        uint16_t arr[size];
                        for (size_t idx = 0; idx < size; ++idx) {
                            arr[idx] = mFdp.ConsumeIntegral<uint16_t>();
                        }
                        mtpDataPacket.putAUInt16(arr, size);
                    } else {
                        mtpDataPacket.putAUInt16(nullptr, 0);
                    }
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        size_t size = mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize);
                        uint32_t arr[size];
                        for (size_t idx = 0; idx < size; ++idx) {
                            arr[idx] = mFdp.ConsumeIntegral<uint32_t>();
                        }
                        mtpDataPacket.putAUInt32(arr, size);
                    } else {
                        mtpDataPacket.putAUInt32(nullptr, 0);
                    }
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        size_t size = mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize);
                        uint64_t arr[size];
                        for (size_t idx = 0; idx < size; ++idx) {
                            arr[idx] = mFdp.ConsumeIntegral<uint64_t>();
                        }
                        mtpDataPacket.putAUInt64(arr, size);
                    } else {
                        mtpDataPacket.putAUInt64(nullptr, 0);
                    }
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        size_t size = mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize);
                        int64_t arr[size];
                        for (size_t idx = 0; idx < size; ++idx) {
                            arr[idx] = mFdp.ConsumeIntegral<int64_t>();
                        }
                        mtpDataPacket.putAInt64(arr, size);
                    } else {
                        mtpDataPacket.putAInt64(nullptr, 0);
                    }
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        std::vector<uint16_t> arr;
                        size_t size = mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize);
                        for (size_t idx = 0; idx < size; ++idx) {
                            arr.push_back(mFdp.ConsumeIntegral<uint16_t>());
                        }
                        mtpDataPacket.putAUInt16(&arr);
                    } else {
                        mtpDataPacket.putAUInt16(nullptr);
                    }
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        std::vector<uint32_t> arr;
                        size_t size = mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize);
                        for (size_t idx = 0; idx < size; ++idx) {
                            arr.push_back(mFdp.ConsumeIntegral<uint32_t>());
                        }
                        mtpDataPacket.putAUInt32(&arr);
                    } else {
                        mtpDataPacket.putAUInt32(nullptr);
                    }
                },

                [&]() {
                    if (mFdp.ConsumeBool()) {
                        size_t size = mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize);
                        int32_t arr[size];
                        for (size_t idx = 0; idx < size; ++idx) {
                            arr[idx] = mFdp.ConsumeIntegral<int32_t>();
                        }
                        mtpDataPacket.putAInt32(arr, size);
                    } else {
                        mtpDataPacket.putAInt32(nullptr, 0);
                    }
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        mtpDataPacket.putString(
                                (mFdp.ConsumeRandomLengthString(kMaxLength)).c_str());
                    } else {
                        mtpDataPacket.putString(static_cast<char*>(nullptr));
                    }
                },
                [&]() {
                    android::MtpStringBuffer sBuffer(
                            (mFdp.ConsumeRandomLengthString(kMaxLength)).c_str());
                    if (mFdp.ConsumeBool()) {
                        mtpDataPacket.getString(sBuffer);
                    } else {
                        mtpDataPacket.putString(sBuffer);
                    }
                },
                [&]() {
                    MtpDevHandle handle;
                    handle.start(mFdp.ConsumeBool());
                    std::string text = mFdp.ConsumeRandomLengthString(kMaxLength);
                    char* data = const_cast<char*>(text.c_str());
                    handle.read(static_cast<void*>(data), text.length());
                    if (mFdp.ConsumeBool()) {
                        mtpDataPacket.read(&handle);
                    } else if (mFdp.ConsumeBool()) {
                        mtpDataPacket.write(&handle);
                    } else {
                        std::string textData = mFdp.ConsumeRandomLengthString(kMaxLength);
                        char* Data = const_cast<char*>(textData.c_str());
                        mtpDataPacket.writeData(&handle, static_cast<void*>(Data),
                                                textData.length());
                    }
                    handle.close();
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        std::string str = mFdp.ConsumeRandomLengthString(kMaxLength);
                        android::String16 s(str.c_str());
                        char16_t* data = const_cast<char16_t*>(s.c_str());
                        mtpDataPacket.putString(reinterpret_cast<uint16_t*>(data));
                    } else {
                        mtpDataPacket.putString(static_cast<uint16_t*>(nullptr));
                    }
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        std::vector<int8_t> data = mFdp.ConsumeBytes<int8_t>(
                                mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize));
                        mtpDataPacket.putAInt8(data.data(), data.size());
                    } else {
                        mtpDataPacket.putAInt8(nullptr, 0);
                    }
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        std::vector<uint8_t> data = mFdp.ConsumeBytes<uint8_t>(
                                mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize));
                        mtpDataPacket.putAUInt8(data.data(), data.size());
                    } else {
                        mtpDataPacket.putAUInt8(nullptr, 0);
                    }
                },
                [&]() {
                    fillFilePath(&mFdp);
                    int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                    fillUsbRequest(fd, &mFdp);
                    mUsbRequest.dev = usb_device_new(mPath.c_str(), fd);
                    std::vector<int8_t> data = mFdp.ConsumeBytes<int8_t>(
                            mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize));
                    mtpDataPacket.readData(&mUsbRequest, data.data(), data.size());
                    usb_device_close(mUsbRequest.dev);
                },
                [&]() {
                    fillFilePath(&mFdp);
                    int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                    fillUsbRequest(fd, &mFdp);
                    mUsbRequest.dev = usb_device_new(mPath.c_str(), fd);
                    mtpDataPacket.write(
                            &mUsbRequest,
                            mFdp.PickValueInArray<UrbPacketDivisionMode>(kUrbPacketDivisionModes),
                            fd, mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize));
                    usb_device_close(mUsbRequest.dev);
                },
                [&]() {
                    fillFilePath(&mFdp);
                    int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                    fillUsbRequest(fd, &mFdp);
                    mUsbRequest.dev = usb_device_new(mPath.c_str(), fd);
                    mtpDataPacket.read(&mUsbRequest);
                    usb_device_close(mUsbRequest.dev);
                },
                [&]() {
                    fillFilePath(&mFdp);
                    int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                    fillUsbRequest(fd, &mFdp);
                    mUsbRequest.dev = usb_device_new(mPath.c_str(), fd);
                    mtpDataPacket.write(&mUsbRequest, mFdp.PickValueInArray<UrbPacketDivisionMode>(
                                                             kUrbPacketDivisionModes));
                    usb_device_close(mUsbRequest.dev);
                },
                [&]() {
                    fillFilePath(&mFdp);
                    int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                    fillUsbRequest(fd, &mFdp);
                    mUsbRequest.dev = usb_device_new(mPath.c_str(), fd);
                    mtpDataPacket.readDataHeader(&mUsbRequest);
                    usb_device_close(mUsbRequest.dev);
                },
                [&]() {
                    fillFilePath(&mFdp);
                    int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                    fillUsbRequest(fd, &mFdp);
                    mUsbRequest.dev = usb_device_new(mPath.c_str(), fd);
                    mtpDataPacket.readDataAsync(&mUsbRequest);
                    usb_device_close(mUsbRequest.dev);
                },
                [&]() {
                    fillFilePath(&mFdp);
                    int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                    fillUsbRequest(fd, &mFdp);
                    mUsbRequest.dev = usb_device_new(mPath.c_str(), fd);
                    mtpDataPacket.readDataWait(mUsbRequest.dev);
                    usb_device_close(mUsbRequest.dev);
                },
                [&]() {
                    if (mFdp.ConsumeBool()) {
                        std::vector<int16_t> data;
                        for (size_t idx = 0;
                             idx < mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize); ++idx) {
                            data.push_back(mFdp.ConsumeIntegral<int16_t>());
                        }
                        mtpDataPacket.putAInt16(data.data(), data.size());
                    } else {
                        mtpDataPacket.putAInt16(nullptr, 0);
                    }
                },
                [&]() {
                    int32_t arr[4];
                    for (size_t idx = 0; idx < 4; ++idx) {
                        arr[idx] = mFdp.ConsumeIntegral<int32_t>();
                    }
                    mtpDataPacket.putInt128(arr);
                },
                [&]() { mtpDataPacket.putInt64(mFdp.ConsumeIntegral<int64_t>()); },
                [&]() {
                    int16_t out;
                    mtpDataPacket.getInt16(out);
                },
                [&]() {
                    int32_t out;
                    mtpDataPacket.getInt32(out);
                },
                [&]() {
                    int8_t out;
                    mtpDataPacket.getInt8(out);
                },
                [&]() {
                    uint32_t arr[4];
                    for (size_t idx = 0; idx < 4; ++idx) {
                        arr[idx] = mFdp.ConsumeIntegral<uint32_t>();
                    }
                    if (mFdp.ConsumeBool()) {
                        mtpDataPacket.putUInt128(arr);
                    } else {
                        mtpDataPacket.getUInt128(arr);
                    }
                },
                [&]() { mtpDataPacket.putUInt64(mFdp.ConsumeIntegral<uint64_t>()); },
                [&]() {
                    uint64_t out;
                    mtpDataPacket.getUInt64(out);
                },
                [&]() { mtpDataPacket.putInt128(mFdp.ConsumeIntegral<int64_t>()); },
                [&]() { mtpDataPacket.putUInt128(mFdp.ConsumeIntegral<uint64_t>()); },
                [&]() {
                    int32_t length;
                    void* data = mtpDataPacket.getData(&length);
                    free(data);
                },
        });
        mtpDataAPI();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    MtpDataPacketFuzzer mtpDataPacketFuzzer(data, size);
    mtpDataPacketFuzzer.process();
    return 0;
}
