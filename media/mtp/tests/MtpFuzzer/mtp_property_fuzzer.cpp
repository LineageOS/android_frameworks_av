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
#include <MtpProperty.h>
#include <functional>
#include <fuzzer/FuzzedDataProvider.h>
#include <utils/String16.h>

using namespace android;

constexpr uint16_t kFeasibleTypes[] = {
        MTP_TYPE_UNDEFINED, MTP_TYPE_INT8,    MTP_TYPE_UINT8,  MTP_TYPE_INT16,   MTP_TYPE_UINT16,
        MTP_TYPE_INT32,     MTP_TYPE_UINT32,  MTP_TYPE_INT64,  MTP_TYPE_UINT64,  MTP_TYPE_INT128,
        MTP_TYPE_UINT128,   MTP_TYPE_AINT8,   MTP_TYPE_AUINT8, MTP_TYPE_AINT16,  MTP_TYPE_AUINT16,
        MTP_TYPE_AINT32,    MTP_TYPE_AUINT32, MTP_TYPE_AINT64, MTP_TYPE_AUINT64, MTP_TYPE_AINT128,
        MTP_TYPE_AUINT128,  MTP_TYPE_STR,
};

class MtpPropertyFuzzer : MtpPacketFuzzerUtils {
  public:
    MtpPropertyFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {
        mUsbDevFsUrb = (struct usbdevfs_urb*)malloc(sizeof(struct usbdevfs_urb) +
                                                    sizeof(struct usbdevfs_iso_packet_desc));
    };
    ~MtpPropertyFuzzer() { free(mUsbDevFsUrb); };
    void process();

  private:
    FuzzedDataProvider mFdp;
};

void MtpPropertyFuzzer::process() {
    MtpProperty* mtpProperty = nullptr;
    if (mFdp.ConsumeBool()) {
        mtpProperty = new MtpProperty();
    } else {
        uint16_t type = mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint16_t>()
                                           : mFdp.PickValueInArray<uint16_t>(kFeasibleTypes);
        mtpProperty = new MtpProperty(mFdp.ConsumeIntegral<uint16_t>(), type, mFdp.ConsumeBool(),
                                      mFdp.ConsumeIntegral<uint16_t>());
    }

    while (mFdp.remaining_bytes() > 0) {
        auto invokeMtpPropertyFuzzer = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    MtpDataPacket mtpDataPacket;
                    if (mFdp.ConsumeBool()) {
                        mtpProperty->read(mtpDataPacket);

                    } else {
                        if (mFdp.ConsumeBool()) {
#ifdef MTP_DEVICE
                            android::IMtpHandle* h = new MtpDevHandle();
                            h->start(mFdp.ConsumeBool());
                            std::string text = mFdp.ConsumeRandomLengthString(kMaxLength);
                            char* data = const_cast<char*>(text.c_str());
                            h->read(static_cast<void*>(data), text.length());
                            mtpDataPacket.write(h);
                            h->close();
                            delete h;
#endif

#ifdef MTP_HOST
                            fillFilePath(&mFdp);
                            int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                            fillUsbRequest(fd, &mFdp);
                            mUsbRequest.dev = usb_device_new(mPath.c_str(), fd);
                            mtpDataPacket.write(&mUsbRequest,
                                                mFdp.PickValueInArray<UrbPacketDivisionMode>(
                                                        kUrbPacketDivisionModes),
                                                fd,
                                                mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize));
                            usb_device_close(mUsbRequest.dev);
#endif
                        }

                        if (mFdp.ConsumeBool()) {
                            mtpProperty->write(mtpDataPacket);
                        } else {
                            mtpProperty->setCurrentValue(mtpDataPacket);
                        }
                    }
                },
                [&]() {
                    char16_t* data = nullptr;
                    std::string str = mFdp.ConsumeRandomLengthString(kMaxLength);
                    android::String16 s(str.c_str());
                    if (mFdp.ConsumeBool()) {
                        data = const_cast<char16_t*>(s.c_str());
                    }

                    if (mFdp.ConsumeBool()) {
                        mtpProperty->setDefaultValue(reinterpret_cast<uint16_t*>(data));
                    } else if (mFdp.ConsumeBool()) {
                        mtpProperty->setCurrentValue(reinterpret_cast<uint16_t*>(data));
                    } else {
                        mtpProperty->setCurrentValue(str.c_str());
                    }
                },
                [&]() {
                    mtpProperty->setFormRange(mFdp.ConsumeIntegral<int32_t>(),
                                              mFdp.ConsumeIntegral<int32_t>(),
                                              mFdp.ConsumeIntegral<int32_t>());
                },
                [&]() {
                    std::vector<int32_t> init;
                    for (size_t idx = 0; idx < mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize);
                         ++idx) {
                        init.push_back(mFdp.ConsumeIntegral<int32_t>());
                    }
                    mtpProperty->setFormEnum(init.data(), init.size());
                },
        });
        invokeMtpPropertyFuzzer();
    }

    delete (mtpProperty);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    MtpPropertyFuzzer mtpPropertyFuzzer(data, size);
    mtpPropertyFuzzer.process();
    return 0;
}
