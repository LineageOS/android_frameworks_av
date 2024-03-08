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

#include <MtpDevHandle.h>
#include <MtpEventPacket.h>
#include <MtpPacketFuzzerUtils.h>
#include <functional>
#include <fuzzer/FuzzedDataProvider.h>

using namespace android;

class MtpEventPacketFuzzer : MtpPacketFuzzerUtils {
  public:
    MtpEventPacketFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {
        mUsbDevFsUrb = (struct usbdevfs_urb*)malloc(sizeof(struct usbdevfs_urb) +
                                                   sizeof(struct usbdevfs_iso_packet_desc));
    };
    ~MtpEventPacketFuzzer() { free(mUsbDevFsUrb); };
    void process();

  private:
    FuzzedDataProvider mFdp;
};

void MtpEventPacketFuzzer::process() {
    MtpEventPacket mtpEventPacket;
    while (mFdp.remaining_bytes() > 0) {
        auto mtpEventAPI = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() { mtpEventPacket.allocate(mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize)); },
                [&]() { mtpEventPacket.reset(); },
                [&]() { writeHandle(&mtpEventPacket, &mFdp); },
                [&]() {
                    fillFilePath(&mFdp);
                    int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                    fillUsbRequest(fd, &mFdp);
                    mUsbRequest.dev = usb_device_new(mPath.c_str(), fd);
                    mtpEventPacket.sendRequest(&mUsbRequest);
                    usb_device_close(mUsbRequest.dev);
                },
                [&]() {
                    fillFilePath(&mFdp);
                    int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                    fillFd(fd, &mFdp);
                    struct usb_device* device = usb_device_new(mPath.c_str(), fd);
                    mtpEventPacket.readResponse(device);
                    usb_device_close(device);
                },
        });
        mtpEventAPI();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    MtpEventPacketFuzzer mtpEventPacketFuzzer(data, size);
    mtpEventPacketFuzzer.process();
    return 0;
}
