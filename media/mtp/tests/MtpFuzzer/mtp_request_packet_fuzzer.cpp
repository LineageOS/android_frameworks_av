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
#include <MtpPacketFuzzerUtils.h>
#include <MtpRequestPacket.h>
#include <fstream>
#include <functional>
#include <fuzzer/FuzzedDataProvider.h>

using namespace android;

std::string kMtpDevPath = "/dev/mtp_usb";
constexpr int32_t kMaxBytes = 100000;

class MtpRequestPacketFuzzer : MtpPacketFuzzerUtils {
  public:
    MtpRequestPacketFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {
        mUsbDevFsUrb = (struct usbdevfs_urb*)malloc(sizeof(struct usbdevfs_urb) +
                                                   sizeof(struct usbdevfs_iso_packet_desc));
    };
    ~MtpRequestPacketFuzzer() { free(mUsbDevFsUrb); };
    void process();

  private:
    FuzzedDataProvider mFdp;
    void makeFile(std::string s);
};

void MtpRequestPacketFuzzer::process() {
    MtpRequestPacket mtpRequestPacket;
    while (mFdp.remaining_bytes() > 0) {
        auto mtpRequestAPI = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    mtpRequestPacket.allocate(mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize));
                },
                [&]() { mtpRequestPacket.reset(); },
                [&]() {
                    MtpDevHandle handle;
                    makeFile(kMtpDevPath);
                    handle.start(mFdp.ConsumeBool());
                    std::vector<uint8_t> data = mFdp.ConsumeBytes<uint8_t>(
                            mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize));
                    handle.write(data.data(), data.size());
                    mtpRequestPacket.read(&handle);
                    handle.close();
                    remove(kMtpDevPath.c_str());
                },
                [&]() {
                    fillFilePath(&mFdp);
                    int32_t fd = memfd_create(mPath.c_str(), MFD_ALLOW_SEALING);
                    fillUsbRequest(fd, &mFdp);
                    mUsbRequest.dev = usb_device_new(mPath.c_str(), fd);
                    mtpRequestPacket.write(&mUsbRequest);
                    usb_device_close(mUsbRequest.dev);
                },
        });
        mtpRequestAPI();
    }
}

void MtpRequestPacketFuzzer::makeFile(std::string s) {
    std::ofstream out;
    out.open(s, std::ios::binary | std::ofstream::trunc);
    for (int32_t idx = 0; idx < mFdp.ConsumeIntegralInRange<int32_t>(kMinSize, kMaxSize); ++idx) {
        out << mFdp.ConsumeRandomLengthString(kMaxBytes) << "\n";
    }
    out.close();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    MtpRequestPacketFuzzer mtpRequestPacketFuzzer(data, size);
    mtpRequestPacketFuzzer.process();
    return 0;
}
