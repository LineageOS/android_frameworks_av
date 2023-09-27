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
#include <MtpDevice.h>
#include <MtpDeviceInfo.h>
#include <MtpObjectInfo.h>
#include <MtpProperty.h>
#include <MtpStorageInfo.h>
#include <MtpStringBuffer.h>
#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <functional>
#include <fuzzer/FuzzedDataProvider.h>
#include <linux/usb/ch9.h>
#include <sys/mman.h>
#include <unistd.h>
#include <usbhost/usbhost.h>

using namespace android;

constexpr int32_t kMaxStringLength = 20;
constexpr int32_t kMaxBytes = 200;
constexpr int32_t kMaxDataSize = 20;
constexpr uint16_t kWMaxPacketSize = 64;
constexpr uint16_t kEndpointsCount = 3;
const std::string kInputFile = "/dev/null";
const std::string kConfigFilePath = "/data/local/tmp/config";

static bool readCallback(void* data, uint32_t offset, uint32_t length, void* clientData) {
    return true;
}

struct fdDescriptors {
    struct usb_interface_descriptor interface;
    struct usb_endpoint_descriptor ep[kEndpointsCount];
};

fdDescriptors writeDescriptorsToFd(int32_t fd, FuzzedDataProvider& fdp) {
    fdDescriptors desc;
    desc.interface.bLength = sizeof(desc.interface);
    desc.interface.bDescriptorType = USB_DT_INTERFACE;
    desc.interface.bInterfaceNumber = fdp.ConsumeIntegral<uint8_t>();
    desc.interface.bNumEndpoints = kEndpointsCount;
    desc.interface.bInterfaceClass =
            fdp.ConsumeBool() ? USB_CLASS_STILL_IMAGE : USB_CLASS_VENDOR_SPEC;
    desc.interface.bInterfaceSubClass = fdp.ConsumeBool() ? 1 : 0xFF;
    desc.interface.bInterfaceProtocol = fdp.ConsumeBool() ? 1 : 0;
    desc.interface.iInterface = fdp.ConsumeIntegral<uint8_t>();
    for (uint16_t idx = 0; idx < kEndpointsCount; ++idx) {
        desc.ep[idx].bLength = sizeof(desc.ep[idx]);
        desc.ep[idx].bDescriptorType = USB_DT_ENDPOINT;
        desc.ep[idx].bEndpointAddress = idx | (fdp.ConsumeBool() ? USB_DIR_OUT : USB_DIR_IN);
        desc.ep[idx].bmAttributes =
                fdp.ConsumeBool() ? USB_ENDPOINT_XFER_BULK : USB_ENDPOINT_XFER_INT;
        desc.ep[idx].wMaxPacketSize = kWMaxPacketSize;
    }
    write(fd, &desc, sizeof(fdDescriptors));
    return desc;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    int32_t fd = memfd_create(kConfigFilePath.c_str(), MFD_ALLOW_SEALING);
    fdDescriptors descriptor = writeDescriptorsToFd(fd, fdp);
    std::string deviceName = fdp.ConsumeRandomLengthString(kMaxStringLength);
    usb_device* device = usb_device_new(deviceName.c_str(), fd);
    MtpDevice mtpDevice(device, fdp.ConsumeIntegral<int32_t>(), &descriptor.ep[0],
                        &descriptor.ep[1], &descriptor.ep[2]);
    while (fdp.remaining_bytes()) {
        auto mtpDeviceFunction = fdp.PickValueInArray<const std::function<void()>>(
                {[&]() { mtpDevice.getStorageIDs(); },
                 [&]() {
                     mtpDevice.getStorageInfo(fdp.ConsumeIntegral<int32_t>() /* storageID */);
                 },
                 [&]() {
                     mtpDevice.getObjectHandles(fdp.ConsumeIntegral<uint32_t>() /* storageID */,
                                                fdp.ConsumeIntegral<uint16_t>() /* format */,
                                                fdp.ConsumeIntegral<uint32_t>() /* parent */);
                 },
                 [&]() { mtpDevice.initialize(); },
                 [&]() {
                     int32_t outLength = 0;
                     mtpDevice.getThumbnail(fdp.ConsumeIntegral<uint32_t>() /* handle */,
                                            outLength);
                 },
                 [&]() {
                     MtpObjectInfo mtpObjectInfo(fdp.ConsumeIntegral<uint32_t>() /* handle */);
                     std::string name = fdp.ConsumeRandomLengthString(kMaxStringLength);
                     std::string keywords = fdp.ConsumeRandomLengthString(kMaxStringLength);
                     mtpObjectInfo.mName = strdup(name.c_str());
                     mtpObjectInfo.mKeywords = strdup(keywords.c_str());
                     mtpDevice.sendObjectInfo(&mtpObjectInfo);
                 },
                 [&]() {
                     mtpDevice.sendObject(fdp.ConsumeIntegral<uint32_t>() /* handle */,
                                          fdp.ConsumeIntegral<uint32_t>() /* size */, fd);
                 },
                 [&]() { mtpDevice.deleteObject(fdp.ConsumeIntegral<uint32_t>() /* handle */); },
                 [&]() {
                     mtpDevice.getObjectPropsSupported(
                             fdp.ConsumeIntegral<uint16_t>() /* format */);
                 },
                 [&]() {
                     MtpDataType dataType = fdp.ConsumeIntegral<int16_t>();
                     MtpProperty mtpProperty(fdp.ConsumeIntegral<int16_t>() /* propCode */,
                                             dataType, fdp.ConsumeBool() /* writeable */,
                                             fdp.ConsumeIntegral<int32_t>() /* defaultValue */);
                     if (dataType == MTP_TYPE_STR) {
                         mtpProperty.setCurrentValue(
                                 fdp.ConsumeRandomLengthString(kMaxStringLength).c_str());
                     }
                     mtpDevice.setDevicePropValueStr(&mtpProperty);
                 },
                 [&]() {
                     mtpDevice.getObjectPropDesc(fdp.ConsumeIntegral<uint16_t>() /* code */,
                                                 fdp.ConsumeIntegral<uint16_t>() /* format */);
                 },
                 [&]() {
                     MtpProperty property;
                     mtpDevice.getObjectPropValue(fdp.ConsumeIntegral<uint16_t>() /* handle */,
                                                  &property);
                 },
                 [&]() {
                     std::vector<uint8_t> clientData = fdp.ConsumeBytes<uint8_t>(kMaxDataSize);
                     mtpDevice.readObject(
                             fdp.ConsumeIntegral<uint32_t>() /* handle */, readCallback,
                             fdp.ConsumeIntegral<uint32_t>() /* objectSize */, &clientData);
                 },
                 [&]() {
                     std::vector<uint8_t> clientData = fdp.ConsumeBytes<uint8_t>(kMaxDataSize);
                     uint32_t writtenSize = 0;
                     mtpDevice.readPartialObject(fdp.ConsumeIntegral<uint32_t>() /* handle */,
                                                 fdp.ConsumeIntegral<uint32_t>() /* offset */,
                                                 fdp.ConsumeIntegral<uint32_t>() /* size */,
                                                 &writtenSize, readCallback, &clientData);
                 },
                 [&]() {
                     std::vector<uint8_t> clientData = fdp.ConsumeBytes<uint8_t>(kMaxDataSize);
                     uint32_t writtenSize = 0;
                     mtpDevice.readPartialObject(fdp.ConsumeIntegral<uint32_t>() /* handle */,
                                                 fdp.ConsumeIntegral<uint64_t>() /* offset */,
                                                 fdp.ConsumeIntegral<uint32_t>() /* size */,
                                                 &writtenSize, readCallback, &clientData);
                 },
                 [&]() {
                     if (mtpDevice.submitEventRequest() != -1) {
                         uint32_t parameters[3];
                         mtpDevice.reapEventRequest(fdp.ConsumeIntegral<int32_t>() /* handle */,
                                                    &parameters);
                     }
                 },
                 [&]() {
                     mtpDevice.discardEventRequest(fdp.ConsumeIntegral<int32_t>() /*handle*/);
                 },
                 [&]() {
                     mtpDevice.discardEventRequest(fdp.ConsumeIntegral<int32_t>() /* handle */);
                 },
                 [&]() { mtpDevice.print(); },
                 [&]() { mtpDevice.getDeviceName(); },
                 [&]() { mtpDevice.getObjectInfo(fdp.ConsumeIntegral<uint32_t>() /* handle */); },
                 [&]() { mtpDevice.getParent(fdp.ConsumeIntegral<uint32_t>() /* handle */); },
                 [&]() { mtpDevice.getStorageID(fdp.ConsumeIntegral<uint32_t>() /* handle */); },
                 [&]() { mtpDevice.getDevicePropDesc(fdp.ConsumeIntegral<uint16_t>() /* code */); },
                 [&]() {
                     mtpDevice.readObject(
                             fdp.ConsumeIntegral<uint32_t>() /* handle */,
                             fdp.ConsumeRandomLengthString(kMaxStringLength).c_str() /* destPath */,
                             fdp.ConsumeIntegral<int32_t>() /* group */,
                             fdp.ConsumeIntegral<int32_t>() /* perm */);
                 },
                 [&]() {
                     int32_t filefd = open(kConfigFilePath.c_str(), O_CREAT | O_RDWR);
                     mtpDevice.readObject(fdp.ConsumeIntegral<uint16_t>() /* handle */, filefd);
                     close(filefd);
                 },
                 [&]() { MtpDevice::open(deviceName.c_str(), fd); },
                 [&]() {
                     MtpObjectInfo objectinfo(fdp.ConsumeIntegral<uint32_t>() /* handle */);
                     MtpDataPacket mtpDataPacket;
                     MtpDevHandle devHandle;
                     std::vector<uint8_t> packet = fdp.ConsumeBytes<uint8_t>(kMaxBytes);
                     mtpDataPacket.writeData(&devHandle, packet.data(), packet.size());
                     objectinfo.read(mtpDataPacket);
                     objectinfo.print();
                 },
                 [&]() {
                     MtpStorageInfo storageInfo(fdp.ConsumeIntegral<uint32_t>() /* id */);
                     MtpDataPacket mtpDataPacket;
                     MtpDevHandle devHandle;
                     std::vector<uint8_t> packet = fdp.ConsumeBytes<uint8_t>(kMaxBytes);
                     mtpDataPacket.writeData(&devHandle, packet.data(), packet.size());
                     storageInfo.read(mtpDataPacket);
                     storageInfo.print();
                 }});
        mtpDeviceFunction();
    }
    close(fd);
    return 0;
}
