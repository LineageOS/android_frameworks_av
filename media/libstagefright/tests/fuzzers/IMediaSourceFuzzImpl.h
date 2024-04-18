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

#ifndef IMEDIASOURCEFUZZIMPL_H
#define IMEDIASOURCEFUZZIMPL_H

#include <media/stagefright/MediaSource.h>

#define MAX_FRAMES 5

namespace android {

class IMediaSourceFuzzImpl : public IMediaSource {
 public:
   IMediaSourceFuzzImpl(FuzzedDataProvider* _fdp, size_t _max_buffer_size)
       : frames_read(0), fdp(_fdp), min_buffer_size(32 * 32), max_buffer_size(_max_buffer_size) {}
   status_t start(MetaData*) override { return 0; }
   status_t stop() override { return 0; }
   sp<MetaData> getFormat() override { return nullptr; }
   status_t read(MediaBufferBase**, const MediaSource::ReadOptions*) override;
   status_t readMultiple(Vector<MediaBufferBase*>*, uint32_t,
                         const MediaSource::ReadOptions*) override;
   bool supportReadMultiple() override { return true; }
   bool supportNonblockingRead() override { return true; }
   status_t pause() override { return 0; }

 protected:
    IBinder* onAsBinder() { return nullptr; }

 private:
   uint8_t frames_read;
   FuzzedDataProvider* fdp;
   const size_t min_buffer_size;
   const size_t max_buffer_size;
   std::vector<uint8_t> buf;
};

// This class is simply to expose the destructor
class MediaBufferFuzzImpl : public MediaBuffer {
 public:
    MediaBufferFuzzImpl(void *data, size_t size) : MediaBuffer(data, size) {}
    ~MediaBufferFuzzImpl() {}
};

status_t IMediaSourceFuzzImpl::read(MediaBufferBase** buffer, const MediaSource::ReadOptions*) {
    Vector<MediaBufferBase*> buffers;
    status_t ret = readMultiple(&buffers, 1, nullptr);
    *buffer = buffers.empty() ? nullptr : buffers[0];

    return ret;
}

status_t IMediaSourceFuzzImpl::readMultiple(Vector<MediaBufferBase*>* buffers, uint32_t,
                                            const MediaSource::ReadOptions*) {
    if (++frames_read == MAX_FRAMES) {
        auto size = fdp->ConsumeIntegralInRange<size_t>(min_buffer_size, max_buffer_size);
        buf = fdp->ConsumeBytes<uint8_t>(size);
        if (buf.size() < size) {
            buf.resize(size, 0);
        }

        MediaBufferBase* mbb = new MediaBufferFuzzImpl(buf.data(), buf.size());
        mbb->meta_data().setInt64(kKeyTime, fdp->ConsumeIntegral<uint64_t>());
        buffers->push_back(mbb);

        return ERROR_END_OF_STREAM;
    }

    auto size = fdp->ConsumeIntegralInRange<size_t>(min_buffer_size, max_buffer_size);
    buf = fdp->ConsumeBytes<uint8_t>(size);
    if (buf.size() < size) {
        buf.resize(size, 0);
    }

    MediaBufferBase* mbb = new MediaBufferFuzzImpl(buf.data(), buf.size());
    mbb->meta_data().setInt64(kKeyTime, fdp->ConsumeIntegral<uint64_t>());
    buffers->push_back(mbb);

    return OK;
}

} // namespace android

#endif // IMEDIASOURCEFUZZIMPL_H

