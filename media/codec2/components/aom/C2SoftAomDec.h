/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef ANDROID_C2_SOFT_AV1_DEC_H_
#define ANDROID_C2_SOFT_AV1_DEC_H_

#include <inttypes.h>

#include <SimpleC2Component.h>
#include "aom/aom_decoder.h"
#include "aom/aomdx.h"

namespace android {

struct C2SoftAomDec : public SimpleC2Component {
    class IntfImpl;

    C2SoftAomDec(const char* name, c2_node_id_t id,
                 const std::shared_ptr<IntfImpl>& intfImpl);
    virtual ~C2SoftAomDec();

    // From SimpleC2Component
    c2_status_t onInit() override;
    c2_status_t onStop() override;
    void onReset() override;
    void onRelease() override;
    c2_status_t onFlush_sm() override;
    void process(const std::unique_ptr<C2Work>& work,
                 const std::shared_ptr<C2BlockPool>& pool) override;
    c2_status_t drain(uint32_t drainMode,
                      const std::shared_ptr<C2BlockPool>& pool) override;

   private:
    std::shared_ptr<IntfImpl> mIntf;
    aom_codec_ctx_t* mCodecCtx;

    uint32_t mWidth;
    uint32_t mHeight;
    bool mSignalledOutputEos;
    bool mSignalledError;

    #ifdef FILE_DUMP_ENABLE
    char mInFile[200];
    char mOutFile[200];
    #endif /* FILE_DUMP_ENABLE */

    nsecs_t mTimeStart = 0;   // Time at the start of decode()
    nsecs_t mTimeEnd = 0;     // Time at the end of decode()

    status_t initDecoder();
    status_t destroyDecoder();
    void finishWork(uint64_t index, const std::unique_ptr<C2Work>& work,
                    const std::shared_ptr<C2GraphicBlock>& block);
    bool outputBuffer(const std::shared_ptr<C2BlockPool>& pool,
                      const std::unique_ptr<C2Work>& work);

    c2_status_t drainInternal(uint32_t drainMode,
                              const std::shared_ptr<C2BlockPool>& pool,
                              const std::unique_ptr<C2Work>& work);

    C2_DO_NOT_COPY(C2SoftAomDec);
};

#ifdef FILE_DUMP_ENABLE

#define INPUT_DUMP_PATH "/data/local/tmp/temp/av1"
#define INPUT_DUMP_EXT "webm"
#define OUTPUT_DUMP_PATH "/data/local/tmp/temp/av1"
#define OUTPUT_DUMP_EXT "av1"
#define GENERATE_FILE_NAMES()                                                 \
    {                                                                         \
        nsecs_t now = systemTime();                                           \
        ALOGD("GENERATE_FILE_NAMES");                                         \
        sprintf(mInFile, "%s_%" PRId64 ".%s", INPUT_DUMP_PATH,                \
                now, INPUT_DUMP_EXT);                                         \
        strcpy(mOutFile, "");                                                 \
        sprintf(mOutFile, "%s_%" PRId64 ".%s", OUTPUT_DUMP_PATH,              \
                now, OUTPUT_DUMP_EXT);                                        \
    }

#define CREATE_DUMP_FILE(m_filename)                     \
    {                                                    \
        FILE* fp = fopen(m_filename, "wb");              \
        if (fp != NULL) {                                \
            ALOGD("Opened file %s", m_filename);         \
            fclose(fp);                                  \
        } else {                                         \
            ALOGD("Could not open file %s", m_filename); \
        }                                                \
    }
#define DUMP_TO_FILE(m_filename, m_buf, m_size)              \
    {                                                        \
        FILE* fp = fopen(m_filename, "ab");                  \
        if (fp != NULL && m_buf != NULL) {                   \
            int i;                                           \
            ALOGD("Dump to file!");                          \
            i = fwrite(m_buf, 1, m_size, fp);                \
            if (i != (int)m_size) {                          \
                ALOGD("Error in fwrite, returned %d", i);    \
                perror("Error in write to file");            \
            }                                                \
            fclose(fp);                                      \
        } else {                                             \
            ALOGD("Could not write to file %s", m_filename); \
            if (fp != NULL) fclose(fp);                      \
        }                                                    \
    }
#else /* FILE_DUMP_ENABLE */
#define INPUT_DUMP_PATH
#define INPUT_DUMP_EXT
#define OUTPUT_DUMP_PATH
#define OUTPUT_DUMP_EXT
#define GENERATE_FILE_NAMES()
#define CREATE_DUMP_FILE(m_filename)
#define DUMP_TO_FILE(m_filename, m_buf, m_size)
#endif /* FILE_DUMP_ENABLE */

}  // namespace android

#endif  // ANDROID_C2_SOFT_AV1_DEC_H_
