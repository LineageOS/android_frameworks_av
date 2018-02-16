/*
 * Copyright 2017 The Android Open Source Project
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

#ifndef C2_SOFT_H264_DEC_H_

#define C2_SOFT_H264_DEC_H_

#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>

#include <util/C2ParamUtils.h>

#include <C2Component.h>
#include <C2Param.h>
#include <SimpleC2Component.h>

#include "C2AvcConfig.h"

#include <media/stagefright/foundation/ABase.h>
#include <media/stagefright/foundation/ColorUtils.h>

#include <sys/time.h>

namespace android {

struct iv_obj_t;
struct ivd_video_decode_ip_t;
struct ivd_video_decode_op_t;

/** Number of entries in the time-stamp array */
#define MAX_PENDING_WORKS 64

/** Maximum number of cores supported by the codec */
#define CODEC_MAX_NUM_CORES 4

#define CODEC_MAX_WIDTH     1920

#define CODEC_MAX_HEIGHT    1088

/** Input buffer size */
#define INPUT_BUF_SIZE (1024 * 1024)

#define MIN(a, b) ((a) < (b)) ? (a) : (b)

/** Get time */
#define GETTIME(a, b) gettimeofday(a, b);

/** Compute difference between start and end */
#define TIME_DIFF(start, end, diff) \
    diff = (((end).tv_sec - (start).tv_sec) * 1000000) + \
            ((end).tv_usec - (start).tv_usec);

#if 0
class C2SoftAvcDecIntf : public C2ComponentInterface {
public:
    struct SupportedValuesWithFields {
        C2FieldSupportedValues supported;
        std::set<C2ParamField> restrictingFields;

        SupportedValuesWithFields(const C2FieldSupportedValues &supported) : supported(supported) {}
    };

    C2SoftAvcDecIntf(const char *name, c2_node_id_t id);
    virtual ~C2SoftAvcDecIntf() override;

    // From C2ComponentInterface
    virtual C2String getName() const override;
    virtual c2_node_id_t getId() const override;
    virtual c2_status_t query_vb(
            const std::vector<C2Param*> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) const override;
    virtual c2_status_t config_vb(
            const std::vector<C2Param*> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) override;
    virtual c2_status_t createTunnel_sm(c2_node_id_t targetComponent) override;
    virtual c2_status_t releaseTunnel_sm(c2_node_id_t targetComponent) override;
    // TODO: move this into some common store class
    std::shared_ptr<C2ParamReflector> getParamReflector() const;
    virtual c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>> * const params) const override;
    virtual c2_status_t querySupportedValues_vb(
            std::vector<C2FieldSupportedValuesQuery> &fields, c2_blocking_t mayBlock) const override;

private:
    class ParamReflector;

    const C2String mName;
    const c2_node_id_t mId;

    C2ComponentDomainInfo mDomainInfo;
    // TODO: config desc
    std::unique_ptr<C2PortMimeConfig::input> mInputPortMime;
    C2PortStreamCountConfig::input mInputStreamCount;
    std::unique_ptr<C2PortMimeConfig::output> mOutputPortMime;
    C2PortStreamCountConfig::output mOutputStreamCount;
    // TODO: C2StreamMimeConfig mInputStreamMime;
    // TODO: C2StreamMimeConfig mOutputStreamMime;
    C2StreamFormatConfig::input mInputStreamFormat;
    std::unique_ptr<C2PortBlockPoolsTuning::output> mOutputBlockPools;
    C2StreamFormatConfig::output mOutputStreamFormat;
    C2VideoSizeStreamInfo::output mVideoSize;
    C2MaxVideoSizeHintPortSetting::input mMaxVideoSizeHint;
    C2AvcProfileInfo::input mProfile;
    C2AvcLevelInfo::input mLevel;
    C2BlockSizeInfo::output mBlockSize;
    C2AlignmentInfo::output mAlignment;
    C2FrameRateInfo::output mFrameRate;
    C2BlocksPerSecondInfo::output mBlocksPerSecond;

    std::shared_ptr<C2ParamReflector> mParamReflector;

    std::unordered_map<uint32_t, C2Param *> mParams;
    // C2ParamField is LessThanComparable
    std::map<C2ParamField, SupportedValuesWithFields> mSupportedValues;
    std::unordered_map<
            uint32_t, std::function<std::unique_ptr<C2SettingResult>(C2Param *)>> mFieldVerifiers;
    std::vector<std::shared_ptr<C2ParamDescriptor>> mParamDescs;

    void updateSupportedValues();
    friend class C2SoftAvcDec;
};
#endif

class C2SoftAvcDec : public SimpleC2Component {
public:
    C2SoftAvcDec(const char *name, c2_node_id_t id);
    virtual ~C2SoftAvcDec();

    // From SimpleC2Component
    c2_status_t onInit() override;
    c2_status_t onStop() override;
    void onReset() override;
    void onRelease() override;
    c2_status_t onFlush_sm() override;
    void process(
            const std::unique_ptr<C2Work> &work,
            const std::shared_ptr<C2BlockPool> &pool) override;
    c2_status_t drain(
            uint32_t drainMode,
            const std::shared_ptr<C2BlockPool> &pool) override;

private:
    Mutex mColorAspectsLock;
    // color aspects passed from the framework.
    ColorAspects mDefaultColorAspects;
    // color aspects parsed from the bitstream.
    ColorAspects mBitstreamColorAspects;
    // final color aspects after combining the above two aspects.
    ColorAspects mFinalColorAspects;
    bool mUpdateColorAspects;

    bool colorAspectsDiffer(const ColorAspects &a, const ColorAspects &b);

    // This functions takes two color aspects and updates the mFinalColorAspects
    // based on |preferredAspects|.
    void updateFinalColorAspects(
            const ColorAspects &otherAspects, const ColorAspects &preferredAspects);

    // This function will update the mFinalColorAspects based on codec preference.
    status_t handleColorAspectsChange();

    std::shared_ptr<C2GraphicBlock> mAllocatedBlock;

    iv_obj_t *mCodecCtx;         // Codec context

    size_t mNumCores;            // Number of cores to be uesd by the codec

    struct timeval mTimeStart;   // Time at the start of decode()
    struct timeval mTimeEnd;     // Time at the end of decode()

    // Internal buffer to be used to flush out the buffers from decoder
    uint8_t *mOutBuffer;

#ifdef FILE_DUMP_ENABLE
    char mInFile[200];
#endif /* FILE_DUMP_ENABLE */

    int mIvColorFormat;        // Ittiam Color format

    bool mIsInFlush;        // codec is flush mode
    bool mReceivedEOS;      // EOS is receieved on input port

    // The input stream has changed to a different resolution, which is still supported by the
    // codec. So the codec is switching to decode the new resolution.
    bool mChangingResolution;
    bool mFlushNeeded;
    bool mSignalledError;
    uint32_t mWidth;
    uint32_t mHeight;
    uint32_t mStride;
    size_t mInputOffset;

    status_t initDecoder();
    status_t deInitDecoder();
    status_t setFlushMode();
    status_t setParams(size_t stride);
    void logVersion();
    status_t setNumCores();
    status_t resetDecoder();
    status_t resetPlugin();

    c2_status_t ensureDecoderState(const std::shared_ptr<C2BlockPool> &pool);
    void finishWork(uint64_t index, const std::unique_ptr<C2Work> &work);
    c2_status_t drainInternal(
            uint32_t drainMode,
            const std::shared_ptr<C2BlockPool> &pool,
            const std::unique_ptr<C2Work> &work);

    bool setDecodeArgs(
            ivd_video_decode_ip_t *ps_dec_ip,
            ivd_video_decode_op_t *ps_dec_op,
            C2ReadView *inBuffer,
            C2GraphicView *outBuffer,
            uint32_t timeStampIx,
            size_t inOffset);

    bool getVUIParams();

    DISALLOW_EVIL_CONSTRUCTORS(C2SoftAvcDec);
};

#ifdef FILE_DUMP_ENABLE

#define INPUT_DUMP_PATH     "/sdcard/media/avcd_input"
#define INPUT_DUMP_EXT      "h264"

#define GENERATE_FILE_NAMES() {                         \
    GETTIME(&mTimeStart, NULL);                         \
    strcpy(mInFile, "");                                \
    sprintf(mInFile, "%s_%ld.%ld.%s", INPUT_DUMP_PATH,  \
            mTimeStart.tv_sec, mTimeStart.tv_usec,      \
            INPUT_DUMP_EXT);                            \
}

#define CREATE_DUMP_FILE(m_filename) {                  \
    FILE *fp = fopen(m_filename, "wb");                 \
    if (fp != NULL) {                                   \
        fclose(fp);                                     \
    } else {                                            \
        ALOGD("Could not open file %s", m_filename);    \
    }                                                   \
}
#define DUMP_TO_FILE(m_filename, m_buf, m_size, m_offset)\
{                                                       \
    FILE *fp = fopen(m_filename, "ab");                 \
    if (fp != NULL && m_buf != NULL && m_offset == 0) { \
        int i;                                          \
        i = fwrite(m_buf, 1, m_size, fp);               \
        ALOGD("fwrite ret %d to write %d", i, m_size);  \
        if (i != (int) m_size) {                        \
            ALOGD("Error in fwrite, returned %d", i);   \
            perror("Error in write to file");           \
        }                                               \
    } else if (fp == NULL) {                            \
        ALOGD("Could not write to file %s", m_filename);\
    }                                                   \
    if (fp) {                                           \
        fclose(fp);                                     \
    }                                                   \
}
#else /* FILE_DUMP_ENABLE */
#define INPUT_DUMP_PATH
#define INPUT_DUMP_EXT
#define OUTPUT_DUMP_PATH
#define OUTPUT_DUMP_EXT
#define GENERATE_FILE_NAMES()
#define CREATE_DUMP_FILE(m_filename)
#define DUMP_TO_FILE(m_filename, m_buf, m_size, m_offset)
#endif /* FILE_DUMP_ENABLE */

} // namespace android

#endif  // C2_SOFT_H264_DEC_H_
