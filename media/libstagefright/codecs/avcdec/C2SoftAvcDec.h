/*
 * Copyright 2016 The Android Open Source Project
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

/** Used to remove warnings about unused parameters */
#define UNUSED(x) ((void)(x))

/** Get time */
#define GETTIME(a, b) gettimeofday(a, b);

/** Compute difference between start and end */
#define TIME_DIFF(start, end, diff) \
    diff = (((end).tv_sec - (start).tv_sec) * 1000000) + \
            ((end).tv_usec - (start).tv_usec);


class C2SoftAvcDecIntf : public C2ComponentInterface {
public:
    struct SupportedValuesWithFields {
        C2FieldSupportedValues supported;
        std::set<C2ParamField> restrictingFields;

        SupportedValuesWithFields(const C2FieldSupportedValues &supported) : supported(supported) {}
    };

    C2SoftAvcDecIntf(const char *name, node_id id);
    virtual ~C2SoftAvcDecIntf() = default;

    // From C2ComponentInterface
    virtual C2String getName() const override;
    virtual node_id getId() const override;
    virtual status_t query_nb(
            const std::vector<C2Param* const> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) const override;
    virtual status_t config_nb(
            const std::vector<C2Param* const> &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) override;
    virtual status_t commit_sm(
            const std::vector<C2Param* const> &params,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) override;
    virtual status_t createTunnel_sm(node_id targetComponent) override;
    virtual status_t releaseTunnel_sm(node_id targetComponent) override;
    virtual std::shared_ptr<C2ParamReflector> getParamReflector() const override;
    virtual status_t getSupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>> * const params) const override;
    virtual status_t getSupportedValues(
            const std::vector<const C2ParamField> &fields,
            std::vector<C2FieldSupportedValues>* const values) const override;

private:
    class ParamReflector;

    const C2String mName;
    const node_id mId;

    C2ComponentDomainInfo mDomainInfo;
    // TODO: config desc
    std::unique_ptr<C2PortMimeConfig::input> mInputPortMime;
    C2PortStreamCountConfig::input mInputStreamCount;
    std::unique_ptr<C2PortMimeConfig::output> mOutputPortMime;
    C2PortStreamCountConfig::output mOutputStreamCount;
    // TODO: C2StreamMimeConfig mInputStreamMime;
    // TODO: C2StreamMimeConfig mOutputStreamMime;
    C2StreamFormatConfig::input mInputStreamFormat;
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
};

class C2SoftAvcDec
    : public C2Component,
      public std::enable_shared_from_this<C2SoftAvcDec> {
public:
    C2SoftAvcDec(
            const char *name, node_id id, const std::shared_ptr<C2ComponentListener> &listener);
    virtual ~C2SoftAvcDec();

    // From C2Component
    virtual status_t queue_nb(std::list<std::unique_ptr<C2Work>>* const items) override;
    virtual status_t announce_nb(const std::vector<C2WorkOutline> &items) override;
    virtual status_t flush_sm(
            bool flushThrough, std::list<std::unique_ptr<C2Work>>* const flushedWork) override;
    virtual status_t drain_nb(bool drainThrough) override;
    virtual status_t start() override;
    virtual status_t stop() override;
    virtual void reset() override;
    virtual void release() override;
    virtual std::shared_ptr<C2ComponentInterface> intf() override;

private:
    class QueueProcessThread;

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

    // Number of input and output buffers
    enum {
        kNumBuffers = 8
    };

    using IndexType = decltype(C2WorkOrdinalStruct().frame_index);

    const std::shared_ptr<C2SoftAvcDecIntf> mIntf;
    const std::shared_ptr<C2ComponentListener> mListener;

    std::mutex mQueueLock;
    std::condition_variable mQueueCond;
    std::list<std::unique_ptr<C2Work>> mQueue;

    std::mutex mPendingLock;
    std::unordered_map<IndexType, std::unique_ptr<C2Work>> mPendingWork;

    std::unique_ptr<QueueProcessThread> mThread;

    std::shared_ptr<C2GraphicBlock> mAllocatedBlock;

    iv_obj_t *mCodecCtx;         // Codec context

    size_t mNumCores;            // Number of cores to be uesd by the codec

    struct timeval mTimeStart;   // Time at the start of decode()
    struct timeval mTimeEnd;     // Time at the end of decode()

    // Internal buffer to be used to flush out the buffers from decoder
    uint8_t *mFlushOutBuffer;

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
    int32_t mWidth;
    int32_t mHeight;
    int32_t mStride;
    size_t mInputOffset;

    void processQueue();
    void process(std::unique_ptr<C2Work> &work);

    status_t initDecoder();
    status_t deInitDecoder();
    status_t setFlushMode();
    status_t setParams(size_t stride);
    void logVersion();
    status_t setNumCores();
    status_t resetDecoder();
    status_t resetPlugin();

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
