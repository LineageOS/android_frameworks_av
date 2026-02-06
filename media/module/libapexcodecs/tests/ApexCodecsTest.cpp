#include <C2.h>
#include <C2Component.h>

#include <android/hardware_buffer_aidl.h>
#include <apex/ApexCodecs.h>
#include <apex/ApexCodecsParam.h>
#include <gtest/gtest.h>

// static_asserts for enum values match
static_assert((uint32_t)APEXCODEC_STATUS_OK        == (uint32_t)C2_OK);
static_assert((uint32_t)APEXCODEC_STATUS_BAD_VALUE == (uint32_t)C2_BAD_VALUE);
static_assert((uint32_t)APEXCODEC_STATUS_BAD_INDEX == (uint32_t)C2_BAD_INDEX);
static_assert((uint32_t)APEXCODEC_STATUS_CANNOT_DO == (uint32_t)C2_CANNOT_DO);
static_assert((uint32_t)APEXCODEC_STATUS_DUPLICATE == (uint32_t)C2_DUPLICATE);
static_assert((uint32_t)APEXCODEC_STATUS_NOT_FOUND == (uint32_t)C2_NOT_FOUND);
static_assert((uint32_t)APEXCODEC_STATUS_BAD_STATE == (uint32_t)C2_BAD_STATE);
static_assert((uint32_t)APEXCODEC_STATUS_BLOCKING  == (uint32_t)C2_BLOCKING);
static_assert((uint32_t)APEXCODEC_STATUS_CANCELED  == (uint32_t)C2_CANCELED);
static_assert((uint32_t)APEXCODEC_STATUS_NO_MEMORY == (uint32_t)C2_NO_MEMORY);
static_assert((uint32_t)APEXCODEC_STATUS_REFUSED   == (uint32_t)C2_REFUSED);
static_assert((uint32_t)APEXCODEC_STATUS_TIMED_OUT == (uint32_t)C2_TIMED_OUT);
static_assert((uint32_t)APEXCODEC_STATUS_OMITTED   == (uint32_t)C2_OMITTED);
static_assert((uint32_t)APEXCODEC_STATUS_CORRUPTED == (uint32_t)C2_CORRUPTED);
static_assert((uint32_t)APEXCODEC_STATUS_NO_INIT   == (uint32_t)C2_NO_INIT);

static_assert((uint32_t)APEXCODEC_KIND_OTHER   == (uint32_t)C2Component::KIND_OTHER);
static_assert((uint32_t)APEXCODEC_KIND_DECODER == (uint32_t)C2Component::KIND_DECODER);
static_assert((uint32_t)APEXCODEC_KIND_ENCODER == (uint32_t)C2Component::KIND_ENCODER);

static_assert((uint32_t)APEXCODEC_DOMAIN_OTHER == (uint32_t)C2Component::DOMAIN_OTHER);
static_assert((uint32_t)APEXCODEC_DOMAIN_VIDEO == (uint32_t)C2Component::DOMAIN_VIDEO);
static_assert((uint32_t)APEXCODEC_DOMAIN_AUDIO == (uint32_t)C2Component::DOMAIN_AUDIO);
static_assert((uint32_t)APEXCODEC_DOMAIN_IMAGE == (uint32_t)C2Component::DOMAIN_IMAGE);

static_assert((uint32_t)APEXCODEC_FLAG_DROP_FRAME    == (uint32_t)C2FrameData::FLAG_DROP_FRAME);
static_assert((uint32_t)APEXCODEC_FLAG_END_OF_STREAM == (uint32_t)C2FrameData::FLAG_END_OF_STREAM);
static_assert((uint32_t)APEXCODEC_FLAG_DISCARD_FRAME == (uint32_t)C2FrameData::FLAG_DISCARD_FRAME);
static_assert((uint32_t)APEXCODEC_FLAG_INCOMPLETE    == (uint32_t)C2FrameData::FLAG_INCOMPLETE);
static_assert((uint32_t)APEXCODEC_FLAG_CORRECTED     == (uint32_t)C2FrameData::FLAG_CORRECTED);
static_assert((uint32_t)APEXCODEC_FLAG_CORRUPT       == (uint32_t)C2FrameData::FLAG_CORRUPT);
static_assert((uint32_t)APEXCODEC_FLAG_CODEC_CONFIG  == (uint32_t)C2FrameData::FLAG_CODEC_CONFIG);

static_assert((uint32_t)APEXCODEC_BUFFER_TYPE_EMPTY          ==
              (uint32_t)C2BufferData::INVALID);
static_assert((uint32_t)APEXCODEC_BUFFER_TYPE_LINEAR         ==
              (uint32_t)C2BufferData::LINEAR);
static_assert((uint32_t)APEXCODEC_BUFFER_TYPE_LINEAR_CHUNKS  ==
              (uint32_t)C2BufferData::LINEAR_CHUNKS);
static_assert((uint32_t)APEXCODEC_BUFFER_TYPE_GRAPHIC        ==
              (uint32_t)C2BufferData::GRAPHIC);
static_assert((uint32_t)APEXCODEC_BUFFER_TYPE_GRAPHIC_CHUNKS ==
              (uint32_t)C2BufferData::GRAPHIC_CHUNKS);

static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_QUERY_CURRENT  ==
              (uint32_t)C2FieldSupportedValuesQuery::CURRENT);
static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_QUERY_POSSIBLE ==
              (uint32_t)C2FieldSupportedValuesQuery::POSSIBLE);

static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_EMPTY  ==
              (uint32_t)C2FieldSupportedValues::EMPTY);
static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_RANGE  ==
              (uint32_t)C2FieldSupportedValues::RANGE);
static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_VALUES ==
              (uint32_t)C2FieldSupportedValues::VALUES);
static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_FLAGS  ==
              (uint32_t)C2FieldSupportedValues::FLAGS);

static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_TYPE_NONE   == (uint32_t)C2Value::NO_INIT);
static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_TYPE_INT32  == (uint32_t)C2Value::INT32);
static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_TYPE_UINT32 == (uint32_t)C2Value::UINT32);
static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_TYPE_INT64  == (uint32_t)C2Value::INT64);
static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_TYPE_UINT64 == (uint32_t)C2Value::UINT64);
static_assert((uint32_t)APEXCODEC_SUPPORTED_VALUES_TYPE_FLOAT  == (uint32_t)C2Value::FLOAT);

static_assert((uint32_t)APEXCODEC_SETTING_RESULT_BAD_TYPE       ==
              (uint32_t)C2SettingResult::BAD_TYPE);
static_assert((uint32_t)APEXCODEC_SETTING_RESULT_BAD_PORT       ==
              (uint32_t)C2SettingResult::BAD_PORT);
static_assert((uint32_t)APEXCODEC_SETTING_RESULT_BAD_INDEX      ==
              (uint32_t)C2SettingResult::BAD_INDEX);
static_assert((uint32_t)APEXCODEC_SETTING_RESULT_READ_ONLY      ==
              (uint32_t)C2SettingResult::READ_ONLY);
static_assert((uint32_t)APEXCODEC_SETTING_RESULT_MISMATCH       ==
              (uint32_t)C2SettingResult::MISMATCH);
static_assert((uint32_t)APEXCODEC_SETTING_RESULT_BAD_VALUE      ==
              (uint32_t)C2SettingResult::BAD_VALUE);
static_assert((uint32_t)APEXCODEC_SETTING_RESULT_CONFLICT       ==
              (uint32_t)C2SettingResult::CONFLICT);
static_assert((uint32_t)APEXCODEC_SETTING_RESULT_UNSUPPORTED    ==
              (uint32_t)C2SettingResult::UNSUPPORTED);
static_assert((uint32_t)APEXCODEC_SETTING_RESULT_INFO_BAD_VALUE ==
              (uint32_t)C2SettingResult::INFO_BAD_VALUE);
static_assert((uint32_t)APEXCODEC_SETTING_RESULT_INFO_CONFLICT  ==
              (uint32_t)C2SettingResult::INFO_CONFLICT);

static_assert((uint32_t)APEXCODEC_PARAM_IS_REQUIRED   == (uint32_t)C2ParamDescriptor::IS_REQUIRED);
static_assert((uint32_t)APEXCODEC_PARAM_IS_PERSISTENT ==
              (uint32_t)C2ParamDescriptor::IS_PERSISTENT);
static_assert((uint32_t)APEXCODEC_PARAM_IS_STRICT     == (uint32_t)C2ParamDescriptor::IS_STRICT);
static_assert((uint32_t)APEXCODEC_PARAM_IS_READ_ONLY  == (uint32_t)C2ParamDescriptor::IS_READ_ONLY);
static_assert((uint32_t)APEXCODEC_PARAM_IS_HIDDEN     == (uint32_t)C2ParamDescriptor::IS_HIDDEN);
static_assert((uint32_t)APEXCODEC_PARAM_IS_INTERNAL   == (uint32_t)C2ParamDescriptor::IS_INTERNAL);
static_assert((uint32_t)APEXCODEC_PARAM_IS_CONSTANT   == (uint32_t)C2ParamDescriptor::IS_CONST);

using ::aidl::android::hardware::HardwareBuffer;

class SpApexCodecBuffer {
public:
    SpApexCodecBuffer() {
        mBuffer = ApexCodec_Buffer_create();
    }

    ~SpApexCodecBuffer() {
        ApexCodec_Buffer_destroy(mBuffer);
    }

    ApexCodec_Buffer* get() const {
        return mBuffer;
    }

private:
    ApexCodec_Buffer* mBuffer;
};

TEST(ApexCodecsTest, BufferCreateDestroyTest) {
    SpApexCodecBuffer buffer;
    ASSERT_NE(buffer.get(), nullptr);
}

TEST(ApexCodecsTest, BufferInitialStateTest) {
    SpApexCodecBuffer buffer;
    ASSERT_NE(buffer.get(), nullptr);
    ASSERT_EQ(ApexCodec_Buffer_getType(buffer.get()), APEXCODEC_BUFFER_TYPE_EMPTY);

    ApexCodec_BufferFlags flags;
    uint64_t frameIndex;
    uint64_t timestampUs;
    ASSERT_EQ(ApexCodec_Buffer_getBufferInfo(buffer.get(), &flags, &frameIndex, &timestampUs),
              APEXCODEC_STATUS_BAD_STATE);

    ApexCodec_LinearBuffer linearBuffer;
    ASSERT_EQ(ApexCodec_Buffer_getLinearBuffer(buffer.get(), &linearBuffer),
              APEXCODEC_STATUS_BAD_STATE);

    AHardwareBuffer* graphicBuffer;
    ASSERT_EQ(ApexCodec_Buffer_getGraphicBuffer(buffer.get(), &graphicBuffer),
              APEXCODEC_STATUS_BAD_STATE);

    ApexCodec_LinearBuffer configUpdates;
    bool ownedByClient;
    ASSERT_EQ(ApexCodec_Buffer_getConfigUpdates(buffer.get(), &configUpdates, &ownedByClient),
              APEXCODEC_STATUS_NOT_FOUND);
}

TEST(ApexCodecsTest, BufferSetGetInfoTest) {
    SpApexCodecBuffer buffer;
    ASSERT_NE(buffer.get(), nullptr);

    ApexCodec_Buffer_setBufferInfo(buffer.get(), APEXCODEC_FLAG_END_OF_STREAM, 123, 456);

    ApexCodec_BufferFlags flags;
    uint64_t frameIndex;
    uint64_t timestampUs;
    ASSERT_EQ(ApexCodec_Buffer_getBufferInfo(buffer.get(), &flags, &frameIndex, &timestampUs),
              APEXCODEC_STATUS_OK);
    ASSERT_EQ(flags, APEXCODEC_FLAG_END_OF_STREAM);
    ASSERT_EQ(frameIndex, 123);
    ASSERT_EQ(timestampUs, 456);
}

TEST(ApexCodecsTest, BufferSetGetLinearBufferTest) {
    SpApexCodecBuffer buffer;
    ASSERT_NE(buffer.get(), nullptr);

    uint8_t data[10];
    ApexCodec_LinearBuffer linearBuffer;
    linearBuffer.data = data;
    linearBuffer.size = 10;
    ASSERT_EQ(ApexCodec_Buffer_setLinearBuffer(buffer.get(), &linearBuffer), APEXCODEC_STATUS_OK);
    ASSERT_EQ(ApexCodec_Buffer_getType(buffer.get()), APEXCODEC_BUFFER_TYPE_LINEAR);
    // Clear the data to ensure that the buffer owns the data.
    linearBuffer.data = nullptr;
    linearBuffer.size = 0;
    ASSERT_EQ(ApexCodec_Buffer_getLinearBuffer(buffer.get(), &linearBuffer), APEXCODEC_STATUS_OK);
    ASSERT_EQ(linearBuffer.data, data);
    ASSERT_EQ(linearBuffer.size, 10);

    ASSERT_EQ(ApexCodec_Buffer_setLinearBuffer(buffer.get(), &linearBuffer),
              APEXCODEC_STATUS_BAD_STATE);
}

TEST(ApexCodecsTest, BufferSetGetGraphicBufferTest) {
    SpApexCodecBuffer buffer;
    ASSERT_NE(buffer.get(), nullptr);

    HardwareBuffer hardwareBuffer;
    AHardwareBuffer_Desc desc;
    desc.width = 100;
    desc.height = 100;
    desc.layers = 1;
    desc.format = AHARDWAREBUFFER_FORMAT_Y8Cb8Cr8_420;
    desc.usage = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN;
    AHardwareBuffer* graphicBuffer = nullptr;
    AHardwareBuffer_allocate(&desc, &graphicBuffer);
    hardwareBuffer.reset(graphicBuffer);
    ASSERT_NE(graphicBuffer, nullptr);
    ASSERT_EQ(ApexCodec_Buffer_setGraphicBuffer(buffer.get(), graphicBuffer), APEXCODEC_STATUS_OK);
    ASSERT_EQ(ApexCodec_Buffer_getType(buffer.get()), APEXCODEC_BUFFER_TYPE_GRAPHIC);
    graphicBuffer = nullptr;
    ASSERT_EQ(ApexCodec_Buffer_getGraphicBuffer(buffer.get(), &graphicBuffer), APEXCODEC_STATUS_OK);
    ASSERT_NE(graphicBuffer, nullptr);

    ASSERT_EQ(ApexCodec_Buffer_setGraphicBuffer(buffer.get(), graphicBuffer),
              APEXCODEC_STATUS_BAD_STATE);
}

TEST(ApexCodecsTest, BufferSetGetConfigUpdatesTest) {
    SpApexCodecBuffer buffer;
    ASSERT_NE(buffer.get(), nullptr);

    uint8_t configData[20];
    ApexCodec_LinearBuffer configUpdates;
    configUpdates.data = configData;
    configUpdates.size = 20;
    ASSERT_EQ(ApexCodec_Buffer_setConfigUpdates(buffer.get(), &configUpdates), APEXCODEC_STATUS_OK);

    bool ownedByClient;
    ASSERT_EQ(ApexCodec_Buffer_getConfigUpdates(buffer.get(), &configUpdates, &ownedByClient),
              APEXCODEC_STATUS_OK);
    ASSERT_EQ(configUpdates.data, configData);
    ASSERT_EQ(configUpdates.size, 20);
    ASSERT_EQ(ownedByClient, true);

    ASSERT_EQ(ApexCodec_Buffer_setConfigUpdates(buffer.get(), &configUpdates),
              APEXCODEC_STATUS_BAD_STATE);
}

TEST(ApexCodecsTest, BufferClearTest) {
    SpApexCodecBuffer buffer;
    ASSERT_NE(buffer.get(), nullptr);

    uint8_t data[10];
    ApexCodec_LinearBuffer linearBuffer;
    linearBuffer.data = data;
    linearBuffer.size = 10;
    ASSERT_EQ(ApexCodec_Buffer_setLinearBuffer(buffer.get(), &linearBuffer), APEXCODEC_STATUS_OK);

    uint8_t configData[20];
    ApexCodec_LinearBuffer configUpdates;
    configUpdates.data = configData;
    configUpdates.size = 20;
    ASSERT_EQ(ApexCodec_Buffer_setConfigUpdates(buffer.get(), &configUpdates), APEXCODEC_STATUS_OK);

    ApexCodec_Buffer_clear(buffer.get());
    ASSERT_EQ(ApexCodec_Buffer_getType(buffer.get()), APEXCODEC_BUFFER_TYPE_EMPTY);

    ApexCodec_BufferFlags flags;
    uint64_t frameIndex;
    uint64_t timestampUs;
    ASSERT_EQ(ApexCodec_Buffer_getBufferInfo(buffer.get(), &flags, &frameIndex, &timestampUs),
              APEXCODEC_STATUS_BAD_STATE);
    ASSERT_EQ(ApexCodec_Buffer_getLinearBuffer(buffer.get(), &linearBuffer),
              APEXCODEC_STATUS_BAD_STATE);
    bool ownedByClient;

    ASSERT_EQ(ApexCodec_Buffer_getConfigUpdates(buffer.get(), &configUpdates, &ownedByClient),
              APEXCODEC_STATUS_NOT_FOUND);
}
