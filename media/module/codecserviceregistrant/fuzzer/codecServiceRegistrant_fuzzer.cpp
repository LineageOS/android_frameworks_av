/*
 * Copyright (C) 2021 The Android Open Source Project
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
#include "../CodecServiceRegistrant.cpp"
#include "fuzzer/FuzzedDataProvider.h"
#include <C2Config.h>
#include <C2Param.h>
#include <android/api-level.h>

using namespace std;

constexpr char kServiceName[] = "software";

class CodecServiceRegistrantFuzzer {
public:
  void process(const uint8_t *data, size_t size);
  ~CodecServiceRegistrantFuzzer() {
    delete mH2C2;
    if (mInputSize) {
      delete mInputSize;
    }
    if (mSampleRateInfo) {
      delete mSampleRateInfo;
    }
    if (mChannelCountInfo) {
      delete mChannelCountInfo;
    }
  }

private:
  void initH2C2ComponentStore();
  void invokeH2C2ComponentStore();
  void invokeConfigSM();
  void invokeQuerySM();
  H2C2ComponentStore *mH2C2 = nullptr;
  C2StreamPictureSizeInfo::input *mInputSize = nullptr;
  C2StreamSampleRateInfo::output *mSampleRateInfo = nullptr;
  C2StreamChannelCountInfo::output *mChannelCountInfo = nullptr;
  C2Param::Index mIndex = C2StreamProfileLevelInfo::output::PARAM_TYPE;
  C2StreamFrameRateInfo::output mFrameRate;
  FuzzedDataProvider *mFDP = nullptr;
};

void CodecServiceRegistrantFuzzer::initH2C2ComponentStore() {
  using namespace ::android::hardware::media::c2;
  shared_ptr<C2ComponentStore> store =
      android::GetCodec2PlatformComponentStore();
  if (!store) {
    return;
  }

  int32_t platformVersion = android_get_device_api_level();
  if (platformVersion >= __ANDROID_API_S__) {
    android::sp<V1_2::IComponentStore> storeV1_2 =
      new V1_2::utils::ComponentStore(store);
    if (storeV1_2->registerAsService(string(kServiceName)) != android::OK) {
      return;
    }
  } else if (platformVersion == __ANDROID_API_R__) {
    android::sp<V1_1::IComponentStore> storeV1_1 =
      new V1_1::utils::ComponentStore(store);
    if (storeV1_1->registerAsService(string(kServiceName)) != android::OK) {
      return;
    }
  } else if (platformVersion == __ANDROID_API_Q__) {
    android::sp<V1_0::IComponentStore> storeV1_0 =
      new V1_0::utils::ComponentStore(store);
    if (storeV1_0->registerAsService(string(kServiceName)) != android::OK) {
      return;
    }
  }
  else {
    return;
  }

  string const preferredStoreName = string(kServiceName);
  sp<V1_0::IComponentStore> preferredStore =
      V1_0::IComponentStore::getService(preferredStoreName.c_str());
  mH2C2 = new H2C2ComponentStore(preferredStore);
}

void CodecServiceRegistrantFuzzer::invokeConfigSM() {
  vector<C2Param *> configParams;
  uint32_t width = mFDP->ConsumeIntegral<uint32_t>();
  uint32_t height = mFDP->ConsumeIntegral<uint32_t>();
  uint32_t samplingRate = mFDP->ConsumeIntegral<uint32_t>();
  uint32_t channels = mFDP->ConsumeIntegral<uint32_t>();
  if (mFDP->ConsumeBool()) {
    mInputSize = new C2StreamPictureSizeInfo::input(0u, width, height);
    configParams.push_back(mInputSize);
  } else {
    if (mFDP->ConsumeBool()) {
      mSampleRateInfo = new C2StreamSampleRateInfo::output(0u, samplingRate);
      configParams.push_back(mSampleRateInfo);
    }
    if (mFDP->ConsumeBool()) {
      mChannelCountInfo = new C2StreamChannelCountInfo::output(0u, channels);
      configParams.push_back(mChannelCountInfo);
    }
  }
  vector<unique_ptr<C2SettingResult>> failures;
  mH2C2->config_sm(configParams, &failures);
}

void CodecServiceRegistrantFuzzer::invokeQuerySM() {
  vector<C2Param *> stackParams;
  vector<C2Param::Index> heapParamIndices;
  if (mFDP->ConsumeBool()) {
    stackParams = {};
    heapParamIndices = {};
  } else {
    uint32_t stream = mFDP->ConsumeIntegral<uint32_t>();
    mFrameRate.setStream(stream);
    stackParams.push_back(&mFrameRate);
    heapParamIndices.push_back(mIndex);
  }
  vector<unique_ptr<C2Param>> heapParams;
  mH2C2->query_sm(stackParams, heapParamIndices, &heapParams);
}

void CodecServiceRegistrantFuzzer::invokeH2C2ComponentStore() {
  initH2C2ComponentStore();
  shared_ptr<C2Component> component;
  shared_ptr<C2ComponentInterface> interface;
  string c2String = mFDP->ConsumeRandomLengthString();
  mH2C2->createComponent(c2String, &component);
  mH2C2->createInterface(c2String, &interface);
  invokeConfigSM();
  invokeQuerySM();

  vector<shared_ptr<C2ParamDescriptor>> params;
  mH2C2->querySupportedParams_nb(&params);

  C2StoreIonUsageInfo usageInfo;
  std::vector<C2FieldSupportedValuesQuery> query = {
      C2FieldSupportedValuesQuery::Possible(
          C2ParamField::Make(usageInfo, usageInfo.usage)),
      C2FieldSupportedValuesQuery::Possible(
          C2ParamField::Make(usageInfo, usageInfo.capacity)),
  };
  mH2C2->querySupportedValues_sm(query);

  mH2C2->getName();
  shared_ptr<C2ParamReflector> paramReflector = mH2C2->getParamReflector();
  if (paramReflector) {
    paramReflector->describe(C2ComponentDomainSetting::CORE_INDEX);
  }
  mH2C2->listComponents();
  shared_ptr<C2GraphicBuffer> src;
  shared_ptr<C2GraphicBuffer> dst;
  mH2C2->copyBuffer(src, dst);
}

void CodecServiceRegistrantFuzzer::process(const uint8_t *data, size_t size) {
  mFDP = new FuzzedDataProvider(data, size);
  invokeH2C2ComponentStore();
  /** RegisterCodecServices is called here to improve code coverage */
  /** as currently it is not called by codecServiceRegistrant       */
  RegisterCodecServices();
  delete mFDP;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  CodecServiceRegistrantFuzzer codecServiceRegistrantFuzzer;
  codecServiceRegistrantFuzzer.process(data, size);
  return 0;
}
