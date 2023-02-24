/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <algorithm>
#include <memory>
#include <unordered_map>

#include <android-base/logging.h>
#include <android-base/thread_annotations.h>

#include "PreProcessingContext.h"
#include "PreProcessingTypes.h"

namespace aidl::android::hardware::audio::effect {

/**
 * @brief Maintain all effect pre-processing sessions.
 *
 * Sessions are identified with the session ID, maximum of MAX_BUNDLE_SESSIONS is supported by the
 * pre-processing implementation.
 */
class PreProcessingSession {
  public:
    static PreProcessingSession& getPreProcessingSession() {
        static PreProcessingSession instance;
        return instance;
    }

    static bool findPreProcessingTypeInList(
            std::vector<std::shared_ptr<PreProcessingContext>>& list,
            const PreProcessingEffectType& type, bool remove = false) {
        auto itor = std::find_if(list.begin(), list.end(),
                                 [type](const std::shared_ptr<PreProcessingContext>& bundle) {
                                     return bundle->getPreProcessingType() == type;
                                 });
        if (itor == list.end()) {
            return false;
        }
        if (remove) {
            (*itor)->deInit();
            list.erase(itor);
        }
        return true;
    }

    /**
     * Create a certain type of PreProcessingContext in shared_ptr container, each session must not
     * have more than one session for each type.
     */
    std::shared_ptr<PreProcessingContext> createSession(const PreProcessingEffectType& type,
                                                        int statusDepth,
                                                        const Parameter::Common& common) {
        int sessionId = common.session;
        LOG(DEBUG) << __func__ << type << " with sessionId " << sessionId;
        std::lock_guard lg(mMutex);
        if (mSessionMap.count(sessionId) == 0 && mSessionMap.size() >= MAX_PRE_PROC_SESSIONS) {
            LOG(ERROR) << __func__ << " exceed max bundle session";
            return nullptr;
        }

        if (mSessionMap.count(sessionId)) {
            if (findPreProcessingTypeInList(mSessionMap[sessionId], type)) {
                LOG(ERROR) << __func__ << type << " already exist in session " << sessionId;
                return nullptr;
            }
        }

        auto& list = mSessionMap[sessionId];
        auto context = std::make_shared<PreProcessingContext>(statusDepth, common, type);
        RETURN_VALUE_IF(!context, nullptr, "failedToCreateContext");

        RetCode ret = context->init(common);
        if (RetCode::SUCCESS != ret) {
            LOG(ERROR) << __func__ << " context init ret " << ret;
            return nullptr;
        }
        list.push_back(context);
        return context;
    }

    void releaseSession(const PreProcessingEffectType& type, int sessionId) {
        LOG(DEBUG) << __func__ << type << " sessionId " << sessionId;
        std::lock_guard lg(mMutex);
        if (mSessionMap.count(sessionId)) {
            auto& list = mSessionMap[sessionId];
            if (!findPreProcessingTypeInList(list, type, true /* remove */)) {
                LOG(ERROR) << __func__ << " can't find " << type << "in session " << sessionId;
                return;
            }
            if (list.empty()) {
                mSessionMap.erase(sessionId);
            }
        }
    }

  private:
    // Lock for mSessionMap access.
    std::mutex mMutex;
    // Max session number supported.
    static constexpr int MAX_PRE_PROC_SESSIONS = 8;
    std::unordered_map<int /* session ID */, std::vector<std::shared_ptr<PreProcessingContext>>>
            mSessionMap GUARDED_BY(mMutex);
};
}  // namespace aidl::android::hardware::audio::effect
