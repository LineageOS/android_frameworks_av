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

#pragma once

#include <android-base/thread_annotations.h>
#include <media/MediaMetricsItem.h>
#include <mutex>

namespace android::mediametrics {

/**
 * AnalyticsActions consists of a map of pairs <trigger, action> which
 * are evaluated for a given incoming MediaMetrics item.
 *
 * A vector of Actions are returned from getActionsForItem() which
 * should be executed outside of any locks.
 *
 * Mediametrics assumes weak consistency, which is fine as the analytics database
 * is generally strictly increasing in size (until gc removes values that are
 * supposedly no longer needed).
 */

class AnalyticsActions {
public:

    using Elem = mediametrics::Item::Prop::Elem;
    /**
     * Trigger: a pair consisting of
     * std::string: A wildcard url specifying a property in the item,
     *              where '*' indicates 0 or more arbitrary characters
     *              for the item key match.
     * Elem: A value that needs to match exactly.
     *
     * Trigger is used in a map sort;  default less with std::string as primary key.
     * The wildcard accepts a string with '*' as being 0 or more arbitrary
     * characters for the item key match.  A wildcard is preferred over general
     * regexp for simple fast lookup.
     *
     * TODO: incorporate a regexp option.
     */
    using Trigger = std::pair<std::string, Elem>;

    /**
     * Function: The function to be executed.
     */
    using Function = std::function<
            void(const std::shared_ptr<const mediametrics::Item>& item)>;

    /**
     * Action:  An action to execute.  This is a shared pointer to Function.
     */
    using Action = std::shared_ptr<Function>;

    /**
     * Adds a new action.
     *
     * \param url references a property in the item with wildcards
     * \param value references a value (cast to Elem automatically)
     *              so be careful of the type.  It must be one of
     *              the types acceptable to Elem.
     * \param action is a function or lambda to execute if the url matches value
     *               in the item.
     */
    template <typename T, typename U, typename A>
    void addAction(T&& url, U&& value, A&& action) {
        std::lock_guard l(mLock);
        mFilters.emplace(Trigger{ std::forward<T>(url), std::forward<U>(value) },
                std::forward<A>(action));
    }

    // TODO: remove an action.

    /**
     * Get all the actions triggered for a particular item.
     *
     * \param item to be analyzed for actions.
     */
    std::vector<Action>
    getActionsForItem(const std::shared_ptr<const mediametrics::Item>& item) {
        std::vector<Action> actions;
        std::lock_guard l(mLock);

        for (const auto &[trigger, action] : mFilters) {
            if (isWildcardMatch(trigger, item) ==
                    mediametrics::Item::RECURSIVE_WILDCARD_CHECK_MATCH_FOUND) {
                actions.push_back(action);
            }
        }

        // TODO: Optimize for prefix search and wildcarding.

        return actions;
    }

private:

    static inline bool isMatch(const Trigger& trigger,
            const std::shared_ptr<const mediametrics::Item>& item) {
        const auto& [key, elem] = trigger;
        if (!startsWith(key, item->getKey())) return false;
        // The trigger key is in format (item key).propName, so + 1 skips '.' delimeter.
        const char *propName = key.c_str() + item->getKey().size() + 1;
        return item->hasPropElem(propName, elem);
    }

    static inline int isWildcardMatch(const Trigger& trigger,
            const std::shared_ptr<const mediametrics::Item>& item) {
        const auto& [key, elem] = trigger;
        return item->recursiveWildcardCheckElem(key.c_str(), elem);
    }

    mutable std::mutex mLock;

    using FilterType = std::multimap<Trigger, Action>;
    FilterType mFilters GUARDED_BY(mLock);
};

} // namespace android::mediametrics
