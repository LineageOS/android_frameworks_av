/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include "stop_token.h"

#include <thread>

namespace android::mediautils {

/**
 * Just a jthread, since std::jthread is still experimental in our toolchain.
 * Implements a subset of essential functionality (co-op cancellation and join on dtor).
 * If jthread gets picked up, usage can be cut over.
 */
class jthread {
  public:
    /**
     * Construct/launch and thread with a callable which consumes a stop_token.
     * The callable must be cooperatively cancellable via stop_token::stop_requested(), and will be
     * automatically stopped then joined on destruction.
     * Example:
     * jthread([](stop_token stok) {
     *     while(!stok.stop_requested) {
     *         // do work
     *     }
     * }
     */
    template <typename F>
    jthread(F&& f) : stop_source_{}, thread_{std::forward<F>(f), stop_source_.get_token()} {}

    ~jthread() {
        stop_source_.request_stop();
        thread_.join();
    }

    bool request_stop() { return stop_source_.request_stop(); }

    bool stop_requested() const { return stop_source_.stop_requested(); }

  private:
    // order matters
    stop_source stop_source_;
    std::thread thread_;
};
}  // namespace android::mediautils
