/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <log/log_main.h>

#include <atomic>
#include <concepts>
#include <memory>
#include <utility>

#pragma push_macro("LOG_TAG")
#undef LOG_TAG
#define LOG_TAG "mediautils::stop_token"

namespace android::mediautils {
/**
 * The stop token functionality is currently experimental in clang due to performance issues (due to
 * a particular complex interface).
 * The implementation below fulfills a principled subset of the specification (omitting edge cases
 * and additional features) for simplicity.
 * See the following std proposals:
 * p2300: in_place_stop_source
 * p3409: single_inplace_stop_source
 *
 * In particular, instead of heap allocating the state object, the stop_source *MUST* outlive any
 * stop_tokens/stop_callbacks (models in_place_stop_source), and only a single stop callback can be
 * registered. In addition, we omit the notion of "empty" stop states/tokens (needed for default
 * constructibility).
 *
 * Note, we retain heap allocation of the single callback object. This allows for join-free
 * destruction of the cb object.
 *
 * Upon moving standardization of the above proposals and/or moving stop_token out of experimental,
 * cutting over from this implementation is possible, since this implements a subset of the
 * standardized concepts.
 */

class stop_source;
class stop_callback;

/**
 * Const view on stop source, which the running thread uses and an interface
 * for cancellation.
 */
class stop_token {
  public:
    stop_token(const stop_source& source) : stop_source_(source) {}
    bool stop_requested() const;

    friend stop_callback;
  private:
    const stop_source& stop_source_;
};

/* State owner and writable end, representing a task which can be cancelled, where the context
 * running the task reads the cancel request via stop token.
 *
 * This object MUST outlive any associated stop_tokens or stop_callbacks.
 */
class stop_source {
  private:
    enum class State : int32_t {
        EMPTY,
        FILLING,
        FILLED,
        FIRING,
        FIRED
    };
    class Cb {
      public:
        virtual void invoke() = 0;
        virtual ~Cb() = default;
    };
    using enum State;
    friend stop_callback;

  public:
    stop_token get_token() const { return stop_token{*this}; }
    bool stop_requested() const {
        const auto state = state_.load(std::memory_order_acquire);
        return is_stopped(state);
    }

    bool request_stop() {
        State old = state_.load(std::memory_order_acquire);
        while (!is_stopped(old) && !state_.compare_exchange_weak(old, FIRING,
                    std::memory_order_acquire))
            ;

        switch (old) {
            case FIRING:
            case FIRED:
                return false;
            case FILLED: {
                const auto cb = cb_.lock();
                cb->invoke();
                [[fallthrough]];
             }
            case FILLING:
            case EMPTY:
                state_.store(FIRED, std::memory_order_release);
                return true;
        }
    }

  private:

    void register_cb(std::shared_ptr<Cb> cb) const {
        if (!cb) return;
        State old = state_.load(std::memory_order_acquire);
        while (old == EMPTY &&
               !state_.compare_exchange_weak(old, FILLING, std::memory_order_acquire));
        switch (old) {
            case FILLING:
            case FILLED: {
                LOG_ALWAYS_FATAL("Violated stop_callback preconditions");
                return;
            }
            case FIRING:
            case FIRED: {
                cb->invoke();
                [[fallthrough]];
            }
            case EMPTY:
                cb_ = cb;
        }
        old = FILLING;
        // a stop request has come in and pre-empted us (STATE is now FIRING/FIRED),
        // but that thread doesn't see our cb (we haven't moved to FILLED), so it is as-if we were
        // already FIRED, and we are responsible for invoking the cb
        if (!state_.compare_exchange_strong(old, FILLED, std::memory_order_release,
                                            std::memory_order_relaxed)) {
            cb->invoke();
        }
    }

    // Note: intentionally param-less, since the pre-condition is exactly a single register_cb is
    // fully sequenced before this method is called (and this method should not be called).
    void unregister_cb() const {
        State old = state_.load(std::memory_order_relaxed);
        while (old == FILLED &&
               !state_.compare_exchange_weak(old, EMPTY, std::memory_order_relaxed));
        switch (old) {
            case EMPTY:
            case FILLING:
                LOG_ALWAYS_FATAL("Violated stop_callback preconditions");
                break;
            case FILLED:
            case FIRING:
            case FIRED:
                // Intentionally not clearing the weak_ptr object. This simplifies the state
                // machine/thread-safety at the cost of holding the memory of the control block
                // slightly longer.
                break;
        }
    }


    bool is_stopped(State state) const {
        return state == FIRING || state == FIRED;
    }

    // Pre-condition: state == FIRING => cb_ is not accessible to writer
    void fire() {
    }

    mutable std::weak_ptr<Cb> cb_;
    mutable std::atomic<State> state_;
};

/**
 * An RAII holder of a notification callback on a particular stop token. The actual callable object
 * is heap stored (i.e. behind a 0-1 shared ptr) for thread safe garbage collection, allowing for
 * the stop_state to hold a weak_ptr.
 * The callback is either called (exactly once) by the thread which successfully moves the
 * stop_source to the stopped state, or in place, as part of construction of this object. Thus, the
 * functional must be re-entrant (i.e. it should not take a lock which the constructing thread
 * already holds) to avoid deadlocks.
 * Each stop_source (through the corresponding stop_token) MUST
 * only have a single stop_callback registered at any given time. Note, this requirement implicitly
 * constrains threading behavior: the lifetimes of any stop_callbacks on the same token/state must
 * not be interleaved: the dtor of one stop_callback must happen_before any subsequent construction
 * another stop_callback on the same state. E.g. while (!stok.stop_requested) {
 *     ...
 *     stop_callback {stok, [&]() {cv.notify_all();} }
 *     cv.wait(...);
 * }
 * Additionally, due to this gc behavior, the functional can be called after (although only just)
 * the dtor of the stop_callback object -- however, it cannot be called after the destruction of the
 * stop_source. Thus, extreme care should be taken when capturing by reference to not access objects
 * after their lifetime has ended.
 */
class stop_callback {
  private:
    template <typename F>
    class holder : public stop_source::Cb {
      public:
        explicit holder(F&& f): f_(std::forward<F>(f)) {}
        holder(const holder&) = delete;
        holder(holder&&) = delete;
        holder& operator=(const holder&) = delete;
        holder& operator=(holder&&) = delete;
        virtual ~holder() = default;

        void invoke() override {
            std::invoke(f_);
        }
      private:
        // logically const
        F f_;
    };
  public:
    template <typename F> requires std::invocable<F>
    stop_callback(const stop_token& st, F&& cb)
        : stop_source_(st.stop_source_), cb_(std::make_shared<holder<F>>(std::forward<F>(cb))) {
        stop_source_.register_cb(cb_);
    }

    stop_callback(const stop_callback&) = delete;
    stop_callback(stop_callback&&) = delete;

    ~stop_callback() {
        stop_source_.unregister_cb();
    }

  private:
    const stop_source& stop_source_;
    // we are the sole owner of this cb
    std::shared_ptr<stop_source::Cb> cb_;
};

inline bool stop_token::stop_requested() const {
    return stop_source_.stop_requested();
}

}

#pragma pop_macro("LOG_TAG")
