/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "inplace_function_tests"

#include <mediautils/InPlaceFunction.h>

#include <type_traits>

#include <gtest/gtest.h>
#include <log/log.h>

using namespace android;
using namespace android::mediautils;

struct BigCallable {
    BigCallable(size_t* x, size_t val1, size_t val2) : ptr(x), a(val1), b(val2) {}
    size_t* ptr;
    size_t a;
    size_t b;
    size_t operator()(size_t input) const {
        *ptr += a * 100 + b * 10 + input;
        return 8;
    }
};

TEST(InPlaceFunctionTests, Basic) {
    size_t x = 5;
    InPlaceFunction<size_t(size_t)> func;
    {
        BigCallable test{&x, 2, 3};
        func = test;
    }
    EXPECT_EQ(func(2), 8ull);
    EXPECT_EQ(x, 232ull + 5);
}

TEST(InPlaceFunctionTests, Invalid) {
    InPlaceFunction<size_t(size_t)> func;
    EXPECT_TRUE(!func);
    InPlaceFunction<size_t(size_t)> func2{nullptr};
    EXPECT_TRUE(!func2);
    InPlaceFunction<size_t(size_t)> func3 = [](size_t x) { return x; };
    EXPECT_TRUE(!(!func3));
    func3 = nullptr;
    EXPECT_TRUE(!func3);
}

TEST(InPlaceFunctionTests, MultiArg) {
    InPlaceFunction<size_t(size_t, size_t, size_t)> func = [](size_t a, size_t b, size_t c) {
        return a + b + c;
    };
    EXPECT_EQ(func(2, 3, 5), 2ull + 3 + 5);
}
struct Record {
    Record(size_t m, size_t c, size_t d) : move_called(m), copy_called(c), dtor_called(d) {}
    Record() {}
    size_t move_called = 0;
    size_t copy_called = 0;
    size_t dtor_called = 0;
    friend std::ostream& operator<<(std::ostream& os, const Record& record) {
        return os << "Record, moves: " << record.move_called << ", copies: " << record.copy_called
                  << ", dtor: " << record.dtor_called << '\n';
    }
};

bool operator==(const Record& lhs, const Record& rhs) {
    return lhs.move_called == rhs.move_called && lhs.copy_called == rhs.copy_called &&
           lhs.dtor_called == rhs.dtor_called;
}

struct Noisy {
    Record& ref;
    size_t state;
    Noisy(Record& record, size_t val) : ref(record), state(val) {}
    Noisy(const Noisy& other) : ref(other.ref), state(other.state) { ref.copy_called++; }

    Noisy(Noisy&& other) : ref(other.ref), state(other.state) { ref.move_called++; }
    ~Noisy() { ref.dtor_called++; }

    size_t operator()() { return state; }
};

TEST(InPlaceFunctionTests, CtorForwarding) {
    Record record;
    Noisy noisy{record, 17};
    InPlaceFunction<size_t()> func{noisy};
    EXPECT_EQ(record, Record(0, 1, 0));  // move, copy, dtor
    EXPECT_EQ(func(), 17ull);
    Record record2;
    Noisy noisy2{record2, 13};
    InPlaceFunction<size_t()> func2{std::move(noisy2)};
    EXPECT_EQ(record2, Record(1, 0, 0));  // move, copy, dtor
    EXPECT_EQ(func2(), 13ull);
}

TEST(InPlaceFunctionTests, FunctionCtorForwarding) {
    {
        Record record;
        Noisy noisy{record, 17};
        InPlaceFunction<size_t()> func{noisy};
        EXPECT_EQ(record, Record(0, 1, 0));  // move, copy, dtor
        EXPECT_EQ(func(), 17ull);
        InPlaceFunction<size_t()> func2{func};
        EXPECT_EQ(record, Record(0, 2, 0));  // move, copy, dtor
        EXPECT_EQ(func2(), 17ull);
    }
    Record record;
    Noisy noisy{record, 13};
    InPlaceFunction<size_t()> func{noisy};
    EXPECT_EQ(record, Record(0, 1, 0));  // move, copy, dtor
    EXPECT_EQ(func(), 13ull);
    InPlaceFunction<size_t()> func2{std::move(func)};
    EXPECT_EQ(record, Record(1, 1, 0));  // move, copy, dtor
    EXPECT_EQ(func2(), 13ull);
    // We expect moved from functions to still be valid
    EXPECT_TRUE(!(!func));
    EXPECT_EQ(static_cast<bool>(func), static_cast<bool>(func2));
    EXPECT_EQ(func(), 13ull);
}

TEST(InPlaceFunctionTests, Dtor) {
    Record record;
    {
        InPlaceFunction<size_t()> func;
        {
            Noisy noisy{record, 17};
            func = noisy;
        }
        EXPECT_EQ(func(), 17ull);
        EXPECT_EQ(record.dtor_called, 1ull);
    }
    EXPECT_EQ(record.dtor_called, 2ull);
}

TEST(InPlaceFunctionTests, Assignment) {
    {
        Record record;
        Record record2;
        Noisy noisy{record, 17};
        Noisy noisy2{record2, 5};
        InPlaceFunction<size_t()> func{noisy};
        EXPECT_EQ(func(), 17ull);
        EXPECT_EQ(record.dtor_called, 0ull);
        func = noisy2;
        EXPECT_EQ(record.dtor_called, 1ull);
        EXPECT_EQ(record2, Record(0, 1, 0));  // move, copy, dtor
        EXPECT_EQ(func(), 5ull);
    }
    {
        Record record;
        Record record2;
        Noisy noisy{record, 17};
        Noisy noisy2{record2, 5};
        InPlaceFunction<size_t()> func{noisy};
        EXPECT_EQ(func(), 17ull);
        EXPECT_EQ(record.dtor_called, 0ull);
        func = std::move(noisy2);
        EXPECT_EQ(record.dtor_called, 1ull);
        EXPECT_EQ(record2, Record(1, 0, 0));  // move, copy, dtor
        EXPECT_EQ(func(), 5ull);
    }

    {
        Record record;
        Record record2;
        Noisy noisy{record, 17};
        Noisy noisy2{record2, 13};
        {
            InPlaceFunction<size_t()> func{noisy};
            EXPECT_EQ(func(), 17ull);
            InPlaceFunction<size_t()> func2{noisy2};
            EXPECT_EQ(record2, Record(0, 1, 0));  // move, copy, dtor
            EXPECT_EQ(record.dtor_called, 0ull);
            func = func2;
            EXPECT_EQ(record.dtor_called, 1ull);
            EXPECT_EQ(func(), 13ull);
            EXPECT_EQ(record2, Record(0, 2, 0));  // move, copy, dtor
            EXPECT_TRUE(static_cast<bool>(func2));
            EXPECT_EQ(func2(), 13ull);
        }
        EXPECT_EQ(record2, Record(0, 2, 2));  // move, copy, dtor
    }

    {
        Record record;
        Record record2;
        Noisy noisy{record, 17};
        Noisy noisy2{record2, 13};
        {
            InPlaceFunction<size_t()> func{noisy};
            EXPECT_EQ(func(), 17ull);
            InPlaceFunction<size_t()> func2{noisy2};
            EXPECT_EQ(record.dtor_called, 0ull);
            EXPECT_EQ(record2, Record(0, 1, 0));  // move, copy, dtor
            func = std::move(func2);
            EXPECT_EQ(record.dtor_called, 1ull);
            EXPECT_EQ(func(), 13ull);
            EXPECT_EQ(record2, Record(1, 1, 0));  // move, copy, dtor
            // Moved from function is still valid
            EXPECT_TRUE(static_cast<bool>(func2));
            EXPECT_EQ(func2(), 13ull);
        }
        EXPECT_EQ(record2, Record(1, 1, 2));  // move, copy, dtor
    }
}

TEST(InPlaceFunctionTests, Swap) {
    Record record1;
    Record record2;
    InPlaceFunction<size_t()> func1 = Noisy{record1, 5};
    InPlaceFunction<size_t()> func2 = Noisy{record2, 7};
    EXPECT_EQ(record1, Record(1, 0, 1));  // move, copy, dtor
    EXPECT_EQ(record2, Record(1, 0, 1));  // move, copy, dtor
    EXPECT_EQ(func1(), 5ull);
    EXPECT_EQ(func2(), 7ull);
    func1.swap(func2);
    EXPECT_EQ(record1, Record(2, 0, 2));  // move, copy, dtor
    // An additional move and destroy into the temporary object
    EXPECT_EQ(record2, Record(3, 0, 3));  // move, copy, dtor
    EXPECT_EQ(func1(), 7ull);
    EXPECT_EQ(func2(), 5ull);
}

TEST(InPlaceFunctionTests, Conversion) {
    Record record;
    Noisy noisy{record, 15};
    {
        InPlaceFunction<size_t(), 16> func2 = noisy;
        EXPECT_EQ(record, Record(0, 1, 0));  // move, copy, dtor
        {
            InPlaceFunction<size_t(), 32> func{func2};
            EXPECT_EQ(record, Record(0, 2, 0));  // move, copy, dtor
            EXPECT_EQ(func2(), func());
        }
        EXPECT_EQ(record, Record(0, 2, 1));  // move, copy, dtor
    }
    EXPECT_EQ(record, Record(0, 2, 2));  // move, copy, dtor
}

TEST(InPlaceFunctionTests, ConversionMove) {
    Record record;
    Noisy noisy{record, 15};
    {
        InPlaceFunction<size_t(), 16> func2 = noisy;
        EXPECT_EQ(record, Record(0, 1, 0));  // move, copy, dtor
        {
            InPlaceFunction<size_t(), 32> func{std::move(func2)};
            EXPECT_EQ(record, Record(1, 1, 0));  // move, copy, dtor
            EXPECT_EQ(func2(), func());
        }
        EXPECT_EQ(record, Record(1, 1, 1));  // move, copy, dtor
    }
    EXPECT_EQ(record, Record(1, 1, 2));  // move, copy, dtor
}

TEST(InPlaceFunctionTests, ConversionAssign) {
    Record record;
    Noisy noisy{record, 15};
    {
        InPlaceFunction<size_t(), 32> func;
        {
            InPlaceFunction<size_t(), 16> func2 = noisy;
            EXPECT_EQ(record, Record(0, 1, 0));  // move, copy, dtor
            func = func2;
            EXPECT_EQ(record, Record(0, 2, 0));  // move, copy, dtor
            EXPECT_EQ(func2(), func());
        }
        EXPECT_EQ(record, Record(0, 2, 1));  // move, copy, dtor
    }
    EXPECT_EQ(record, Record(0, 2, 2));  // move, copy, dtor
}

TEST(InPlaceFunctionTests, ConversionAssignMove) {
    Record record;
    Noisy noisy{record, 15};
    {
        InPlaceFunction<size_t(), 32> func;
        {
            InPlaceFunction<size_t(), 16> func2 = noisy;
            EXPECT_EQ(record, Record(0, 1, 0));  // move, copy, dtor
            func = std::move(func2);
            EXPECT_EQ(record, Record(1, 1, 0));  // move, copy, dtor
            EXPECT_EQ(func2(), func());
        }
        EXPECT_EQ(record, Record(1, 1, 1));  // move, copy, dtor
    }
    EXPECT_EQ(record, Record(1, 1, 2));  // move, copy, dtor
}

struct NoMoveCopy {
    NoMoveCopy() = default;
    NoMoveCopy(const NoMoveCopy&) = delete;
    NoMoveCopy(NoMoveCopy&&) = delete;
};
struct TestCallable {
    NoMoveCopy& operator()(NoMoveCopy& x) { return x; }
};

TEST(InPlaceFunctionTests, ArgumentForwarding) {
    const auto lambd = [](NoMoveCopy& x) -> NoMoveCopy& { return x; };
    InPlaceFunction<NoMoveCopy&(NoMoveCopy&)> func = lambd;
    const auto lambd2 = [](NoMoveCopy&& x) -> NoMoveCopy&& { return std::move(x); };
    InPlaceFunction<NoMoveCopy && (NoMoveCopy &&)> func2 = lambd2;
    auto lvalue = NoMoveCopy{};
    func(lvalue);
    func2(NoMoveCopy{});
    InPlaceFunction<void(NoMoveCopy&)> func3 = [](const NoMoveCopy&) {};
    func3(lvalue);
    InPlaceFunction<void(NoMoveCopy &&)> func4 = [](const NoMoveCopy&) {};
    func4(std::move(lvalue));
    InPlaceFunction<void(const NoMoveCopy&)> func5 = [](const NoMoveCopy&) {};
    func5(lvalue);
    InPlaceFunction<void(const NoMoveCopy&&)> func6 = [](const NoMoveCopy&) {};
    func6(std::move(lvalue));
    InPlaceFunction<void(const NoMoveCopy&&)> func7 = [](const NoMoveCopy&&) {};
    func7(std::move(lvalue));
    InPlaceFunction<void(NoMoveCopy &&)> func8 = [](const NoMoveCopy&&) {};
    func8(std::move(lvalue));

    {
        Record record;
        Noisy noisy{record, 5};
        const auto lambd3 = [](Noisy) {};
        InPlaceFunction<void(Noisy)> func3{lambd3};
        EXPECT_EQ(record, Record(0, 0, 0));  // move, copy, dtor
        func3(std::move(noisy));
        EXPECT_EQ(record, Record(2, 0, 2));  // move, copy, dtor
    }

    {
        Record record;
        Noisy noisy{record, 5};
        const auto lambd3 = [](Noisy) {};
        InPlaceFunction<void(Noisy)> func3{lambd3};
        EXPECT_EQ(record, Record(0, 0, 0));  // move, copy, dtor
        func3(noisy);
        EXPECT_EQ(record, Record(1, 1, 2));  // move, copy, dtor
    }
}

TEST(InPlaceFunctionTests, VoidFunction) {
    InPlaceFunction<void(size_t)> func = [](size_t x) -> size_t { return x; };
    func(5);
    InPlaceFunction<void(void)> func2 = []() -> size_t { return 5; };
    func2();
}
NoMoveCopy foo() {
    return NoMoveCopy();
}
struct Test {
    NoMoveCopy operator()() { return NoMoveCopy{}; }
};

TEST(InPlaceFunctionTests, FullElision) {
    InPlaceFunction<NoMoveCopy()> func = foo;
}

TEST(InPlaceFunctionTests, ReturnConversion) {
    const auto lambd = [](int&& x) -> int&& { return std::move(x); };
    InPlaceFunction<int && (int&& x)> func = lambd;
    func(5);
    InPlaceFunction<void(int)> func3 = [](double) {};
    func3(5);
    InPlaceFunction<double()> func4 = []() -> int { return 5; };
    func4();
}

struct Overloaded {
    int operator()() & { return 2; }
    int operator()() const& { return 3; }
    int operator()() && { return 4; }
    int operator()() const&& { return 5; }
};

TEST(InPlaceFunctionTests, OverloadResolution) {
    InPlaceFunction<int()> func = Overloaded{};
    EXPECT_EQ(func(), 2);
    EXPECT_EQ(std::move(func()), 2);
}

template <class T, class U, class = void>
struct can_assign : std::false_type {};

template <class T, class U>
struct can_assign<T, U, typename std::void_t<decltype(T().operator=(U()))>> : std::true_type {};

template <class From, class To, bool Expected>
static constexpr bool Convertible =
        (can_assign<To, From>::value ==
         std::is_constructible_v<To, From>)&&(std::is_constructible_v<To, From> == Expected);

struct TooBig {
    std::array<uint64_t, 5> big = {1, 2, 3, 4, 5};
    size_t operator()() { return static_cast<size_t>(big[0] + big[1] + big[2] + big[3] + big[4]); }
};
static_assert(sizeof(TooBig) == 40);
struct NotCallable {};
struct WrongArg {
    void operator()(NotCallable) {}
};
struct WrongRet {
    NotCallable operator()(size_t) { return NotCallable{}; }
};

static_assert(Convertible<InPlaceFunction<size_t(), 32>, InPlaceFunction<size_t(), 32>, true>);
static_assert(
        Convertible<InPlaceFunction<size_t(size_t), 32>, InPlaceFunction<size_t(), 32>, false>);
static_assert(Convertible<InPlaceFunction<void(), 32>, InPlaceFunction<size_t(), 32>, false>);
static_assert(Convertible<TooBig, InPlaceFunction<size_t(), 32>, false>);
static_assert(Convertible<TooBig, InPlaceFunction<size_t(), 40>, true>);
static_assert(Convertible<NotCallable, InPlaceFunction<size_t(), 40>, false>);
static_assert(Convertible<WrongArg, InPlaceFunction<void(size_t), 40>, false>);
static_assert(Convertible<WrongRet, InPlaceFunction<size_t(size_t), 40>, false>);
// Void returning functions are modelled by any return type
static_assert(Convertible<WrongRet, InPlaceFunction<void(size_t), 40>, true>);

// Check constructibility/assignability from smaller function types
static_assert(Convertible<InPlaceFunction<size_t(), 32>, InPlaceFunction<size_t(), 24>, false>);
static_assert(Convertible<InPlaceFunction<size_t(), 32>, InPlaceFunction<size_t(), 40>, true>);
static_assert(
        Convertible<InPlaceFunction<size_t(), 32>, InPlaceFunction<size_t(size_t), 40>, false>);
static_assert(
        Convertible<InPlaceFunction<size_t(), 32>, InPlaceFunction<NotCallable(), 40>, false>);

struct BadLambd {
    int operator()(int&& x) { return std::move(x); }
};

static_assert(Convertible<BadLambd, InPlaceFunction<int(int&&), 32>, true>);
static_assert(Convertible<BadLambd, InPlaceFunction<int&(int&&), 32>, false>);
static_assert(Convertible<BadLambd, InPlaceFunction<const int&(int&&), 32>, false>);
static_assert(Convertible<BadLambd, InPlaceFunction<int && (int&&), 32>, false>);
static_assert(Convertible<BadLambd, InPlaceFunction<const int && (int&&), 32>, false>);

struct Base {};
struct Derived : Base {};
struct Converted {
    Converted(const Derived&) {}
};

struct ConvertCallable {
    Derived operator()() { return Derived{}; }
    Derived& operator()(Derived& x) { return x; }
    Derived&& operator()(Derived&& x) { return std::move(x); }
    const Derived& operator()(const Derived& x) { return x; }
    const Derived&& operator()(const Derived&& x) { return std::move(x); }
};

static_assert(Convertible<ConvertCallable, InPlaceFunction<Derived&()>, false>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<Base&()>, false>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<Derived()>, true>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<Base()>, true>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<Converted()>, true>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<Converted&()>, false>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<Converted && ()>, false>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<const Converted&()>, false>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<const Converted && ()>, false>);

static_assert(Convertible<ConvertCallable, InPlaceFunction<Derived&(Derived&)>, true>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<Base&(Derived&)>, true>);

static_assert(Convertible<ConvertCallable, InPlaceFunction<Derived && (Derived &&)>, true>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<Base && (Derived &&)>, true>);

static_assert(Convertible<ConvertCallable, InPlaceFunction<const Derived&(const Derived&)>, true>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<const Base&(const Derived&)>, true>);

static_assert(
        Convertible<ConvertCallable, InPlaceFunction<const Derived && (const Derived&&)>, true>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<const Base && (const Derived&&)>, true>);

static_assert(Convertible<ConvertCallable, InPlaceFunction<const Derived&(Derived&)>, true>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<const Base&(Derived&)>, true>);

static_assert(Convertible<ConvertCallable, InPlaceFunction<const Derived && (Derived &&)>, true>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<const Base && (Derived &&)>, true>);

static_assert(Convertible<ConvertCallable, InPlaceFunction<const Derived&(Derived&&)>, true>);
static_assert(Convertible<ConvertCallable, InPlaceFunction<const Base&(Derived&&)>, true>);
