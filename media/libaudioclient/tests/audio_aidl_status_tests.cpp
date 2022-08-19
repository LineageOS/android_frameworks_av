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

#include <gtest/gtest.h>
#include <media/AidlConversionUtil.h>
#include <utils/Errors.h>

using namespace android;
using namespace android::aidl_utils;
using android::binder::Status;

// Tests for statusTFromBinderStatus() and binderStatusFromStatusT().

// STATUS_T_SMALL_VALUE_LIMIT is an arbitrary limit where we exhaustively check status_t errors.
// It is known that this limit doesn't cover UNKNOWN_ERROR ~ INT32_MIN.
constexpr status_t STATUS_T_SMALL_VALUE_LIMIT = -1000;

// Small status values are preserved on round trip
TEST(audio_aidl_status_tests, statusRoundTripSmallValues) {
    for (status_t status = 0; status > STATUS_T_SMALL_VALUE_LIMIT; --status) {
        ASSERT_EQ(status, statusTFromBinderStatus(binderStatusFromStatusT(status)));
    }
}

// Special status values are preserved on round trip.
TEST(audio_aidl_status_tests, statusRoundTripSpecialValues) {
    for (status_t status :
         {OK, UNKNOWN_ERROR, NO_MEMORY, INVALID_OPERATION, BAD_VALUE, BAD_TYPE, NAME_NOT_FOUND,
          PERMISSION_DENIED, NO_INIT, ALREADY_EXISTS, DEAD_OBJECT, FAILED_TRANSACTION, BAD_INDEX,
          NOT_ENOUGH_DATA, WOULD_BLOCK, TIMED_OUT, UNKNOWN_TRANSACTION, FDS_NOT_ALLOWED}) {
        ASSERT_EQ(status, statusTFromBinderStatus(binderStatusFromStatusT(status)));
    }
}

// Binder exceptions show as an error (not fixed at this time); these come fromExceptionCode().
TEST(audio_aidl_status_tests, binderStatusExceptions) {
    for (int exceptionCode : {
                 // Status::EX_NONE,
                 Status::EX_SECURITY, Status::EX_BAD_PARCELABLE, Status::EX_ILLEGAL_ARGUMENT,
                 Status::EX_NULL_POINTER, Status::EX_ILLEGAL_STATE, Status::EX_NETWORK_MAIN_THREAD,
                 Status::EX_UNSUPPORTED_OPERATION,
                 // Status::EX_SERVICE_SPECIFIC, -- tested fromServiceSpecificError()
                 Status::EX_PARCELABLE,
                 // This is special and Java specific; see Parcel.java.
                 Status::EX_HAS_REPLY_HEADER,
                 // This is special, and indicates to C++ binder proxies that the
                 // transaction has failed at a low level.
                 // Status::EX_TRANSACTION_FAILED, -- tested fromStatusT().
         }) {
        ASSERT_NE(OK, statusTFromBinderStatus(Status::fromExceptionCode(exceptionCode)));
    }
}

// Binder transaction errors show exactly in status_t; these come fromStatusT().
TEST(audio_aidl_status_tests, binderStatusTransactionError) {
    for (status_t status :
         {OK,  // Note: fromStatusT does check if this is 0, so this is no error.
          UNKNOWN_ERROR, NO_MEMORY, INVALID_OPERATION, BAD_VALUE, BAD_TYPE, NAME_NOT_FOUND,
          PERMISSION_DENIED, NO_INIT, ALREADY_EXISTS, DEAD_OBJECT, FAILED_TRANSACTION, BAD_INDEX,
          NOT_ENOUGH_DATA, WOULD_BLOCK, TIMED_OUT, UNKNOWN_TRANSACTION, FDS_NOT_ALLOWED}) {
        ASSERT_EQ(status, statusTFromBinderStatus(Status::fromStatusT(status)));
    }
}

// Binder service specific errors show in status_t; these come fromServiceSpecificError().
TEST(audio_aidl_status_tests, binderStatusServiceSpecificError) {
    // fromServiceSpecificError() still stores exception code if status is 0.
    for (status_t status = -1; status > STATUS_T_SMALL_VALUE_LIMIT; --status) {
        ASSERT_EQ(status, statusTFromBinderStatus(Status::fromServiceSpecificError(status)));
    }
}

// Binder status with message.
TEST(audio_aidl_status_tests, binderStatusMessage) {
    const String8 message("abcd");
    for (status_t status = -1; status > STATUS_T_SMALL_VALUE_LIMIT; --status) {
        const Status binderStatus = binderStatusFromStatusT(status, message.c_str());
        ASSERT_EQ(status, statusTFromBinderStatus(binderStatus));
        ASSERT_EQ(message, binderStatus.exceptionMessage());
    }
}
