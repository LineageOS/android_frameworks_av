#
# Copyright (C) 2019 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#

cmake_minimum_required(VERSION 3.4.1)

set(native_source_path "../../../../src/native")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")

add_library(
  mediabenchmark_jni SHARED
  NativeExtractor.cpp
  NativeMuxer.cpp
  NativeDecoder.cpp
  NativeEncoder.cpp
  ${native_source_path}/common/BenchmarkCommon.cpp
  ${native_source_path}/common/Stats.cpp
  ${native_source_path}/common/utils/Timers.cpp
  ${native_source_path}/extractor/Extractor.cpp
  ${native_source_path}/muxer/Muxer.cpp
  ${native_source_path}/decoder/Decoder.cpp
  ${native_source_path}/encoder/Encoder.cpp)

include_directories(${native_source_path}/common)
include_directories(${native_source_path}/extractor)
include_directories(${native_source_path}/muxer)
include_directories(${native_source_path}/decoder)
include_directories(${native_source_path}/encoder)

find_library(log-lib log)

target_link_libraries(mediabenchmark_jni mediandk ${log-lib})
