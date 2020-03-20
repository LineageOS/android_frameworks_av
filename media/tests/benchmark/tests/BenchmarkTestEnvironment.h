/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef __BENCHMARK_TEST_ENVIRONMENT_H__
#define __BENCHMARK_TEST_ENVIRONMENT_H__

#include <gtest/gtest.h>

#include <getopt.h>

using namespace std;

class BenchmarkTestEnvironment : public ::testing::Environment {
  public:
    BenchmarkTestEnvironment()
        : res("/data/local/tmp/MediaBenchmark/res/"),
          statsFile("/data/local/tmp/MediaBenchmark/res/stats.csv") {}

    // Parses the command line argument
    int initFromOptions(int argc, char **argv);

    void setRes(const char *_res) { res = _res; }

    const string getRes() const { return res; }

    void setStatsFile(const string module) { statsFile = getRes() + module; }

    const string getStatsFile() const { return statsFile; }

    bool writeStatsHeader();

  private:
    string res;
    string statsFile;
};

int BenchmarkTestEnvironment::initFromOptions(int argc, char **argv) {
    static struct option options[] = {{"path", required_argument, 0, 'P'}, {0, 0, 0, 0}};

    while (true) {
        int index = 0;
        int c = getopt_long(argc, argv, "P:", options, &index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'P': {
                setRes(optarg);
                break;
            }
            default:
                break;
        }
    }

    if (optind < argc) {
        fprintf(stderr,
                "unrecognized option: %s\n\n"
                "usage: %s <gtest options> <test options>\n\n"
                "test options are:\n\n"
                "-P, --path: Resource files directory location\n",
                argv[optind ?: 1], argv[0]);
        return 2;
    }
    return 0;
}

/**
 * Writes the stats header to a file
 * <p>
 * \param statsFile    file where the stats data is to be written
 **/
bool BenchmarkTestEnvironment::writeStatsHeader() {
    char statsHeader[] =
        "currentTime, fileName, operation, componentName, NDK/SDK, sync/async, setupTime, "
        "destroyTime, minimumTime, maximumTime, averageTime, timeToProcess1SecContent, "
        "totalBytesProcessedPerSec, timeToFirstFrame, totalSizeInBytes, totalTime\n";
    FILE *fpStats = fopen(statsFile.c_str(), "w");
    if(!fpStats) {
        return false;
    }
    int32_t numBytes = fwrite(statsHeader, sizeof(char), sizeof(statsHeader), fpStats);
    fclose(fpStats);
    if(numBytes != sizeof(statsHeader)) {
        return false;
    }
    return true;
}

#endif  // __BENCHMARK_TEST_ENVIRONMENT_H__
