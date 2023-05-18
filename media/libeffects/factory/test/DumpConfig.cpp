/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <getopt.h>

#include <media/EffectsFactoryApi.h>
#include "EffectsXmlConfigLoader.h"
#include "EffectsConfigLoader.h"

int main(int argc, char* argv[]) {
    const char* const short_opts = "lx:h";
    const option long_opts[] = {{"legacy", no_argument, nullptr, 'l'},
                                {"xml", optional_argument, nullptr, 'x'},
                                {"help", no_argument, nullptr, 'h'}};

    const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
    switch (opt) {
        case 'l': { // -l or --legacy
            printf("Dumping legacy effect config file\n");
            if (EffectLoadEffectConfig() < 0) {
                fprintf(stderr, "loadEffectConfig failed, see logcat for detail.\n");
                return 1;
            }
            return EffectDumpEffects(STDOUT_FILENO);
        }
        case 'x': { // -x or --xml
            printf("Dumping effect config file: %s\n", (optarg == NULL) ? "default" : optarg);
            ssize_t ret = EffectLoadXmlEffectConfig(optarg);
            if (ret < 0) {
                fprintf(stderr, "loadXmlEffectConfig failed, see logcat for detail.\n");
                return 1;
            }
            if (ret > 0) {
                printf("Partially failed to load config. Skipped %zu elements.\n",
                        (size_t)ret);
            }
            return EffectDumpEffects(STDOUT_FILENO);
        }
        case 'h': // -h or --help
        default: {
            printf("Usage: %s\n"
                   "--legacy (or -l):        Legacy audio effect config file to load\n"
                   "--xml (or -x) <FILE>:    Audio effect config file to load\n"
                   "--help (or -h):          Show this help\n",
                   argv[0]);
            return 0;
        }
    }
}
