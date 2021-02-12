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

#include <iostream>
#include <vector>

constexpr int kMinLoopLimitValue = 1;
constexpr int kNumPeaks = 3;

/*!
  \brief           Compute the length normalized correlation of two signals

  \sigX            Pointer to signal 1
  \sigY            Pointer to signal 2
  \len             Length of signals
  \enableCrossCorr Flag to be set to 1 if cross-correlation is needed

  \return          First value is vector of correlation peak indices
                   Second value is vector of correlation peak values
*/

static std::pair<std::vector<int>, std::vector<float>> correlation(const int16_t* sigX,
                                                                   const int16_t* sigY, int len,
                                                                   int16_t enableCrossCorr) {
    float maxCorrVal = 0.f, prevCorrVal = 0.f;
    int delay = 0, peakIndex = 0, flag = 0;
    int loopLim = (1 == enableCrossCorr) ? len : kMinLoopLimitValue;
    std::vector<int> peakIndexVect(kNumPeaks, 0);
    std::vector<float> peakValueVect(kNumPeaks, 0.f);
    for (int i = 0; i < loopLim; i++) {
        float corrVal = 0.f;
        for (int j = i; j < len; j++) {
            corrVal += (float)(sigX[j] * sigY[j - i]);
        }
        corrVal /= len - i;
        if (corrVal > maxCorrVal) {
            delay = i;
            maxCorrVal = corrVal;
        }
        // Correlation peaks are expected to be observed at equal intervals. The interval length is
        // expected to match with wave period.
        // The following block of code saves the first kNumPeaks number of peaks and the index at
        // which they occur.
        if (peakIndex < kNumPeaks) {
            if (corrVal > prevCorrVal) {
                peakIndexVect[peakIndex] = i;
                peakValueVect[peakIndex] = corrVal;
                flag = 0;
            } else if (0 == flag) {
                peakIndex++;
                flag = 1;
            }
        }
        if (peakIndex == kNumPeaks) break;
        prevCorrVal = corrVal;
    }
    return {peakIndexVect, peakValueVect};
}

void printUsage() {
    printf("\nUsage: ");
    printf("\n     correlation <firstFile> <secondFile> [enableCrossCorr]\n");
    printf("\nwhere, \n     <firstFile>       is the first file name");
    printf("\n     <secondFile>      is the second file name");
    printf("\n     [enableCrossCorr] is flag to set for cross-correlation (Default 1)\n\n");
}

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        printUsage();
        return EXIT_FAILURE;
    }

    std::unique_ptr<FILE, decltype(&fclose)> fInput1(fopen(argv[1], "rb"), &fclose);
    if (fInput1.get() == NULL) {
        printf("\nError: missing file %s\n", argv[1]);
        return EXIT_FAILURE;
    }
    std::unique_ptr<FILE, decltype(&fclose)> fInput2(fopen(argv[2], "rb"), &fclose);
    if (fInput2.get() == NULL) {
        printf("\nError: missing file %s\n", argv[2]);
        return EXIT_FAILURE;
    }
    int16_t enableCrossCorr = (4 == argc) ? atoi(argv[3]) : 1;

    fseek(fInput1.get(), 0L, SEEK_END);
    unsigned int fileSize1 = ftell(fInput1.get());
    rewind(fInput1.get());
    fseek(fInput2.get(), 0L, SEEK_END);
    unsigned int fileSize2 = ftell(fInput2.get());
    rewind(fInput2.get());
    if (fileSize1 != fileSize2) {
        printf("\nError: File sizes different\n");
        return EXIT_FAILURE;
    }

    size_t numFrames = fileSize1 / sizeof(int16_t);
    std::unique_ptr<int16_t[]> inBuffer1(new int16_t[numFrames]());
    std::unique_ptr<int16_t[]> inBuffer2(new int16_t[numFrames]());

    if (numFrames != fread(inBuffer1.get(), sizeof(int16_t), numFrames, fInput1.get())) {
        printf("\nError: Unable to read %zu samples from file %s\n", numFrames, argv[1]);
        return EXIT_FAILURE;
    }

    if (numFrames != fread(inBuffer2.get(), sizeof(int16_t), numFrames, fInput2.get())) {
        printf("\nError: Unable to read %zu samples from file %s\n", numFrames, argv[2]);
        return EXIT_FAILURE;
    }

    auto pairAutoCorr1 = correlation(inBuffer1.get(), inBuffer1.get(), numFrames, enableCrossCorr);
    auto pairAutoCorr2 = correlation(inBuffer2.get(), inBuffer2.get(), numFrames, enableCrossCorr);

    // Following code block checks pitch period difference between two input signals. They must
    // match as AGC applies only gain, no frequency related computation is done.
    bool pitchMatch = false;
    for (unsigned i = 0; i < pairAutoCorr1.first.size() - 1; i++) {
        if (pairAutoCorr1.first[i + 1] - pairAutoCorr1.first[i] !=
            pairAutoCorr2.first[i + 1] - pairAutoCorr2.first[i]) {
            pitchMatch = false;
            break;
        }
        pitchMatch = true;
    }
    if (pitchMatch) {
        printf("Auto-correlation  : Pitch matched\n");
    } else {
        printf("Auto-correlation  : Pitch mismatch\n");
        return EXIT_FAILURE;
    }

    if (enableCrossCorr) {
        auto pairCrossCorr =
                correlation(inBuffer1.get(), inBuffer2.get(), numFrames, enableCrossCorr);

        // Since AGC applies only gain, the pitch information obtained from cross correlation data
        // of input and output is expected to be same as the input signal's pitch information.
        pitchMatch = false;
        for (unsigned i = 0; i < pairCrossCorr.first.size() - 1; i++) {
            if (pairAutoCorr1.first[i + 1] - pairAutoCorr1.first[i] !=
                pairCrossCorr.first[i + 1] - pairCrossCorr.first[i]) {
                pitchMatch = false;
                break;
            }
            pitchMatch = true;
        }
        if (pitchMatch) {
            printf("Cross-correlation : Pitch matched for AGC\n");
            if (pairAutoCorr1.second[0]) {
                printf("Expected gain     : (maxCrossCorr / maxAutoCorr1) = %f\n",
                       pairCrossCorr.second[0] / pairAutoCorr1.second[0]);
            }
        } else {
            printf("Cross-correlation : Pitch mismatch\n");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
