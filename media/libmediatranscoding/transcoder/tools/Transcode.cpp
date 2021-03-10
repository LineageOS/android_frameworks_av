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

#include <android-base/macros.h>
#include <fcntl.h>
#include <getopt.h>
#include <media/MediaTranscoder.h>
#include <media/NdkCommon.h>

using namespace android;

#define ERR_MSG(fmt, ...) fprintf(stderr, "Error: " fmt "\n", ##__VA_ARGS__)

class TranscoderCallbacks : public MediaTranscoder::CallbackInterface {
public:
    media_status_t waitForTranscodingFinished() {
        std::unique_lock<std::mutex> lock(mMutex);
        while (!mFinished) {
            mCondition.wait(lock);
        }
        return mStatus;
    }

private:
    virtual void onFinished(const MediaTranscoder* /*transcoder*/) override {
        notifyTranscoderFinished(AMEDIA_OK);
    }

    virtual void onError(const MediaTranscoder* /*transcoder*/, media_status_t error) override {
        ERR_MSG("Transcoder failed with error %d", error);
        notifyTranscoderFinished(error);
    }

    virtual void onProgressUpdate(const MediaTranscoder* /*transcoder*/,
                                  int32_t /*progress*/) override {}

    virtual void onCodecResourceLost(
            const MediaTranscoder* /*transcoder*/,
            const std::shared_ptr<ndk::ScopedAParcel>& /*pausedState*/) override {
        ERR_MSG("Transcoder lost codec resource while transcoding");
        notifyTranscoderFinished(AMEDIACODEC_ERROR_INSUFFICIENT_RESOURCE);
    }

    virtual void onHeartBeat(const MediaTranscoder* /*transcoder*/) override {}

    void notifyTranscoderFinished(media_status_t status) {
        std::unique_lock<std::mutex> lock(mMutex);
        mFinished = true;
        mStatus = status;
        mCondition.notify_all();
    }

    std::mutex mMutex;
    std::condition_variable mCondition;
    bool mFinished = false;
    media_status_t mStatus = AMEDIA_OK;
};

struct TranscodeConfig {
    std::string srcFile;
    std::string dstFile;

    std::string dstCodec{AMEDIA_MIMETYPE_VIDEO_AVC};
    int32_t bitrate = -1;
};

static int transcode(const struct TranscodeConfig& config) {
    auto callbacks = std::make_shared<TranscoderCallbacks>();
    auto transcoder = MediaTranscoder::create(callbacks, -1 /*heartBeatIntervalUs*/);

    const int srcFd = open(config.srcFile.c_str(), O_RDONLY);
    if (srcFd <= 0) {
        ERR_MSG("Unable to open source file %s", config.srcFile.c_str());
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    media_status_t status = transcoder->configureSource(srcFd);
    close(srcFd);
    if (status != AMEDIA_OK) {
        ERR_MSG("configureSource returned error %d", status);
        return status;
    }

    std::vector<std::shared_ptr<AMediaFormat>> trackFormats = transcoder->getTrackFormats();
    if (trackFormats.size() <= 0) {
        ERR_MSG("No tracks found in source file");
        return AMEDIA_ERROR_MALFORMED;
    }

    for (int i = 0; i < trackFormats.size(); ++i) {
        AMediaFormat* dstFormat = nullptr;

        const char* mime = nullptr;
        AMediaFormat_getString(trackFormats[i].get(), AMEDIAFORMAT_KEY_MIME, &mime);

        if (strncmp(mime, "video/", 6) == 0) {
            dstFormat = AMediaFormat_new();
            AMediaFormat_setString(dstFormat, AMEDIAFORMAT_KEY_MIME, config.dstCodec.c_str());

            if (config.bitrate > 0) {
                AMediaFormat_setInt32(dstFormat, AMEDIAFORMAT_KEY_BIT_RATE, config.bitrate);
            }
        }

        status = transcoder->configureTrackFormat(i, dstFormat);

        if (dstFormat != nullptr) {
            AMediaFormat_delete(dstFormat);
        }

        if (status != AMEDIA_OK) {
            ERR_MSG("configureTrack returned error %d", status);
            return status;
        }
    }

    // Note: Overwrites existing file.
    const int dstFd = open(config.dstFile.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (dstFd <= 0) {
        ERR_MSG("Unable to open destination file %s", config.dstFile.c_str());
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    status = transcoder->configureDestination(dstFd);
    close(dstFd);
    if (status != AMEDIA_OK) {
        ERR_MSG("configureDestination returned error %d", status);
        return status;
    }

    status = transcoder->start();
    if (status != AMEDIA_OK) {
        ERR_MSG("start returned error %d", status);
        return status;
    }

    return callbacks->waitForTranscodingFinished();
}

// Options.
static const struct option kLongOpts[] = {{"help", no_argument, nullptr, 'h'},
                                          {"codec", required_argument, nullptr, 'c'},
                                          {"bitrate", required_argument, nullptr, 'b'},
                                          {0, 0, 0, 0}};
static const char kShortOpts[] = "hc:b:";

static void printUsageAndExit() {
    const char* usage =
            "  -h / --help    : Print this usage message and exit.\n"
            "  -c / --codec   : Specify output video codec type using MediaFormat codec mime "
            "type.\n"
            "                     Defaults to \"video/avc\".\n"
            "  -b / --bitrate : Specify output video bitrate in bits per second.\n"
            "                     Defaults to estimating and preserving the original bitrate.\n"
            "";

    printf("Usage: %s [-h] [-c CODEC] <srcfile> <dstfile>\n%s", getprogname(), usage);
    exit(-1);
}

int main(int argc, char** argv) {
    int c;
    TranscodeConfig config;

    while ((c = getopt_long(argc, argv, kShortOpts, kLongOpts, nullptr)) >= 0) {
        switch (c) {
        case 'c':
            config.dstCodec.assign(optarg);
            break;

        case 'b':
            config.bitrate = atoi(optarg);
            if (config.bitrate <= 0) {
                ERR_MSG("Bitrate must an integer larger than zero.");
                printUsageAndExit();
            }
            break;

        case '?':
            FALLTHROUGH_INTENDED;
        case 'h':
            FALLTHROUGH_INTENDED;
        default:
            printUsageAndExit();
            break;
        }
    }

    if (optind > (argc - 2)) {
        ERR_MSG("Source and destination file not specified");
        printUsageAndExit();
    }
    config.srcFile.assign(argv[optind++]);
    config.dstFile.assign(argv[optind]);

    return transcode(config);
}
