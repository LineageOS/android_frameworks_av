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

#ifndef _HEIF_DECODER_API_
#define _HEIF_DECODER_API_

#include <vector>

/*
 * The output color pixel format of heif decoder.
 */
typedef enum {
    kHeifColorFormat_RGB565     = 0,
    kHeifColorFormat_RGBA_8888  = 1,
    kHeifColorFormat_BGRA_8888  = 2,
} HeifColorFormat;

/*
 * The color spaces encoded in the heif image.
 */
typedef enum {
    kHeifEncodedColor_RGB = 0,
    kHeifEncodedColor_YUV = 1,
    kHeifEncodedColor_CMYK = 2,
} HeifEncodedColor;

/*
 * Represents a color converted (RGB-based) video frame
 */
struct HeifFrameInfo {
    uint32_t mWidth;
    uint32_t mHeight;
    int32_t  mRotationAngle;           // Rotation angle, clockwise, should be multiple of 90
    uint32_t mBytesPerPixel;           // Number of bytes for one pixel
    int64_t mDurationUs;               // Duration of the frame in us
    std::vector<uint8_t> mIccData;     // ICC data array
};

/*
 * Abstract interface to provide data to HeifDecoder.
 */
struct HeifStream {
    HeifStream() {}

    virtual ~HeifStream() {}

    /*
     * Reads or skips size number of bytes. return the number of bytes actually
     * read or skipped.
     * If |buffer| == NULL, skip size bytes, return how many were skipped.
     * If |buffer| != NULL, copy size bytes into buffer, return how many were copied.
     */
    virtual size_t read(void* buffer, size_t size) = 0;

    /*
     * Rewinds to the beginning of the stream. Returns true if the stream is known
     * to be at the beginning after this call returns.
     */
    virtual bool rewind() = 0;

    /*
     * Seeks to an absolute position in the stream. If this cannot be done, returns false.
     * If an attempt is made to seek past the end of the stream, the position will be set
     * to the end of the stream.
     */
    virtual bool seek(size_t /*position*/) = 0;

    /** Returns true if this stream can report its total length. */
    virtual bool hasLength() const = 0;

    /** Returns the total length of the stream. If this cannot be done, returns 0. */
    virtual size_t getLength() const = 0;

private:
    HeifStream(const HeifStream&) = delete;
    HeifStream& operator=(const HeifStream&) = delete;
};

/*
 * Abstract interface to decode heif images from a HeifStream data source.
 */
struct HeifDecoder {
    HeifDecoder() {}

    virtual ~HeifDecoder() {}

    /*
     * Returns true if it successfully sets outColor to the encoded color,
     * and false otherwise.
     */
    virtual bool getEncodedColor(HeifEncodedColor* outColor) const = 0;

    /*
     * Returns true if it successfully sets the output color format to color,
     * and false otherwise.
     */
    virtual bool setOutputColor(HeifColorFormat color) = 0;

    /*
     * Returns true if it successfully initialize heif decoder with source,
     * and false otherwise. |frameInfo| will be filled with information of
     * the primary picture upon success and unmodified upon failure.
     * Takes ownership of |stream| regardless of result.
     */
    virtual bool init(HeifStream* stream, HeifFrameInfo* frameInfo) = 0;

    /*
     * Returns true if the stream contains an image sequence and false otherwise.
     * |frameInfo| will be filled with information of pictures in the sequence
     * and |frameCount| the length of the sequence upon success and unmodified
     * upon failure.
     */
    virtual bool getSequenceInfo(HeifFrameInfo* frameInfo, size_t *frameCount) = 0;

    /*
     * Decode the picture internally, returning whether it succeeded. |frameInfo|
     * will be filled with information of the primary picture upon success and
     * unmodified upon failure.
     *
     * After this succeeded, getScanline can be called to read the scanlines
     * that were decoded.
     */
    virtual bool decode(HeifFrameInfo* frameInfo) = 0;

    /*
     * Decode the picture from the image sequence at index |frameIndex|.
     * |frameInfo| will be filled with information of the decoded picture upon
     * success and unmodified upon failure.
     *
     * |frameIndex| is the 0-based index of the video frame to retrieve. The frame
     * index must be that of a valid frame. The total number of frames available for
     * retrieval was reported via getSequenceInfo().
     *
     * After this succeeded, getScanline can be called to read the scanlines
     * that were decoded.
     */
    virtual bool decodeSequence(int frameIndex, HeifFrameInfo* frameInfo) = 0;

    /*
     * Read the next scanline (in top-down order), returns true upon success
     * and false otherwise.
     */
    virtual bool getScanline(uint8_t* dst) = 0;

    /*
     * Skip the next |count| scanlines, returns true upon success and
     * false otherwise.
     */
    virtual size_t skipScanlines(size_t count) = 0;

private:
    HeifDecoder(const HeifFrameInfo&) = delete;
    HeifDecoder& operator=(const HeifFrameInfo&) = delete;
};

/*
 * Creates a HeifDecoder. Returns a HeifDecoder instance upon success, or NULL
 * if the creation has failed.
 */
HeifDecoder* createHeifDecoder();

#endif // _HEIF_DECODER_API_
