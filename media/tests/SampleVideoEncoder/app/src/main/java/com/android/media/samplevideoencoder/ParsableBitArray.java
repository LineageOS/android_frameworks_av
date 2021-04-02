/*
 * Copyright (C) 2016 The Android Open Source Project
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

package com.android.media.samplevideoencoder;

public class ParsableBitArray {
    public byte[] data;
    private int byteOffset;
    private int bitOffset;
    private int byteLimit;

    public ParsableBitArray(byte[] dataArray) {
        this(dataArray, dataArray.length);
    }

    public ParsableBitArray(byte[] dataArray, int limit) {
        this.data = dataArray;
        byteLimit = limit;
    }

    public void reset(byte[] data, int offset, int limit) {
        this.data = data;
        byteOffset = offset;
        bitOffset = 0;
        byteLimit = limit;
    }

    public void skipBit() {
        if (++bitOffset == 8) {
            bitOffset = 0;
            byteOffset++;
        }
    }

    public void skipBits(int numBits) {
        int numBytes = numBits / 8;
        byteOffset += numBytes;
        bitOffset += numBits - (numBytes * 8);
        if (bitOffset > 7) {
            byteOffset++;
            bitOffset -= 8;
        }
    }

    public boolean readBit() {
        boolean returnValue = (data[byteOffset] & (0x80 >> bitOffset)) != 0;
        skipBit();
        return returnValue;
    }

    public int readBits(int numBits) {
        if (numBits == 0) {
            return 0;
        }
        int returnValue = 0;
        bitOffset += numBits;
        while (bitOffset > 8) {
            bitOffset -= 8;
            returnValue |= (data[byteOffset++] & 0xFF) << bitOffset;
        }
        returnValue |= (data[byteOffset] & 0xFF) >> (8 - bitOffset);
        returnValue &= 0xFFFFFFFF >>> (32 - numBits);
        if (bitOffset == 8) {
            bitOffset = 0;
            byteOffset++;
        }
        return returnValue;
    }

    public boolean canReadUEV() {
        int initialByteOffset = byteOffset;
        int initialBitOffset = bitOffset;
        int leadingZeros = 0;
        while (byteOffset < byteLimit && !readBit()) {
            leadingZeros++;
        }
        boolean hitLimit = byteOffset == byteLimit;
        byteOffset = initialByteOffset;
        bitOffset = initialBitOffset;
        return !hitLimit && canReadBits(leadingZeros * 2 + 1);
    }

    public int readUEV() {
        int leadingZeros = 0;
        while (!readBit()) {
            leadingZeros++;
        }
        return (1 << leadingZeros) - 1 + (leadingZeros > 0 ? readBits(leadingZeros) : 0);
    }

    public boolean canReadBits(int numBits) {
        int oldByteOffset = byteOffset;
        int numBytes = numBits / 8;
        int newByteOffset = byteOffset + numBytes;
        int newBitOffset = bitOffset + numBits - (numBytes * 8);
        if (newBitOffset > 7) {
            newByteOffset++;
            newBitOffset -= 8;
        }
        for (int i = oldByteOffset + 1; i <= newByteOffset && newByteOffset < byteLimit; i++) {
            if (shouldSkipByte(i)) {
                // Skip the byte and check three bytes ahead.
                newByteOffset++;
                i += 2;
            }
        }
        return newByteOffset < byteLimit || (newByteOffset == byteLimit && newBitOffset == 0);
    }

    private boolean shouldSkipByte(int offset) {
        return (2 <= offset && offset < byteLimit && data[offset] == (byte) 0x03 &&
                data[offset - 2] == (byte) 0x00 && data[offset - 1] == (byte) 0x00);
    }

}
