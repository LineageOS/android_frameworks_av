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

package com.android.media.benchmark.library;

/**
 * Class that manages the buffer senders
*/
import com.android.media.benchmark.library.IBufferXfer;
import java.util.ArrayDeque;
import android.util.Log;
public class IBufferXferImpl implements IBufferXfer.ISendBuffer {

  private static class BufferInfo {
      public IBufferXfer.IReceiveBuffer rIface;
      public IBufferXfer.BufferXferInfo info;
  }
  private final String TAG = "IBufferXferImpl";
  private final ArrayDeque<BufferInfo> mProducerQueue = new ArrayDeque<>();
  private final ArrayDeque<BufferInfo> mConsumerQueue = new ArrayDeque<>();
  private IBufferXfer.IReceiveBuffer mProducer = null;
  private IBufferXfer.IReceiveBuffer mConsumer = null;
  private final Object mLock = new Object();

  public IBufferXferImpl(IBufferXfer.IReceiveBuffer producer,
      IBufferXfer.IReceiveBuffer consumer) {
      mProducer = producer;
      mConsumer = consumer;
      // Attach this to be their receiver
      mProducer.connect(this);
      mConsumer.connect(this);
  }
  @Override
  public boolean sendBuffer(IBufferXfer.IReceiveBuffer rIface,
                     IBufferXfer.BufferXferInfo bufferInfo) {
      if (rIface != mProducer && rIface != mConsumer) {
         Log.e(TAG, "Interfaces does not match");
        return false;
      }
      boolean status = true;
      BufferInfo pBuf = null, cBuf = null;
      synchronized(mLock) {
          // see which interface this buffer belongs to
          // producer has a filled buffer and the consumer
          // buffer needs to be filled.
          if ( rIface == mProducer ) {
              if (mConsumerQueue.size() > 0) {
                  cBuf = mConsumerQueue.remove();
                  pBuf = new BufferInfo();
                  pBuf.rIface = rIface;
                  pBuf.info = bufferInfo;
              } else {
                  BufferInfo info = new BufferInfo();
                  info.rIface = rIface;
                  info.info = bufferInfo;
                  mProducerQueue.add(info);
              }
          } else if(rIface == mConsumer) {
              if (mProducerQueue.size() > 0) {
                  pBuf = mProducerQueue.remove();
                  cBuf = new BufferInfo();
                  cBuf.rIface = rIface;
                  cBuf.info = bufferInfo;
              } else {
                  BufferInfo info = new BufferInfo();
                  info.rIface = rIface;
                  info.info = bufferInfo;
                  mConsumerQueue.add(info);
              }
          } else {
              status = false;
          }
      }

      if ( pBuf != null && cBuf != null) {
          int bytesRead = 0;
          if (cBuf.info.buf != null && pBuf.info.buf != null) {
              if (cBuf.info.buf.remaining() >= pBuf.info.buf.remaining()) {
                  bytesRead = pBuf.info.buf.remaining();
                  cBuf.info.buf.put(pBuf.info.buf);
              } else {
                  Log.e(TAG, "Something is wrong with the sizes P:" +
                      pBuf.info.buf.remaining() +" C:" + cBuf.info.buf.remaining());
              }
          }
          cBuf.info.bytesRead = bytesRead;
          cBuf.info.presentationTimeUs = pBuf.info.presentationTimeUs;
          cBuf.info.flag = pBuf.info.flag;

          if (pBuf.rIface != null) {
              pBuf.rIface.receiveBuffer(pBuf.info);
          }
          if (cBuf.rIface != null) {
              cBuf.rIface.receiveBuffer(cBuf.info);
          }
      }
      return status;
  }
  public boolean resetAll() {
      synchronized(mLock) {
          while (mProducerQueue.size() > 0) {
              BufferInfo info = mProducerQueue.remove();
              info.rIface.receiveBuffer(info.info);
          }
          while (mConsumerQueue.size() > 0) {
              BufferInfo info = mConsumerQueue.remove();
              info.rIface.receiveBuffer(info.info);
          }
          mProducer = null;
          mConsumer = null;
      }
  return true;
  }
}
