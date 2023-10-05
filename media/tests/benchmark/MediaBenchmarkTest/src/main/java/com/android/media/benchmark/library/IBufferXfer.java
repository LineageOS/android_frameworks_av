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
import android.media.MediaCodec;
import java.nio.ByteBuffer;
/**
 * interfaces that can be used to implement
 * sending of buffers to external and receive using callbacks
 */
public class IBufferXfer {
  static class BufferXferInfo {
      public ByteBuffer buf;
      public int idx;
      public Object obj;
      int flag;
      int bytesRead;
      long presentationTimeUs;
  }

  public interface IReceiveBuffer {
      // Implemented by sender to get buffers back
      boolean receiveBuffer(BufferXferInfo info);
      // Establishes a connection between the buffer sender and receiver.
      // Implemented by the entity that sends the buffers to receiver.
      // the receiverInterface is the interface of the receiver.
      // The sender uses this interface to send buffers.
      boolean connect(IBufferXfer.ISendBuffer receiverInterface);
  }
  // Implemented by an entity that does not own the buffers and only
  // wants to manage the buffers. ( Usually the receiver)
  // The receiver uses returnIface to return the buffers to sender
  public interface ISendBuffer {
      boolean sendBuffer(IBufferXfer.IReceiveBuffer returnIface,
                              BufferXferInfo info);
  }
}
