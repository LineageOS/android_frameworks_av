# libshmem

This library provides facilities for sharing memory across processes over (stable) AIDL. The main
feature is the definition of the `android.media.SharedMemory` AIDL type, which represents a block of
memory that can be shared between processes. In addition, a few utilities are provided to facilitate
the use of shared memory and to integrate with legacy code that uses older facilities.