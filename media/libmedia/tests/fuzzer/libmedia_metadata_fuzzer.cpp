//This program fuzzes Metadata.cpp

#include <stddef.h>
#include <stdint.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/Metadata.h>
#include <binder/Parcel.h>

using namespace android;
using namespace media;

static const float want_prob = 0.5;

bool bytesRemain(FuzzedDataProvider *fdp);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    Parcel p;
    Metadata md = Metadata(&p);

    md.appendHeader();
    while (bytesRemain(&fdp)) {

        float got_prob = fdp.ConsumeProbability<float>();
        if (!bytesRemain(&fdp)) {
            break;
        }

        if (got_prob < want_prob) {
            int32_t key_bool = fdp.ConsumeIntegral<int32_t>();
            if (!bytesRemain(&fdp)) {
                break;
            }
            bool val_bool = fdp.ConsumeBool();
            md.appendBool(key_bool, val_bool);
        } else {
            int32_t key_int32 = fdp.ConsumeIntegral<int32_t>();
            if (!bytesRemain(&fdp)) {
                break;
            }
            bool val_int32 = fdp.ConsumeIntegral<int32_t>();
            md.appendInt32(key_int32, val_int32);
        }
        md.updateLength();
    }
    md.resetParcel();
    return 0;
}

bool bytesRemain(FuzzedDataProvider *fdp){
    return fdp -> remaining_bytes() > 0;
}