#include <cstring>
#include "../include/cthash/cthash.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        uint8_t opt = Data[0];
        std::span sp = std::span(Data + 1, Size - 1);

        switch (opt) {
            case 0:
                cthash::sha224{}.update(sp).final();
                break;
            case 1:
                cthash::sha256{}.update(sp).final();
                break;
            case 2:
                cthash::sha384{}.update(sp).final();
                break;
            case 3:
                cthash::sha512{}.update(sp).final();
                break;
            case 4:
                cthash::sha3_224{}.update(sp).final();
                break;
            case 5:
                cthash::sha3_256{}.update(sp).final();
                break;
            case 6:
                cthash::sha3_384{}.update(sp).final();
                break;
            case 7:
                cthash::sha3_512{}.update(sp).final();
                break;
            case 8:
                cthash::shake128{}.update(sp).final<32>();
                break;
            case 9:
                cthash::shake256{}.update(sp).final<32>();
                break;
        }
    }

    return 0;
}