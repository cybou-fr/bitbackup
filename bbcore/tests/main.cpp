#include "Testing.h"

#include "bbcore/bbcore.h"

#include <cstdio>

int main()
{
    if (bb_init() != BB_OK) {
        std::printf("bb_init failed\n");
        return 2;
    }

    std::printf("%s\n\n", bb_version());
    return bb::test::RunAll();
}
