// (c) Copyright 2020-2022 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// AUTO-generated.
//
//   built: 2023-02-03
// version: 5.1.0
//
#include <stdint.h>

// this overrides ports/stm32/fatfs_port.c
uint32_t get_fattime(void) {
    return 0x56432820UL;
}
