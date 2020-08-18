// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#ifndef __PLATFORM__
#define __PLATFORM__

#if defined(TARGET_TOFINO_CHIP_32D)
#define _NUM_HW_PIPES 2
#define _TOFINO_CHIP_NAME "TOFINO_32D"
#define _CPU_PORT_PCIE 192
#define _LAST_PORT 255

#elif defined(TARGET_TOFINO_CHIP_64D)
#define _NUM_HW_PIPES 4
#define _TOFINO_CHIP_NAME "TOFINO_64D"
#define _CPU_PORT_PCIE 320
#define _LAST_PORT 511

#else
#error "Must define a TARGET_TOFINO_CHIP_X"
#endif

// This is the platform annotation to be placed on the main Switch().
#define PLATFORM_ANNOTATION \
    @chip(_TOFINO_CHIP_NAME) \
    @num_hw_pipes(_NUM_HW_PIPES) \
    @cpu_port_pcie(_CPU_PORT_PCIE) \
    @last_port(_LAST_PORT)

// Export information with proper types.
const bit<9> CPU_PORT_PCIE = _CPU_PORT_PCIE;

#endif // __PLATFORM__
