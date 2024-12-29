/**
 * @brief Patch for handling RFC Command Type 7 (0x7XXX)
 *
 * SPDX-FileCopyrightText: 2024 Robert Pafford
 * SPDX-License-Identifier: MIT
 */

#include "custom_cmd_defs.h"
#include "cpe_patch.h"

#include <hw_memmap.h>
#include <hw_prcm.h>
#include <hw_types.h>

#include <stdint.h>

#define CMDSTA_Done 0x01
#define CMDSTA_IllegalPointer 0x81
#define CMDSTA_UnknownCommand 0x82
#define CMDSTA_ParError 0x87

static uint handle_mem_read_cmd(struct cmd_mem_read_args* args) {
    uint restore;

    switch (args->width) {
    case 8:
        restore = enablePwr(0xFFFF);
        args->value_out = *(volatile uint8_t*)args->addr;
        disablePwr(restore);

        return CMDSTA_Done;
    case 16:
        if ((args->addr & 1) != 0)
            return CMDSTA_IllegalPointer;

        restore = enablePwr(0xFFFF);
        args->value_out = *(volatile uint16_t*)args->addr;
        disablePwr(restore);

        return CMDSTA_Done;
    case 32:
        if ((args->addr & 0b11) != 0)
            return CMDSTA_IllegalPointer;

        restore = enablePwr(0xFFFF);
        args->value_out = *(volatile uint32_t*)args->addr;
        disablePwr(restore);

        return CMDSTA_Done;
    default:
        return CMDSTA_ParError;
    }
}

static uint handle_mem_write_cmd(struct cmd_mem_write_args* args) {
    uint restore;

    switch (args->width) {
    case 8:
        restore = enablePwr(0xFFFF);
        *(volatile uint8_t*)args->addr = args->value;
        disablePwr(restore);

        return CMDSTA_Done;
    case 16:
        if ((args->addr & 1) != 0)
            return CMDSTA_IllegalPointer;

        restore = enablePwr(0xFFFF);
        *(volatile uint16_t*)args->addr = args->value;
        disablePwr(restore);

        return CMDSTA_Done;
    case 32:
        if ((args->addr & 0b11) != 0)
            return CMDSTA_IllegalPointer;

        restore = enablePwr(0xFFFF);
        *(volatile uint32_t*)args->addr = args->value;
        disablePwr(restore);

        return CMDSTA_Done;
    default:
        return CMDSTA_ParError;
    }
}

static uint handle_mem_array_read_cmd(struct cmd_mem_array_read_args* args) {
    if (args->length == 0)
        return CMDSTA_ParError;

    uint restore = enablePwr(0xFFFF);
    romMemcpy(args->data_out, (void*) args->addr, args->length);
    disablePwr(restore);

    return CMDSTA_Done;
}

static uint handle_mem_array_write_cmd(struct cmd_mem_array_write_args* args) {
    if (args->length == 0)
        return CMDSTA_ParError;

    uint old = enablePwr(0xFFFF);
    romMemcpy((void*) args->addr, args->data, args->length);
    disablePwr(old);

    return CMDSTA_Done;
}

uint custom_cmd7_handler(union command_7_args* args) {
    switch (args->cmd_num) {
    case CMD7_MEM_READ:
        return handle_mem_read_cmd(&args->mem_read);
    case CMD7_MEM_WRITE:
        return handle_mem_write_cmd(&args->mem_write);
    case CMD7_MEM_ARRAY_READ:
        return handle_mem_array_read_cmd(&args->mem_array_read);
    case CMD7_MEM_ARRAY_WRITE:
        return handle_mem_array_write_cmd(&args->mem_array_write);
    case CMD7_ECHO_TEST:
        return ((args->echo_test.arg & 0xFFFF) << 8) | CMDSTA_Done;
    case CMD7_FORCE_CRASH:
        // Force crash
        return *(uint32_t*)0xFFFFFFFF;
    default:
        return CMDSTA_UnknownCommand;
    }
}

PATCH_TAB_DEF(PATCH_IDX_CMD7, custom_cmd7_handler);

// void custom_irq_handler(void) {
//     HWREG(PRCM_BASE + PRCM_O_RFCBITS) = 0;
// }

// void second_custom_irq_handler(void) {}

// PATCH_IRQ_DEF(0, custom_irq_handler);
// PATCH_IRQ_DEF(4, second_custom_irq_handler);
