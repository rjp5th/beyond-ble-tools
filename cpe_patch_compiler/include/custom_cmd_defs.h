// SPDX-FileCopyrightText: 2024 Robert Pafford
// SPDX-License-Identifier: MIT

#pragma once

#include <stdint.h>

#define CMD7_MEM_READ 0x7001
#define CMD7_MEM_WRITE 0x7002
#define CMD7_MEM_ARRAY_READ 0x7003
#define CMD7_MEM_ARRAY_WRITE 0x7004
#define CMD7_ECHO_TEST 0x7401
#define CMD7_FORCE_CRASH 0x7402

struct cmd_mem_read_args {
    uint16_t commandNo;
    uint8_t width;
    uint8_t reserved0;
    uint32_t addr;
    uint32_t value_out;
};

struct cmd_mem_write_args {
    uint16_t commandNo;
    uint8_t width;
    uint8_t reserved0;
    uint32_t addr;
    uint32_t value;
};

struct cmd_mem_array_read_args {
    uint16_t commandNo;
    uint16_t length;
    uint32_t addr;
    uint8_t data_out[0];
};

struct cmd_mem_array_write_args {
    uint16_t commandNo;
    uint16_t length;
    uint32_t addr;
    uint8_t data[0];
};

struct cmd_echo_test {
    uint16_t commandNo;
    uint16_t arg;
};

union command_7_args {
    uint16_t cmd_num;
    struct cmd_mem_read_args mem_read;
    struct cmd_mem_write_args mem_write;
    struct cmd_mem_array_read_args mem_array_read;
    struct cmd_mem_array_write_args mem_array_write;
    struct cmd_echo_test echo_test;
};
