// SPDX-FileCopyrightText: 2024 Robert Pafford
// SPDX-License-Identifier: MIT

#ifndef CPE_PATCH_H_
#define CPE_PATCH_H_

// ========================================
// Useful Types
// ========================================

#define CONCAT(x, y) __CONCATX(x, y)
#define __CONCATX(x, y) x ## y

#define XSTR(x) STR(x)
#define STR(x) #x

typedef unsigned int uint;


// ========================================
// Patch Vector Definitions
// ========================================

#define PATCH_IDX_CMD7 169

#define PATCH_TAB_DEF(index, func_name) __attribute__((__section__(".vectable_ptrs." XSTR(index)))) \
    void* CONCAT(vectable_patch__idx, index) = &(func_name);

#define PATCH_IRQ_DEF(index, func_name) __attribute__((__section__(".irqpatch_ptrs." XSTR(index) ",\"\"//"))) \
    void* CONCAT(irq_patch__idx, index) = &(func_name);

// ========================================
// Define Function Pointers in CPE ROM
// ========================================

#define ROM_FUNC_DEF(return_type, name, params, addr) \
    static return_type (*const name)params = (void*)((addr) | 1);

ROM_FUNC_DEF(uint, enablePwr, (uint flags), 0x00004834);
ROM_FUNC_DEF(uint, disablePwr, (uint flags), 0x00004850);
ROM_FUNC_DEF(void*, romMemcpy, (void* dest, const void* src, uint n), 0x000002f8);

#endif
