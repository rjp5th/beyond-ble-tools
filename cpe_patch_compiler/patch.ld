/* SPDX-FileCopyrightText: 2024 Robert Pafford
 * SPDX-License-Identifier: MIT
 */
ENTRY(entry)

MEMORY
{
    /* RFC ULLRAM appears to go from 0x21004000 -> 0x21006000 (Then mirrors again until 0x21008000) */
    PATCH_RAM(rwx) : ORIGIN = 0x2100404C, LENGTH = 8116
}

SECTIONS
{
    /* If no entry defined, set it to NULL */
    PROVIDE_HIDDEN(entry = 0);

    .vectable_ptrs : {
        KEEP(*(SORT(.vectable_ptrs.*)))
    } > PATCH_RAM

    .patch : {
    	. = ALIGN(4);

    	*(.text)
        *(.text.*)

    	. = ALIGN(4);
    	*(.rodata)
        *(.rodata.*)
    	*(.data)
        *(.data.*)

        /* We want BSS to also be stashed in data so the patch load will inherently zero it out */
        *(.bss)
        *(.bss.*)
        *(COMMON)

        . = ALIGN(4);
	} > PATCH_RAM

    .irqpatch_ptrs 0 : {
        KEEP(*(SORT(.irqpatch_ptrs.*)))
    }
}
