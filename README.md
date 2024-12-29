# Tools for working with CC13XX and CC26XX RF Core

Demonstrated at our 38C3 talk [Beyond BLE](https://events.ccc.de/congress/2024/hub/en/event/beyond-ble-cracking-open-the-black-box-of-rf-microcontrollers/).

This repository contains the following tools:
* A Ghidra Plugin for disassembling TopSM binaries
* An assembler for generating TopSM patches
* A simple build environment to generate CPE patches.

## Generating a CPE Patch

1. Ensure the SimpleLink SDK and the arm-none-eabi-gcc compiler is installed on your machine
2. Set the `SIMPLELINK_SDK_PATH` environment variable to your install directory of the CC13XX_CC16XX sdk
3. Run `make` in the `cpe_patch_compiler` directory
4. Use the header file as part of your CCS project

## Generating an MCE patch

1. Create your TopSM assembly file. For example: `rf_patch_mce_testrom.asm`
2. Call the assembler with `topsm_assembler.py rf_patch_mce_testrom.asm rf_patch_mce_testrom.bin`
3. Convert the binary into an MCE patch with `topsm_create_patch.py rf_patch_mce_testrom.bin rf_patch_mce_testrom.h`
4. Use the generated C and header files as part of your CCS project
