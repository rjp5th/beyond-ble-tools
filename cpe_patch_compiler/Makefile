SIMPLELINK_SDK_PATH := $(HOME)/ti/simplelink_cc13xx_cc26xx_sdk_7_41_00_17

# Compiler
CC=arm-none-eabi-gcc

# Output Name
OUT_NAME	:= cpe_patch

# Paths
SRCDIR		:= src
INCDIR		:= include
BUILDDIR	:= build
LDSCRIPT	:= patch.ld
SRCEXT      := c
DEPEXT      := d
OBJEXT      := o

# Compiler Options
SIMPLELINK_INC_PATH := $(SIMPLELINK_SDK_PATH)/source/ti/devices/cc13x2_cc26x2/inc
INC			:= -I$(INCDIR) -isystem $(SIMPLELINK_INC_PATH)
CFLAGS		:= -Wall -Wextra -std=c11 -mcpu=cortex-m0 -march=armv6s-m -mthumb -Os -nostartfiles -nodefaultlibs -nostdlib -ffreestanding -fdata-sections -ffunction-sections
LDFLAGS		:= -nostartfiles -Wl,--gc-sections,-zmax-page-size=4096


# ========================================
# DO NOT EDIT BELOW THIS LINE!
# ========================================

SOURCES 	:= $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS		:= $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.$(OBJEXT)))
DEPENDS 	:= $(OBJECTS:.$(OBJEXT)=.$(DEPEXT))


# We want to make the python file by default
all: $(OUT_NAME).h

# Include dependencies so c files refresh when headers are changed
-include $(DEPENDS)

# Compile Object Files

$(BUILDDIR)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	@if ! [ -d "$(SIMPLELINK_INC_PATH)" ]; then echo "Could not find SDK in $(SIMPLELINK_INC_PATH) be sure to set SIMPLELINK_SDK_PATH"; exit 1; fi
	$(CC) $(CFLAGS) $(INC) -MMD -MP -MF $(BUILDDIR)/$*.$(DEPEXT) -MT '$@' -c $< -o $@

# Create final targets

$(BUILDDIR)/$(OUT_NAME).elf: $(OBJECTS) $(LDSCRIPT)
	$(CC) $(LDFLAGS) $(OBJECTS) -T $(LDSCRIPT) -o $@

$(OUT_NAME).h: $(BUILDDIR)/$(OUT_NAME).elf
	python3 patch_gen.py $< $@

# Clean Target
.PHONY: clean
clean:
	@rm -rf $(BUILDDIR) $(OUT_NAME).h
