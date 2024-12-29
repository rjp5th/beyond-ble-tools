#Adds TopSM Modem Registers for Agama
#@author rjp5th
#@category TopSM
#@keybinding
#@menupath
#@toolbar
#@runtime Jython

# SPDX-FileCopyrightText: 2024 Robert Pafford
# SPDX-License-Identifier: MIT

regs = [
"MDMENABLE", "MDMINIT", "MDMPDREQ", "DEMENABLE0", "DEMENABLE1", "DEMINIT0", "DEMINIT1", "MCESTROBES0", "MCESTROBES1",
"MCEEVENT0", "MCEEVENT1", "MCEEVENT2", "MCEEVENT3", "MCEEVENTMSK0", "MCEEVENTMSK1", "MCEEVENTMSK2", "MCEEVENTMSK3",
"MCEEVENTCLR0", "MCEEVENTCLR1", "MCEEVENTCLR2", "MCEEVENTCLR3", "MCEPROGRAMSRC", "MDMAPI", "MDMCMDPAR0", "MDMCMDPAR1",
"MDMCMDPAR2", "MDMRFCHANNEL", "MDMSTATUS", "MDMFIFOWR", "MDMFIFORD", "MDMFIFOWRCTRL", "MDMFIFORDCTRL", "MDMFIFOCFG",
"MDMFIFOSTA", "CPEFWEVENT", "RFESEND", "RFERECV", "SMICONF", "SMIDLOUTG", "SMICLOUTG", "SMIDLINC", "SMICLINC", "SMISTA",
"ADCDIGCONF", "MODPRECTRL", "MODSYMMAP0", "MODSYMMAP1", "MODSOFTTX", "MDMBAUD", "MDMBAUDPRE", "MODMAIN", "DEMMISC0",
"DEMMISC1", "DEMMISC2", "DEMMISC3", "DEMIQMC0", "DEMDSBU", "DEMDSBU2", "DEMCODC0", "DEMFIDC0", "DEMFEXB0", "DEMDSXB0",
"DEMD2XB0", "DEMFIFE0", "DEMMAFI0", "DEMMAFI1", "DEMMAFI2", "DEMMAFI3", "DEMC1BE0", "DEMC1BE1", "DEMC1BE2", "DEMC1BE10",
"DEMC1BE11", "DEMC1BE12", "MDMSYNC0", "MDMSYNC1", "MDMSYNC2", "MDMSYNC3", "DEMSWQU0", "DEMFB2P0", "DEMFB2P1", "DEMPHAC0",
"DEMPHAC1", "DEMPHAC2", "DEMPHAC3", "DEMPHAC4", "DEMPHAC5", "DEMPHAC6", "DEMPHAC7", "DEMC1BEREF0", "DEMC1BEREF1",
"DEMC1BEREF2", "DEMC1BEREF3", "DEMC1BEREF4", "DEMC1BEREF5", "DEMC1BEREF6", "DEMC1BEREF7", "DEMMLSE4MAP", "DEMC1BE13",
"MODCTRL", "MODPREAMBLE", "DEMFRAC0", "DEMFRAC1", "DEMFRAC2", "DEMFRAC3", "DEMCODC1", "DEMCODC2", "DEMFIDC1", "DEMFIDC2",
"DEMFIFE1", "DEMTHRD0", "DEMTHRD1", "DEMMAFC0", "DEMMAFI4", "DEMSWIMBAL", "DEMSOFTPDIFF", "DEMDEBUG", "VITCTRL", "VITCOMPUTE",
"VITAPMRDBACK", "VITSTATE", "VITBRMETRIC10", "VITBRMETRIC32", "VITBRMETRIC54", "VITBRMETRIC76", "VITBRSEL0", "VITAPMSEL0",
"VITBRSEL1", "VITAPMSEL1", "VITBRSEL2", "VITAPMSEL2", "VITBRSEL3", "VITAPMSEL3", "VITBRSEL4", "VITAPMSEL4", "VITBRSEL5",
"VITAPMSEL5", "VITBRSEL6", "VITAPMSEL6", "VITBRSEL7", "VITAPMSEL7", "LOCMULTA", "LOCMULTB", "LOCMULTC0", "LOCMULTC1",
"TIMCTRL", "TIMINC", "TIMPERIOD", "TIMCOUNTER", "TIMCAPT", "TIMEBASE", "COUNT1IN", "COUNT1RES", "BRMACC0", "BRMACC1",
"BRMACC2", "VITACCCTRL", "VITACCRDBIT", "MCETRCSEND", "MCETRCBUSY", "MCETRCCMD", "MCETRCPAR0", "MCETRCPAR1", "RDCAPT0",
"DEMCODC3", "DEMCODC4", "DEMMGEX1", "DEMMGEX2", "DEMFIDC3", "DEMFIDC4", "DEMCA2P0", "DEMPDIF0", "DEMC1BE3", "DEMC1BE4",
"DEMC1BE5", "DEMFIFE2", "DEMDSBU0", "DEMDSBU1", "DEMSTIM0", "DEMSTIM1", "DEMSWQU1", "DEMLQIE0", "DEMSOFD0", "RDCAPT1",
"DEMTHRD4", "DEMMLSEBIT", "DEMMLSE4BITS", "DEMBDEC0", "DEMBDEC1", "DEMCHFI0", "DEMCHFI1", "DEMFRAC4", "DEMFRAC5",
"DEMPNSOFT", "DEMMAFI5", "DEMC1BE6", "DEMC1BE7", "DEMC1BE8", "DEMC1BE9", "DEMC1BEA", "MDMSPAR0", "MDMSPAR1", "MDMSPAR2",
"MDMSPAR3", "DEMSOFD1", "DEMSOFD2", "DEMSOFD3", "DEMSOFD4", "DEMC1BE14", "DEMC1BE15", "DEMC1BE16", "DEMC1BE17",
"DEMC1BE18", "DEMC1BE19", "DEMC1BE20", "DEMDSBU3", "MCEDUMP0", "MCEGPO0", "DEMPHAC8", "DEMPHAC9", "DEMFB2P2", "DEMHDIS0"
]

io_space = currentProgram.addressFactory.getAddressSpace("io")
for i, name in enumerate(regs):
	sym_addr = io_space.getAddress(i*2)
	clearListing(sym_addr)
	createSymbol(sym_addr, name, True)
	createWord(sym_addr)

