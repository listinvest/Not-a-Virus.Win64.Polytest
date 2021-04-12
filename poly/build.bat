del poly.obj
uasm64.exe -q -win64 poly.asm
link.exe^
    /ERRORREPORT:PROMPT^
    /INCREMENTAL:NO^
    /DEBUG^
    /SUBSYSTEM:CONSOLE^
    /NODEFAULTLIB^
    /OPT:NOREF^
    /OPT:NOICF^
    /ENTRY:"Main"^
    /DYNAMICBASE^
    /NXCOMPAT^
    /MACHINE:X64^
    /SAFESEH:NO^
    /LARGEADDRESSAWARE:NO^
    poly.obj
