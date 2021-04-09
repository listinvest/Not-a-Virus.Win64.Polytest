del vir.obj
uasm64.exe -q -win64 vir.asm
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
    vir.obj
