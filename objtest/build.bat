del objtest.obj
uasm64.exe -q -win64 objtest.asm
link.exe /DEBUG /SUBSYSTEM:CONSOLE /NODEFAULTLIB /ENTRY:"Main" /MACHINE:x64 /SAFESEH:NO .\objtest.obj