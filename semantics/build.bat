del semantics.obj
uasm64.exe -q -win64 semantics.asm
link.exe /DEBUG /SUBSYSTEM:CONSOLE /NODEFAULTLIB /ENTRY:"Main" /MACHINE:x64 /SAFESEH:NO .\semantics.obj