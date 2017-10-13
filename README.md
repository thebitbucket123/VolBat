# VolBat
A simple batch script that automates executing Volatility commands on a memory image. 

Typing out each and every command for volatility can be tiresome. I've been in environments where I've been handed multiple memory images to analyze per day. Scripting it out to save myself time seemed like the logical thing to do. I grouped certain commands together so that I could specify what I wanted to run rather than just executing everything each time. The groups are listed in the usage message below.

Has been tested and used with Volatility 2.1-2.5. 

Example invocation:

volbat.bat WinXPSP3x86 C:\Users\username\evidence\image.dump .\out quick


Usage message:  
volbat.bat profileString imageFilePath output_dir [groupName]  
 profileString: Ex: WinXPSP3x86, Win7SP0x64  
       - Can be found using volatility's imageinfo plugin  
 imageFilePath: Absolute path to memory image  
 output_dir: All output from commands will be dumped into this directory (can be relative or absolute)  
 groupName (optional): specifying any combination of these command groups will execute all commands in the specified groups  
       quick - Runs a select number of useful commands, intended to complete quickly.  
       trio - Runs malware, process and network groups  
       malware - malfind, svcscan, ldrmodules, idt, gdt, threads, callbacks,  
                 driverirp, devicetree, psxview, timers REM impscan  
       process - privs, pslist, psscan, pstree, dlllist, handles, getsids, envars, cmdscan,  
                 consoles, memmap, vadinfo, vadtree, vadwalk  
       network - connections, connscan, sockets, sockscan  
       kernel - driverscan, filescan, modscan, modules, mutantscan, ssdt, symlinkscan,  
                thrdscan, unloadedmodules  
       misc - bioskbd, clipboard, eventhooks, getservicesids, hivelist, iehistory, mbrparser,  
              messagehooks, sessions, shimcache, userassist, windows, wintree, yarascan  
       dumps - vaddump, procexedump, procmemdump, moddump, memdump, lsadump, hivedump, hashdump,  
               dumpcerts, dumpfiles, dlldump  
        --- If no group is specified, all groups will be executed  
