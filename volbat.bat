@ECHO OFF
setlocal enabledelayedexpansion

REM Mandatory args
if [%1]==[] goto usage REM check for empty profilestring
if [%2]==[] goto usage REM check for empty filepath
if [%3]==[] goto usage REM check for empty output_dir
REM optional arg(s)
if [%4]==[] goto default REM if no groupings specified, execute all

REM These variables are only set if anything is specified on "%4"
SET all=0
SET quickdone=1
SET maldone=1
SET procdone=1
SET netdone=1
SET kerndone=1
SET miscdone=1
SET dumpsdone=1


REM Take in all args, set vars based on which groups were specified, 0 = Run this group
FOR %%A in (%*) do (
	IF "%%A" == "trio" (
	(SET maldone=0)
	(SET procdone=0)
	(SET netdone=0)
	)
	IF "%%A" == "quick" SET quickdone=0
	IF "%%A" == "malware" SET maldone=0
	IF "%%A" == "process" SET procdone=0
	IF "%%A" == "network" SET netdone=0
	IF "%%A" == "kernel" SET kerndone=0
	IF "%%A" == "misc" SET miscdone=0
	IF "%%A" == "dumps" SET dumpsdone=0
)


:back
if [!quickdone!] equ [0] goto quick
if [!maldone!] equ [0] goto malware
if [!procdone!] equ [0] goto process
if [!netdone!] equ [0] goto network
if [!kerndone!] equ [0] goto kernel
if [!miscdone!] equ [0] goto misc
if [!dumpsdone!] equ [0] goto dumps
goto exit

:usage
ECHO USAGE: %0 profileString imageFilePath output_dir [groupName...]
ECHO         profileString: Ex: WinXPSP3x86, Win7SP0x64
ECHO               - Can be found using volatility's imageinfo plugin
ECHO         imageFilePath: Absolute path to memory image
ECHO         output_dir: All output from commands will be dumped into this directory (can be relative or absolute)
REM ECHO         -v (optional): utilize verbosity flag on any command where that is possible REM //////TO DO
ECHO         groupName (optional): specifying any combination of these command groups will execute all commands in the specified groups
ECHO               quick - Runs a select number of useful commands, intended to complete quickly.
ECHO               trio - Runs malware, process and network groups
ECHO               malware - malfind, svcscan, ldrmodules, idt, gdt, threads, callbacks, 
ECHO                         driverirp, devicetree, psxview, timers REM impscan
REM ECHO               malware_long - apihooks + malware group
ECHO               process - privs, pslist, psscan, pstree, dlllist, handles, getsids, envars, cmdscan,
ECHO                         consoles, memmap, vadinfo, vadtree, vadwalk
ECHO               network - connections, connscan, sockets, sockscan
ECHO               kernel - driverscan, filescan, modscan, modules, mutantscan, ssdt, symlinkscan, 
ECHO                        thrdscan, unloadedmodules
ECHO               misc - bioskbd, clipboard, eventhooks, getservicesids, hivelist, iehistory, mbrparser,
ECHO                      messagehooks, sessions, shimcache, userassist, windows, wintree, yarascan
ECHO               dumps - vaddump, procexedump, procmemdump, moddump, memdump, lsadump, hivedump, hashdump,
ECHO                       dumpcerts, dumpfiles, dlldump
ECHO                --- If no group is specified, all groups will be executed 
exit /B 1


REM - TO DO
REM vol.exe --profile=%1 -f%2 --output-file="%3\imageinfo.txt" imageinfo
REM We should run this first and feed the profile it spits out back in as a parameter
REM ***This might be better off staying as a given value rather than automated through imageinfo. 
REM ***   Imageinfo suggests multiple profiles after running.




:default
SET all=1

:quick
ECHO Executing Quick group...
ECHO Malfind...
vol.exe --profile=%1 -f%2 --output-file="%3\malfind.txt" malfind > NUL 2>&1
ECHO netscan...
vol.exe --profile=%1 -f%2 --output-file="%3\netscan.txt" netscan > NUL 2>&1
ECHO PsScan...
vol.exe --profile=%1 -f%2 --output-file="%3\psscan.txt" psscan > NUL 2>&1
ECHO SvcScan...
vol.exe --profile=%1 -f%2 --output-file="%3\svcscan.txt" svcscan > NUL 2>&1
ECHo DLLList...
vol.exe --profile=%1 -f%2 --output-file="%3\dlllist.txt" dlllist > NUL 2>&1
ECHO LdrModules...
vol.exe --profile=%1 -f%2 --output-file="%3\ldrmodules.txt" ldrmodules > NUL 2>&1
ECHO PsxView...
vol.exe --profile=%1 -f%2 --output-file="%3\psxview.txt" psxview > NUL 2>&1
ECHO PsList...
vol.exe --profile=%1 -f%2 --output-file="%3\pslist.txt" pslist > NUL 2>&1
ECHO PsTree...
vol.exe --profile=%1 -f%2 --output-file="%3\pstree.txt" pstree > NUL 2>&1
ECHO GetSids...
vol.exe --profile=%1 -f%2 --output-file="%3\getsids.txt" getsids > NUL 2>&1
ECHO cmdline...
vol.exe --profile=%1 -f%2 --output-file="%3\cmdline.txt" cmdline > NUL 2>&1
ECHO UnloadedModules...
vol.exe --profile=%1 -f%2 --output-file="%3\unloadedmodules.txt" unloadedmodules > NUL 2>&1
if [!all!] NEQ [1] (
	SET quickdone=1
	goto back
)


:malware
ECHO Executing Malware Group...
ECHO Malfind...
vol.exe --profile=%1 -f%2 --output-file="%3\malfind.txt" malfind > NUL 2>&1
ECHO SvcScan...
vol.exe --profile=%1 -f%2 --output-file="%3\svcscan.txt" svcscan > NUL 2>&1
ECHO LdrModules...
vol.exe --profile=%1 -f%2 --output-file="%3\ldrmodules.txt" ldrmodules > NUL 2>&1
REM ECHO Impscan... //requires other args
REM vol.exe --profile=%1 -f%2 --output-file="%3\impscan.txt" impscan > NUL 2>&1
ECHO IDT...
vol.exe --profile=%1 -f%2 --output-file="%3\idt.txt" idt > NUL 2>&1
ECHO GDT...
vol.exe --profile=%1 -f%2 --output-file="%3\gdt.txt" gdt > NUL 2>&1
ECHO Threads...
vol.exe --profile=%1 -f%2 --output-file="%3\threads.txt" threads > NUL 2>&1
ECHO Callbacks...
vol.exe --profile=%1 -f%2 --output-file="%3\callbacks.txt" callbacks > NUL 2>&1
ECHO DriverIRP...
vol.exe --profile=%1 -f%2 --output-file="%3\driverirp.txt" driverirp > NUL 2>&1
ECHO DeviceTree...
vol.exe --profile=%1 -f%2 --output-file="%3\devicetree.txt" devicetree > NUL 2>&1
ECHO PsxView...
vol.exe --profile=%1 -f%2 --output-file="%3\psxview.txt" psxview > NUL 2>&1
ECHO Timers... 
vol.exe --profile=%1 -f%2 --output-file="%3\timers.txt" timers > NUL 2>&1
if [!all!] NEQ [1] (
	SET maldone=1
	goto back
)



:process
ECHO Executing Process Group...
ECHO Privs...
vol.exe --profile=%1 -f%2 --output-file="%3\privs.txt" privs > NUL 2>&1
ECHO PsList...
vol.exe --profile=%1 -f%2 --output-file="%3\pslist.txt" pslist > NUL 2>&1
ECHO PsScan...
vol.exe --profile=%1 -f%2 --output-file="%3\psscan.txt" psscan > NUL 2>&1
ECHO PsTree...
vol.exe --profile=%1 -f%2 --output-file="%3\pstree.txt" pstree > NUL 2>&1
ECHo DLLList...
vol.exe --profile=%1 -f%2 --output-file="%3\dlllist.txt" dlllist > NUL 2>&1
ECHO Handles...
vol.exe --profile=%1 -f%2 --output-file="%3\handles.txt" handles > NUL 2>&1
ECHO GetSids...
vol.exe --profile=%1 -f%2 --output-file="%3\getsids.txt" getsids > NUL 2>&1
ECHO EnVars...
vol.exe --profile=%1 -f%2 --output-file="%3\envars.txt" envars > NUL 2>&1
ECHO CmdScan...
vol.exe --profile=%1 -f%2 --output-file="%3\cmdscan.txt" cmdscan > NUL 2>&1
ECHO Consoles...
vol.exe --profile=%1 -f%2 --output-file="%3\consoles.txt" consoles > NUL 2>&1
ECHO MemMap...
vol.exe --profile=%1 -f%2 --output-file="%3\memmap.txt" memmap > NUL 2>&1
ECHO VADInfo...
vol.exe --profile=%1 -f%2 --output-file="%3\vadinfo.txt" vadinfo > NUL 2>&1
ECHO VADTree...
vol.exe --profile=%1 -f%2 --output-file="%3\vadtree.txt" vadtree  > NUL 2>&1
ECHO VADWalk...
vol.exe --profile=%1 -f%2 --output-file="%3\vadwalk.txt" vadwalk > NUL 2>&1
if [!all!] NEQ [1] (
	SET procdone=1
	goto back
)

:network
ECHO Executing Network Group...
ECHO netscan (Supports Vista+)...
vol.exe --profile=%1 -f%2 --output-file="%3\netscan.txt" netscan > NUL 2>&1
ECHO Connections (Supports xp/2003 only)...
vol.exe --profile=%1 -f%2 --output-file="%3\connections.txt" connections > NUL 2>&1
ECHO ConnScan (Supports xp/2003 only)...
vol.exe --profile=%1 -f%2 --output-file="%3\connscan.txt" connscan > NUL 2>&1
ECHO Sockets (Supports xp/2003 only)...
vol.exe --profile=%1 -f%2 --output-file="%3\sockets.txt" sockets > NUL 2>&1
ECHO SockScan (Supports xp/2003 only)...
vol.exe --profile=%1 -f%2 --output-file="%3\sockscan.txt" sockscan > NUL 2>&1
if [!all!] NEQ [1] (
	SET netdone=1
	goto back
)

:kernel
ECHO Executing Kernel Group...
ECHO DriverScan...
vol.exe --profile=%1 -f%2 --output-file="%3\driverscan.txt" driverscan > NUL 2>&1
ECHO FileScan...
vol.exe --profile=%1 -f%2 --output-file="%3\filescan.txt" filescan > NUL 2>&1
ECHO ModScan...
vol.exe --profile=%1 -f%2 --output-file="%3\modscan.txt" modscan > NUL 2>&1
ECHO Modules...
vol.exe --profile=%1 -f%2 --output-file="%3\modules.txt" modules > NUL 2>&1
ECHO MutantScan...
vol.exe --profile=%1 -f%2 --output-file="%3\mutantscan.txt" mutantscan > NUL 2>&1
ECHO SSDT...
vol.exe --profile=%1 -f%2 --output-file="%3\ssdt.txt" ssdt > NUL 2>&1
ECHO SymLinkScan...
vol.exe --profile=%1 -f%2 --output-file="%3\symlinkscan.txt" symlinkscan > NUL 2>&1
ECHO ThrdScan...
vol.exe --profile=%1 -f%2 --output-file="%3\thrdscan.txt" thrdscan > NUL 2>&1
ECHO UnloadedModules...
vol.exe --profile=%1 -f%2 --output-file="%3\unloadedmodules.txt" unloadedmodules > NUL 2>&1
if [!all!] NEQ [1] (
	SET kerndone=1
	goto back
)

:misc
ECHO Executing Miscellaneous Group...
ECHO bioskbd...
vol.exe --profile=%1 -f%2 --output-file="%3\bioskbd.txt" bioskbd > NUL 2>&1
ECHO clipboard...
vol.exe --profile=%1 -f%2 --output-file="%3\clipboard.txt" clipboard > NUL 2>&1
ECHO eventhooks...
vol.exe --profile=%1 -f%2 --output-file="%3\eventhooks.txt" eventhooks > NUL 2>&1
ECHO getservicesids...
vol.exe --profile=%1 -f%2 --output-file="%3\getservicesids.txt" getservicesids > NUL 2>&1
ECHO hivelist...
vol.exe --profile=%1 -f%2 --output-file="%3\hivelist.txt" hivelist > NUL 2>&1
ECHO iehistory...
vol.exe --profile=%1 -f%2 --output-file="%3\iehistory.txt" iehistory > NUL 2>&1
ECHO mbrparser...
vol.exe --profile=%1 -f%2 --output-file="%3\mbrparser.txt" mbrparser > NUL 2>&1
ECHO messagehooks...
vol.exe --profile=%1 -f%2 --output-file="%3\messagehooks.txt" messagehooks > NUL 2>&1
ECHO sessions...
vol.exe --profile=%1 -f%2 --output-file="%3\sessions.txt" sessions > NUL 2>&1
ECHO shimcache...
vol.exe --profile=%1 -f%2 --output-file="%3\shimcache.txt" shimcache > NUL 2>&1
ECHO userassist...
vol.exe --profile=%1 -f%2 --output-file="%3\userassist.txt" userassist > NUL 2>&1
ECHO windows...
vol.exe --profile=%1 -f%2 --output-file="%3\windows.txt" windows > NUL 2>&1
ECHO wintree...
vol.exe --profile=%1 -f%2 --output-file="%3\wintree.txt" wintree > NUL 2>&1
ECHO yarascan...
vol.exe --profile=%1 -f%2 --output-file="%3\yarascan.txt" yarascan > NUL 2>&1
if [!all!] NEQ [1] (
	SET miscdone=1
	goto back
)

:dumps
ECHO Executing Dumps group...
ECHO vaddump...
mkdir "%3\vaddump"
vol.exe --profile=%1 -f%2 --dump-dir="%3\vaddump" vaddump > NUL 2>&1
ECHO procexedump...
mkdir "%3\procexedump"
vol.exe --profile=%1 -f%2 --dump-dir="%3\procexedump" procexedump > NUL 2>&1
ECHO procmemdump...
mkdir "%3\procmemdump"
vol.exe --profile=%1 -f%2 --dump-dir="%3\procmemdump" procmemdump > NUL 2>&1
ECHO moddump...
mkdir "%3\moddump"
vol.exe --profile=%1 -f%2 --dump-dir="%3\moddump" moddump > NUL 2>&1
ECHO memdump...
mkdir "%3\memdump"
vol.exe --profile=%1 -f%2 --dump-dir="%3\memdump" memdump > NUL 2>&1
ECHO lsadump...
mkdir "%3\lsadump"
vol.exe --profile=%1 -f%2 --dump-dir="%3\lsadump" lsadump > NUL 2>&1
ECHO hivedump...
mkdir "%3\hivedump"
vol.exe --profile=%1 -f%2 --dump-dir="%3\hivedump" hivedump > NUL 2>&1
ECHO hashdump...
mkdir "%3\hashdump"
vol.exe --profile=%1 -f%2 --dump-dir="%3\hashdump" hashdump > NUL 2>&1
ECHO dumpcerts...
mkdir "%3\dumpcerts"
vol.exe --profile=%1 -f%2 --dump-dir="%3\dumpcerts" dumpcerts > NUL 2>&1
ECHO dumpfiles...
mkdir "%3\dumpfiles"
vol.exe --profile=%1 -f%2 --dump-dir="%3\dumpfiles" dumpfiles > NUL 2>&1
ECHO dlldump...
mkdir "%3\dlldump"
vol.exe --profile=%1 -f%2 --dump-dir="%3\dlldump" dlldump > NUL 2>&1
if [!all!] NEQ [1] (
	SET dumpsdone=1
	goto back
)

:exit
endlocal disabledelayedexpansion
exit /B 0

REM mkdir %3\screenshot
REM vol.exe --profile=%1 -f%2 --dump-dir="%3\screenshot" screenshot

REM vol.exe --profile=%1 -f%2 --output-file="%3\wndscan.txt" wndscan
REM vol.exe --profile=%1 -f%2 --output-file="%3\vboxinfo.txt" vboxinfo
REM vol.exe --profile=%1 -f%2 --output-file="%3\vmwareinfo.txt" vmwareinfo
REM vol.exe --profile=%1 -f%2 --output-file="%3\volshell.txt" volshell
REM vol.exe --profile=%1 -f%2 --output-file="%3\userhandles.txt" userhandles
REM vol.exe --profile=%1 -f%2 --output-file="%3\timeliner.txt" timeliner
REM vol.exe --profile=%1 -f%2 --output-file="%3\strings.txt" strings
REM vol.exe --profile=%1 -f%2 --output-file="%3\shellbags.txt" shellbags
REM vol.exe --profile=%1 -f%2 --output-file="%3\raw2dmp.txt" raw2dmp
REM vol.exe --profile=%1 -f%2 --output-file="%3\patcher.txt" patcher
REM vol.exe --profile=%1 -f%2 --output-file="%3\printkey.txt" printkey
REM vol.exe --profile=%1 -f%2 --output-file="%3\mftparser.txt" mftparser
REM vol.exe --profile=%1 -f%2 --output-file="%3\machoinfo.txt" machoinfo
REM vol.exe --profile=%1 -f%2 --output-file="%3\kpcrscan.txt" kpcrscan
REM vol.exe --profile=%1 -f%2 --output-file="%3\imagecopy.txt" imagecopy
REM vol.exe --profile=%1 -f%2 --output-file="%3\hivescan.txt" hivescan
REM vol.exe --profile=%1 -f%2 --output-file="%3\hpakextract.txt" hpakextract
REM vol.exe --profile=%1 -f%2 --output-file="%3\hpakinfo.txt" hpakinfo
REM vol.exe --profile=%1 -f%2 --output-file="%3\hibinfo.txt" hibinfo
REM vol.exe --profile=%1 -f%2 --output-file="%3\gahti.txt" gahti
REM vol.exe --profile=%1 -f%2 --output-file="%3\gditimers.txt" gditimers
REM vol.exe --profile=%1 -f%2 --output-file="%3\evtlogs.txt" evtlogs

REM vol.exe --profile=%1 -f%2 --output-file="%3\crashinfo.txt" crashinfo
REM vol.exe --profile=%1 -f%2 --output-file="%3\deskscan.txt" deskscan
REM vol.exe --profile=%1 -f%2 --output-file="%3\atoms.txt" atoms
REM vol.exe --profile=%1 -f%2 --output-file="%3\atomscan.txt" atomscan