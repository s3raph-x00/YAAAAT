# This Project Is Still In Early Alpha #

## Yet Another Android Analysis Tool (YAAAT) ###

##### Because it is still in pre-alpha, there are alot of bugs. Please let me know if you run into any issues and I'll try my best to knock them out. #####

### Background: 

    ######################################################################
    ### The name and the methodology stems from a need to be able to   ###
    ### conduct larger scale Android forensics. This does not replace  ###
    ### industry tools such as Cellebrite, etc but rather augments     ###
    ### the analysis and data already collected.                       ###
    ######################################################################

### DESCRIPTION:

    ######################################################################
    ### SYNOPSIS:    Collection Starts Either Automated (In Autopsy)   ###
    ###              or manually (via CLI). Each script has it's own   ###
    ###              -h switch depending on what you want to do.       ###
    ######################################################################

The core functionality of the tool requires the associated binaries to be in the ./ directory. Plan accordingly prior to running. 
- Test software and script prior to using in a live enviorment

### REQUIREMENTS: <br />
Note: Store Binaries (And Their Associated DLLs/Files) In The Following Folder Structure:<br/>
<blockquote>
#   ./YAAAAT*.py<br/>
#      ./win/<br/>
#         ./strings.exe
#         ./openssl.exe (and associated dlls)
#         ./lib/(jadx classes)<br/>
#         ./bin/jadx.bat<br/>
#         ./bin/jadx<br/>
</blockquote>
    
### Current Development Status 
  1. Autopsy Plugin
     - [X] Core Functionality <br />
       [ ] Additional Indicing of Ripped Data   <br/>
       [ ] Switches and Parametization<br/>
       &#9746; Testing<br/>
     - [ ] GUI   
  2. Python Ripper
     - [ ] Decompile and Analysis Functionaliy
       - &#9746; APK decompilation and analysis<br/>   
       - [ ] OAT decompilation and analysis<br/>
       - [ ] JAR decompilation and analysis<br/>
       - [ ] DEX decompilation and analysis<br/>
       - [ ] CLASS decompilation and analysis<br/>
       - [ ] XAPK decompilation and analysis<br/>
       - [ ] vDEX/cDEX decompilation and analysis<br/>
       - [ ] SO decompilation and analysis<br/>
       - [ ] Testing 
     - [ ] GUI   
  3. Linux/Unix Python Script
     - [ ] Core Functionality
       - [ ] Additional Triage Sources   
       - [ ] Switches and Parametization
       - [ ] Testing
     - [ ] GUI   
  4. ELK/Splunk Linkage Tool
     - [ ] Core Functionality
     - [ ] ELK Linkage
     - [ ] SPLUNK Linkage
     - [ ] Testing
     - [ ] GUI

##### Legend:
- - [X] - Completed <br />
&#9746; - Partially Completed
- - [ ] - Not Started

##### Known Issues:
  1. Everything

### Updating The Core Binaries

When updating various binaries, ensure the name matches what is currently in the directory and copy over any associated files. 

### Where To Get The Core Binaries: <br />
winpmem: https://github.com/Velocidex/WinPmem <br />
memoryze: https://www.fireeye.com/services/freeware/memoryze.html <br />
ramcapture: https://belkasoft.com/ram-capturer <br />
Surge Collect Pro (Not Free): https://www.volexity.com/products-overview/surge/ <br />
FTK Imager (CLI): https://accessdata.com/product-download/ftk-imager-version-4-5 <br />
RedLine Collector: https://www.fireeye.com/services/freeware/redline.html <br />
SpadowSpawn (Still Testing): https://github.com/candera/shadowspawn <br />
