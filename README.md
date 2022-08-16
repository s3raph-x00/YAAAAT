# This Project Is Still In Early Alpha #

## Yet Another Android Analysis Tool (YAAAAT) ###

##### Because it is still in pre-alpha, there are alot of bugs. Please let me know if you run into any issues and I'll try my best to knock them out. Additionally this project will later be nested under the Battlefield Triage Project. #####

##### At this time, Python 2.7 is the primary supported implementation. This is primarily because Autopsy is still using Python 2. Part of this project is having the script be version aware (you'll notice some functions are properly switched), but most of the functionality is broken in Python 3 and will be fixed in later versions. #####

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
#         ./win/strings.exe<br/>
#         ./win/openssl.exe (and associated dlls)<br/>
#         ./win/lib/(jadx classes)<br/>
#         ./win/bin/jadx.bat<br/>
#         ./win/bin/jadx.exe<br/>
#         ./win/bin/yarac64.exe<br/>
#         ./win/bin/yara64.exe<br/>
</blockquote>
    
### Current Development Status 
  1. Autopsy Plugin
     - [X] Core Functionality <br />
       [ ] Additional Indicing of Ripped Data   <br/>
       &#9746; Switches and Parametization<br/>
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
     - [ ] Decompile and Analysis Functionaliy
       - [ ] APK decompilation and analysis<br/>   
       - [ ] OAT decompilation and analysis<br/>
       - [ ] JAR decompilation and analysis<br/>
       - [ ] DEX decompilation and analysis<br/>
       - [ ] CLASS decompilation and analysis<br/>
       - [ ] XAPK decompilation and analysis<br/>
       - [ ] vDEX/oDEX decompilation and analysis<br/>
       - [ ] SO decompilation and analysis<br/>
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
strings: https://docs.microsoft.com/en-us/sysinternals/downloads/strings <br />
openssl: https://www.openssl.org/source/ <br />
jadx:    https://github.com/skylot/jadx/releases <br />
yara:    https://github.com/VirusTotal/yara/releases <br />
