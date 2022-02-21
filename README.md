![logo](/images/powershell-emblem.jpg)

# PowerShell-BlueTeam
This is just a collection of powershell functions that I will be turning into an Incident Response Module.
Some of them I wrote myself, some I took snippets of from other functions, and some are still in the testing and development stage. 

The goal after all functions are created is to cover some digital forensics, some threat hunting, and some basic malware analysis. These techniques can be mapped back to the Mitre Attack Matrix for TTP chaining and to possibly help with attribution.

## Importing
Import the data file:
```
Import-Module PowerShellBlueTeam.psd1
```

## Syntax Examples
Alternate Data Streams:
```
Read-AltDataStreams -DirectoryPath C:\Temp -Recurse
```
Local Memory Dumps:
```
Get-LocalMemDump -DestPath C:\Users\admin\Documents\notepad.dmp
```
Finding Obfuscated File Extensions:
```
Find-HiddenExes -DirPath C:\Windows -Recurse
```
