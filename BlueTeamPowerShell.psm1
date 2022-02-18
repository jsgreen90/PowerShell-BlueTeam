Function Find-HiddenExes {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the FULL PATH of the directory you would like to analyze' )]$DirPath,
        [switch] $Recurse
    )
    
    #create whitelist
    $whitelist = '.exe', '.dll'
    #grab items in target directory
    $file_listing = Get-ChildItem -Path $DirPath -Recurse:$Recurse
    Write-Host("Number of Files/Folders:")$file_listing.count
    $suspect_files = @()
    for ($i=0;$i -lt $file_listing.count; $i++)
    {
        #for each item make sure its not a directory or whitelisted
        if ((Test-Path $file_listing[$i] -PathType Leaf) -and ($file_listing[$i].Extension -notin $whitelist))
        {
            $exebytes = '{0:X2}' -f (Get-Content $file_listing[$i] -Encoding Byte -ReadCount 4)
            if($exebytes -eq '4D 5A 90 00')
            {
                Write-Host("Found atypical file:")$file_listing[$i]
                $suspect_files += $file_listing[$i]
            }
        }
    }
    Write-Host("Number of suspicious files found:")$suspect_files.count
    Write-Host $suspect_files
}


Function Get-ParentChildProcess {

    $runningprocesses = Get-CimInstance -ClassName Win32_Process | 
    Select-Object CreationDate, ProcessName, ProcessId,CommandLine, ParentProcessId

    for($i=0;$i -le $runningprocesses.count; $i++)
    {
        $runningprocesses[$i]
    
        Write-Host("Process:")
        (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -EQ $runningprocesses[$i].OwningProcess).ProcessName
        Write-Host("CMDLine:")
        (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -EQ $runningprocesses[$i].OwningProcess).CommandLine
        Write-Host ("Parent:")
        (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -EQ $runningprocesses[$i].ParentProcessId).ProcessName
        Write-Host("Parent CMDLine:")
        (Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -EQ $runningprocesses[$i].ParentProcessId).CommandLine
        Write-Host("---------------------")
        }
}

Function Find-SusFilterDrivers {

    $FilterEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName="Microsoft-Windows-FilterManager"} | ForEach-Object {
        [PSCustomObject] @{
            TimeCreated = $_.TimeCreated
            MachineName = $_.MachineName
            UserId = $_.UserId
            FilterDriver = $_.Properties[4].Value
            Message = $_.Message
        }
    }
    echo "Scanning for suspicious filter drivers. Any found will be compared against existing services:"
    $SuspectDrivers = $($FilterEvents | where-object {$_.FilterDriver -ine "FileInfo" -AND $_.FilterDriver -ine "WdFilter" -AND $_.FilterDriver -ine "storqosflt" -AND $_.FilterDriver -ine "wcifs" -AND $_.FilterDriver -ine "CldFlt" -AND $_.FilterDriver -ine "FileCrypt" -AND $_.FilterDriver -ine "luafv" -AND $_.FilterDriver -ine "npsvctrig" -AND $_.FilterDriver -ine "Wof" -AND $_.FilterDriver -ine "FileInfo" -AND $_.FilterDriver -ine "bindflt" -AND $_.FilterDriver -ine "PROCMON24" -AND $_.FilterDriver -ine "FsDepends"} | select -exp FilterDriver)
    $SuspectDrivers
    foreach ($driver in $SuspectDrivers){
    echo "Checking services for relevant drivers. Any which aren't present may indicate a filter driver which has since been removed, or an active rootkit filtering service registry keys."
    gci REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\$driver
    }
}

Function Get-UserPSHistory {
    $users = Get-ChildItem C:\Users

    foreach($user in $users){
        if(Test-Path -Path  C:\Users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt){
            $psHistory = Get-Content C:\Users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
            $line = 0
            foreach($cmd in $psHistory){
                $result = @{}
                $result.add("CommandLine", $cmd)

                $prefix = $cmd.split()[0]
                $result.add("Prefix", $prefix)
                
                $result.add("User", $user.Name.toString()) 
                $result.add("Line", $line++)
                
                Add-Result -hashtbl $result
        }
    }
}
}

Function Find-UnsignedDLLs {
    (gps).Modules.FileName | get-authenticodesignature | ? Status -NE "Valid"
}



Function Get-LocalMemDump {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the FULL PATH of the destination for your dumpfile, including filename' )]$DestPath
    )

    $ss = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace Root\Microsoft\Windows\Storage
    Invoke-CimMethod -InputObject $ss -MethodName "GetDiagnosticInfo" -Arguments @{DestinationPath=$DestPath; IncludeLiveDump=$true}
}

Function Read-AltDataStreams {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the FULL PATH of the directory you would like to analyze' )]$DirectoryPath,
        [switch] $Recurse 
    )

    #Make sure directory exists
    if (!(Test-Path $DirectoryPath))
    {
        Write-Output "Cannot find target directory!"
        exit
    }

    $StreamFiles = Get-ChildItem $DirectoryPath -Recurse:$Recurse
    foreach ($File in $StreamFiles)
    {
        #Make sure the file is not a directory
        if (Test-Path $File.FullName -PathType Leaf) 
        {
        #Get the streams that are not the :$DATA stream which is present in every NTFS File
        $streams = Get-Item $File.FullName -Stream * | Where-Object Stream -ne ':$DATA'
        Write-Host "Alternate Streams for $File" -ForegroundColor Red
        $streams
        foreach ($stream in $streams)
        {
            #Get the content of the streams
            Write-Host "Stream Content:" -ForegroundColor Green
            Get-Content $File.FullName -Stream $stream.Stream            
        }
        Write-Host "--------------------------------"
        }
    }
}

function Get-Connections{
    $results = Invoke-Command { netstat -ano } | Select-String -Pattern '::','\]:','Active','Proto','\s+$' -NotMatch
    $results | % {
       $socket = $_
       $pattern = '(^\s+(?<proto>[TCP]{3})\s+(?<LocalAddress>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(?<LocalPort>[0-9]{1,5})\s+(?<RemoteAddress>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(?<RemotePort>[0-9]{1,5})\s+(?<State>[\w]+)\s+(?<PID>[0-9]{1,5}))|(\s+(?<proto>[UDP]{3})\s+(?<LocalAddress>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(?<LocalPort>[0-9]{1,5})\s+\*:\*\s+(?<PID>[0-9]{1,5}))'
         if ($socket -match $pattern)
         {
           New-Object psobject | Select @{N='Protocol';E={$Matches['proto']}},
                                        @{N='LocalAddress';E={$Matches['LocalAddress']}},
                                        @{N='LocalPort';E={$Matches['LocalPort']}},
                                        @{N='RemoteAddress';E={$Matches['RemoteAddress']}},
                                        @{N='RemotePort';E={$Matches['RemotePort']}},
                                        @{N='State';E={$Matches['State']}},
                                        @{N='PID';E={$Matches['PID']}},
                                        @{N='ProcessName';E={[System.Diagnostics.Process]::GetProcessById([int]$Matches['PID']).ProcessName};},
                                        @{N='ProcessBornDate';E={Get-UnixDateTime -DateTime ([System.Diagnostics.Process]::GetProcessById([int]$Matches['PID']).StartTime)};}
                                        @{N='ProcessCMDLine';E={Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -EQ $Matches['PID'] | Select-Object CommandLine}}
          }
  
      }
  }

Function Get-SuspiciousTasks {
    #Enumerate Tasks
    $tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, Date, Author, Actions, Triggers, Description, State |
    Where-Object Author -NotLike 'Microsoft*' | Where-Object Author -NE $null | Where-Object Author -NotLike '*@%SystemRoot%\*'

    #for each task found, export in XML which will show any commands run
    foreach ($task in $tasks)
    {
        Export-ScheduledTask -TaskName $task.TaskName
    }
}

Function Get-ActiveServiceDLLHashes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the Algorithm you wish to use with -Algorithm' )]$Algorithm
    )

    Set-ItemProperty REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\*\* -ea 0 | where {($_.ServiceDll -ne $null)} | foreach {Get-FileHash -Algorithm $Algorithm $_.ServiceDll}
}

Function Find-SDDLHiddenServices {
    
    #find services hidden using SDDL for possible persistence(some common legitimate hidden services are WUDFRd,WUDFWpdFs,WUDFWpdMtp)
    $SDDLServices = Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | % { $_ -replace "_[0-9a-f]{2,8}$" } ) -DifferenceObject (gci -path hklm:\system\currentcontrolset\services |
    % { $_.Name -Replace "HKEY_LOCAL_MACHINE\\","HKLM:\" } | ? { Get-ItemProperty -Path "$_" -name objectname -erroraction 'ignore' } | 
    % { $_.substring(40) }) -PassThru | ?{$_.sideIndicator -eq "=>"}

    foreach ($SDDLService in $SDDLServices)
    {
        Get-CimInstance -ClassName CIM_Service | Where-Object Name -EQ $SDDLService | fl *
    }

    
}

Function Get-PrivEscInfo {
    [CmdletBinding()]
        param()

    $TimeSpan = (Get-Date) - (New-TimeSpan -Minutes 2)
    $ConsentPrompt = Get-WinEvent -FilterHashTable @{LogName='Security';ID='4648';StartTime=$TimeSpan} -MaxEvents 1 -ErrorAction "SilentlyContinue" | Where-Object -Property Message -Match 'consent.exe'

    If ($ConsentPrompt)
    {

        $Success = Get-WinEvent -FilterHashTable @{LogName='Security';ID='4624';StartTime=$TimeSpan} -MaxEvents 1 -ErrorAction "SilentlyContinue"
        $Failure = Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625';StartTime=$TimeSpan} -MaxEvents 1 -ErrorAction "SilentlyContinue"
        $Service = Get-WinEvent -FilterHashTable @{LogName='Security';ID='4688';StartTime=$TimeSpan} -MaxEvents 1 -ErrorAction "SilentlyContinue"
        $Canceled = Get-WinEvent -FilterHashTable @{LogName='Security';ID='4673';StartTime=$TimeSpan} -MaxEvents 1 -ErrorAction "SilentlyContinue"

    }  # End If
    Else
    {

        Write-Verbose "[*] Event triggered was not for consent.exe"

    }
}

Function Get-SuspiciousPowerShellCommand {
    [CmdletBinding()]
        param()

    BEGIN
    {

        $Computer = $env:COMPUTERNAME

        Write-Verbose "Checking event log for malicious commands..."

        [array]$BadEvent = Get-WinEvent -FilterHashtable @{logname="Windows PowerShell"; id=800} -MaxEvents 100 | Where-Object { ($_.Message -like "*Pipeline execution details for command line: IEX*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: cmd /c certutil") `
                                -or ($_.Message -like "*Pipeline execution details for command line: certutil") `
                                -or ($_.Message -like "*Pipeline execution details for command line: cmd /c bitsadmin*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: bitsadmin*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: Start-BitsTransfer*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: cmd /c vssadmin*")  `
                                -or ($_.Message -like "*Pipeline execution details for command line: vssadmin*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: Invoke-Expression*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: Invoke-WebRequest*") `
                                -and ($_.Message -notlike "**Pipeline execution details for command line:*Get-WinEvent*" )
                                }  # End FilterHashTable


    } # End BEGIN

    PROCESS
    {

        If (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "IEX*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "Invoke-Expression*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "certutil*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "cmd /c certutil*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "bitsadmin*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "cmd /c bitsadmin*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "Start-BitsTransfer*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "vssadmin*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "cmd /c vssadmin*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "Invoke-WebRequest*") {$EventInfo = $BadEvent}
        Else { exit }

        If ($EventInfo -like $null)
        {

            Write-Host "No malicious commands have been found. Ending rest of script execution. " -ForegroundColor Green

            exit

        } # End If
        Else
        {

            Write-Host "A malicious command may have been found..." -ForegroundColor Red

        }  # End Else

    }
}

<# Usage: 
import-module .\Get-ProcessTree.ps1
Get-ProcessTree -Verbose | select Id, Level, IndentedName, ParentId
OR for more verbose output:
Get-ProcessTree -Verbose | FT Id, Level, IndentedName,ParentId,Path,Hash,CommandLine -AutoSize
Get-ProcessTree -Verbose | FT Id, Level, IndentedName,ParentId,Hash,CommandLine -AutoSize
Get-ProcessTree -Verbose | FT Id, Level, IndentedName,ParentId,Hash,signature,CommandLine -AutoSize
#>
Function Get-DecodedBase64 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the Encoded Data' )]$EncodedText
    )

    $plaintextcommand = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
    $plaintextcommand
}

function Get-ProcessTree
{
    [CmdletBinding()]
    param([string]$ComputerName, [int]$IndentSize = 2)
    
    $indentSize   = [Math]::Max(1, [Math]::Min(12, $indentSize))
    $computerName = ($computerName, ".")[[String]::IsNullOrEmpty($computerName)]
    $processes    = Get-WmiObject Win32_Process -ComputerName $computerName
    $pids         = $processes | select -ExpandProperty ProcessId
    $parents      = $processes | select -ExpandProperty ParentProcessId -Unique
    $liveParents  = $parents | ? { $pids -contains $_ }
    $deadParents  = Compare-Object -ReferenceObject $parents -DifferenceObject $liveParents `
                  | select -ExpandProperty InputObject
    $processByParent = $processes | Group-Object -AsHashTable ParentProcessId
    
    function Write-ProcessTree($process, [int]$level = 0)
    {
        $id = $process.ProcessId
        $processCommandLine = $process.CommandLine
        $parentProcessId = $process.ParentProcessId
        $process = Get-Process -Id $id -ComputerName $computerName
        $hash   = ($process | gi -ea SilentlyContinue|filehash -ea 0).hash
        $signingstatus  = ($process | gi -ea SilentlyContinue|authenticodesignature -ea 0).status
        $indent = New-Object String(' ', ($level * $indentSize))
        $process `
        | Add-Member NoteProperty CommandLine $processCommandLine -PassThru `
        | Add-Member NoteProperty ParentId $parentProcessId -PassThru `
        | Add-Member NoteProperty Level $level -PassThru `
        | Add-Member NoteProperty Hash $hash -PassThru `
        | Add-Member NoteProperty signature $signingstatus -PassThru `
        | Add-Member NoteProperty IndentedName "$indent$($process.Name)" -PassThru 
        $processByParent.Item($id) `
        | ? { $_ } `
        | % { Write-ProcessTree $_ ($level + 1) }
    }
    $processes `
    | ? { $_.ProcessId -ne 0 -and ($_.ProcessId -eq $_.ParentProcessId -or $deadParents -contains $_.ParentProcessId) } `
    | % { Write-ProcessTree $_ }
}

<#
.Synopsis
   Gets running process memory information in relationship to total memory in use.
.DESCRIPTION
   This function uses the Get-Process cmdlet to retrieve running processes grouped by
   name and path. For each grouping it totals the number of running processes, sums the
   workingset property, and provides a percentage of total memory in use by the workingset
   property.
.EXAMPLE
In this example, process memory data is retrieved from the local machine.
>Get-ProcessMemory
ProcName        : AcrobatNotificationClient
Path            : C:\Program Files\WindowsApps\ReaderNotificationClient_1.0.4.0_x86__e1rzdqpraam7r\AcrobatNotificationClient.exe
TotalProcs      : 1
WorkingSetTotal : 9715712
Percentage      : 0.000834550092356408
ProcName        : AdobeCollabSync
Path            : C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AdobeCollabSync.exe
TotalProcs      : 2
WorkingSetTotal : 21123072
Percentage      : 0.00181440759961298
....
.EXAMPLE
This example retrieves process memory data from svr1, and svr2
   "svr1", "svr2" | Get-ProcessMemory
.INPUTS
   This function will accept a ComputerName argument by value over the pipeline.
.OUTPUTS
   This function returns a PSCustomObject that is not specifically formatted or sorted.
#>

function Get-ProcessMemory {
    [CmdletBinding(DefaultParameterSetName = 'None')]
    [OutputType([PSCustomObject])]

    param (
        # Remote computer or collection of remote computers
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'CN')]
        [string[]]
        $ComputerName,

        # PSCredential for remote computer(s)
        [Parameter(ParameterSetName = 'CN')]
        [pscredential]
        $Credential,

        # PSSession for remote connection
        [Parameter(Mandatory = $true, ParameterSetName = 'Session')]
        [System.Management.Automation.Runspaces.PSSession]
        $Session
    )
       
    process {
        $Command = @'
            Get-Process |
                Tee-Object -Variable Procs |
                    Group-Object Name, path |
                        Select-Object @{
                            n="ProcName"
                            e={($_.name -split ", ")[0]}
                        },
                        @{
                            n="Path"
                            e={($_.name -split ", ")[-1]}
                        },
                        @{
                            n="TotalProcs"
                            e={$_.Count}
                        }, 
                        @{
                            n="WorkingSetTotal"
                            e={($_.Group.WorkingSet | Measure-Object -Sum).sum}
                        },
                        @{
                            n="Percentage"
                            e={($_.Group.WorkingSet | Measure-Object -Sum).sum / 
                                ($Procs.workingset | Measure-Object -Sum).Sum 
                            }
                        }
'@ #Command here-string to invoke

        if ($PSCmdlet.ParameterSetName -eq "None") {
            Invoke-Expression -Command $Command
        } #if ParameterSetName is None (local machine)
        
        else {
            $InvokeCommandArgs = $PSBoundParameters #works because I use the same parameter names
            $InvokeCommandArgs.ScriptBlock = [scriptblock]::Create($Command)
            Invoke-Command @InvokeCommandArgs
        } #else - ParameterSetName is NOT None (remoting)   

    } #Process Script Block for Get-ProcessMemory Function 

} #Get-ProcessMemory Function Definition

<#
.Synopsis
   Displays running process memory information in relationship to total memory in use.
.DESCRIPTION
   This function uses the Get-ProcessMemory function to retrieve running processes grouped by
   name and path. For each grouping it totals the number of running processes, sums the
   workingset property, and provides a percentage of total memory in use by the workingset
   property.
.EXAMPLE
In this example, process memory data is displayed from the local machine.
>Show-ProcessMemory
Name                                Path                            Procesess        Usage/MB      Percentage
----                                ----                            ---------        --------      ----------
chrome                              C:\Program Files (x86)\Goog...         29        3,578.19          32.45%
Teams                               C:\Users\micha\AppData\Loca...          9        1,295.24          11.75%
svchost                             svchost                                78          899.66           8.16%
Code                                C:\Users\micha\AppData\Loca...          8          838.29           7.60%
powershell_ise                      C:\WINDOWS\system32\Windows...          1          582.86           5.29%
....
.EXAMPLE
This example displays process memory data from svr1, and svr2
   "svr1", "svr2" | Show-ProcessMemory
.INPUTS
   This function will accept a ComputerName argument by value over the pipeline.
.OUTPUTS
   This function returns a Formatted Table Object.
#>
function Show-ProcessMemory {
    [CmdletBinding(DefaultParameterSetName = 'None')]

    param (
        # Remote computer or collection of remote computers
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'CN')]
        [string[]]
        $ComputerName,

        # PSCredential for remote computer(s)
        [Parameter(ParameterSetName = 'CN')]
        [pscredential]
        $Credential,

        # PSSession for remote connection
        [Parameter(Mandatory = $true, ParameterSetName = 'Session')]
        [System.Management.Automation.Runspaces.PSSession]
        $Session
    )
    
    process {
        
        Get-ProcessMemory @PSBoundParameters |
            Sort-Object WorkingSetTotal -Descending |
                Format-Table -Property @{
                    n="Name"
                    e={$_.ProcName}
                    w=35
                },
                @{
                    n="Path"
                    e={$_.Path}
                    w=30
                },
                @{
                    n="Procesess"
                    e={$_.TotalProcs}
                    w=10
                },
                @{
                    n="Usage/MB"
                    e={$_.WorkingSetTotal / 1MB}
                    f="N2"
                    w=15
                },
                @{
                    n="Percentage"
                    e={$_.Percentage}
                    f="P2"
                    w=15
                }
        
    } #Process Script Block for Show-ProcessMemory Function
    
} #Show-ProcessMemory Function Definition

Function Get-RunningProcessHashes{
    Get-Process | Select-Object -Property name, path, @{n="Hash"; e={(Get-FileHash -Path $_.path).hash}}
}

Export-ModuleMember -Function Find-SDDLHiddenServices, Get-ActiveServiceDLLHashes, Get-SuspiciousTasks, Get-Connections, Read-AltDataStreams, 
Get-LocalMemDump, Get-ParentChildProcess, Get-UserPSHistory, Find-UnsignedDLLs, Find-SusFilterDrivers, Find-HiddenExes, Get-PrivEscInfo,
Get-SuspiciousPowerShellCommand, Get-DecodedBase64, Get-ProcessTree, Get-ProcessMemory, Show-ProcessMemory, Get-RunningProcessHashes
