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

Export-ModuleMember -Function Find-SDDLHiddenServices, Get-ActiveServiceDLLHashes, Get-SuspiciousTasks, Get-Connections,
    Read-AltDataStreams, Get-LocalMemDump, Get-ParentChildProcess, Get-UserPSHistory, Find-UnsignedDLLs,
    Find-SusFilterDrivers, Find-HiddenExes
