<#
Enriches process information utilizing both Get-Process and WMI to include usernames and commandline arguments
#>

function Get-EnrichedProcesses {
  $ProcInfo1 = Get-WmiObject win32_process | select processname, ProcessId, CommandLine | Sort-Object processname
  foreach ($proc in $ProcInfo1){
   $ProcInfo2 = Get-Process -Id $proc.ProcessId -IncludeUserName | Select-Object UserName
   $FullProcInfo = New-Object -TypeName psobject -Property @{
    PID = $proc.ProcessId
    User = $ProcInfo2.UserName
    ProcessName = $proc.processname
    CommandLine = $proc.CommandLine
    }
   $FullProcInfo
  }
}
