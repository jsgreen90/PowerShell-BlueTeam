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
                                        @{N= 'ProcessCMDLine';E={Get-CimInstance -ClassName Win32_Process | Where-Object ProcessId -EQ $Matches['PID'] | Select-Object CommandLine}}
          }
  
      }
  }
