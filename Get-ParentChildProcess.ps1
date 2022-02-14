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
