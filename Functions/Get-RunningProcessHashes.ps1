Function Get-RunningProcessHashes{
    Get-Process | Select-Object -Property name, path, @{n="Hash"; e={(Get-FileHash -Path $_.path).hash}}
}
