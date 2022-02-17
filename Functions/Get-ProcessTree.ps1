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
