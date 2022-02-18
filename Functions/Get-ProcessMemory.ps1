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
