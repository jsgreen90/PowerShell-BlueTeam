<#
Find abnormal scheduled tasks and export them to see any commands they have run
#>
Function Grab-SuspiciousTasks {
    #Enumerate Tasks
    $tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, Date, Author, Actions, Triggers, Description, State |
    Where-Object Author -NotLike 'Microsoft*' | Where-Object Author -NE $null | Where-Object Author -NotLike '*@%SystemRoot%\*'

    #for each task found, export in XML which will show any commands run
    foreach ($task in $tasks)
    {
        Export-ScheduledTask -TaskName $task.TaskName
    }
}
