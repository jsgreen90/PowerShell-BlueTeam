function Find-RecentlyAccessedFiles {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage = 'Please enter the starting path for the directory you would like to check')]$DirectoryPath,
        [switch]$Recurse
    )
    # Make sure the directory exists
    if (!(Test-Path $DirectoryPath))
    {
        Write-Output "Cannot find target directory!"
        exit
    }
    $folders = Get-ChildItem -Path $DirectoryPath -Directory -Recurse:$Recurse
    foreach ($folder in $folders)
    {
        Get-ChildItem -Attributes !Directory | Sort-Object LastAccessTime -Descending | Select-Object FullName, LastAccessTime -First 3
    }
}
