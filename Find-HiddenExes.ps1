<#
Find Windows Executables based on byte code that may be obfuscated using simply changing the file extension
#>
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
