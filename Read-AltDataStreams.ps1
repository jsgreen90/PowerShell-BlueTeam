<#
Find hidden/alternate Data Streams for files, excluding :$DATA which is present in every NTFS File
#>
Function Read-AltDataStreams {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the FULL PATH of the directory you would like to analyze' )]$DirectoryPath,
        [switch] $Recurse 
    )

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
