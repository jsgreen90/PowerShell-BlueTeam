function Get-ItemsofInterest {
 [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the filename to output' )]$Output
        )

$commands = ('dir /s /b %localappdata%\*.exe | findstr /e .exe',
              'dir /s /b %appdata%\*.exe | findstr /e .exe',
              'dir /s /b %localappdata%\*.dll | findstr /e .dll',
              'dir /s /b %appdata%\*.dll | findstr /e .dll',
              'dir /s /b %localappdata%\*.bat | findstr /e .bat',
              'dir /s /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\" | findstr /e .lnk',
              'dir /s /b "C:\Users\Public\" | findstr /e .exe',
              'dir /s /b "C:\Users\Public\" | findstr /e .lnk',
              'dir /s /b "C:\Users\Public\" | findstr /e .dll',
              'dir /s /b "C:\Users\Public\" | findstr /e .bat')
   

foreach ($command in $commands)
{
    Echo $command >> $Output
    cmd.exe /c $command >> $Output
    Echo "-----------------------------------------------------" >> $Output
}
} 
