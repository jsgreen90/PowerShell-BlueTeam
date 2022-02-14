<#
Get the powershell history for each user
#>
Function Get-UserPSHistory {
    $users = Get-ChildItem C:\Users

    foreach($user in $users){
        if(Test-Path -Path  C:\Users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt){
            $psHistory = Get-Content C:\Users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
            $line = 0
            foreach($cmd in $psHistory){
                $result = @{}
                $result.add("CommandLine", $cmd)

                $prefix = $cmd.split()[0]
                $result.add("Prefix", $prefix)
                
                $result.add("User", $user.Name.toString()) 
                $result.add("Line", $line++)
                
                Add-Result -hashtbl $result
        }
    }
}
}
