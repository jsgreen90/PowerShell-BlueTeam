# Finds any user init mpr logon scripts

function Get-UserInitLogonScripts {
    $logonScriptsArrayList = [System.Collections.ArrayList]@();
                 
    New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null;
    Set-Location HKU: | Out-Null;

    $SIDS  += Get-ChildItem -Path HKU: | where {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | foreach {$_.PSChildName };

    foreach($SID in $SIDS){
       $logonscriptObject = [PSCustomObject]@{
           SID =""
           HasLogonScripts = ""
    
       };
       $logonscriptObject.sid = $SID; 
       $logonscriptObject.haslogonscripts = !((Get-ItemProperty HKU:\$SID\Environment\).userinitmprlogonscript -eq $null); 
       $logonScriptsArrayList.add($logonscriptObject) | out-null
       }
    $logonScriptsArrayList
}
