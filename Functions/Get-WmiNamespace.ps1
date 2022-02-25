function Get-WmiNamespace {
    # usage = Get-wminamespace -Recurse
	foreach ($Namespace in (Get-WmiObject -Namespace $Path -Class __Namespace))
	{
		$FullPath = $Path + "/" + $Namespace.Name
		Write-Output $FullPath
		Get-WmiNamespace -Path $FullPath
	}
}
