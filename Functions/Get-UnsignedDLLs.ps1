# Find DLLs that do not have a valid signature

function Get-UnsignedDLLs {
    $a = Get-ChildItem  -Path C:\Windows\* -Include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid" | Format-List *
    $b = Get-ChildItem  -Path C:\Windows\System32\* -Include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid" | Format-List *
    $c = $a + $b
    $c
}
