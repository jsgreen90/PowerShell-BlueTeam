<#
Decode Base64
#>

Function Get-DecodedBase64 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Please Enter the Encoded Data' )]$EncodedText
    )

    $plaintextcommand = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
    $plaintextcommand
}
