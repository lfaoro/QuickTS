function Out-MsgBox {
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [string]$message
)

    $WshShell = New-Object -ComObject wscript.shell
    $PopUp = $WshShell.popup("$message",0,"GFI Software",0)
}

Out-MsgBox "test"