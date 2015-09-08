function Get-DCOMconfig {

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [string]$ApplicationName
)


$dcomApp = get-wmiobject -class "Win32_DCOMApplicationSetting" -namespace "root\CIMV2" -Filter "Caption='$ApplicationName'" -EnableAllPrivileges

foreach ($object in $dcomApp) { 
      write-output "Application ID:  $($object.AppID)"
      write-output "Authentication Level:  $($object.AuthenticationLevel)"
      write-output "Caption:  $($object.Caption) "
      write-output "Custom Surrogate:  $($object.CustomSurrogate)"
      write-output "Description: $( $object.Description) "
      write-output "Enable At Storage Activation: $($object.EnableAtStorageActivation )"
      write-output "Local Service: $( $object.LocalService )"
      write-output "Remote Server Name: $( $object.RemoteServerName )"
      write-output -ForegroundColor Yellow "Run As User: $( $object.RunAsUser )"
      write-output "Service Parameters: $( $object.ServiceParameters )"
      write-output "Setting ID: $( $object.SettingID )"
      write-output "Use Surrogate: $( $object.UseSurrogate )"
} 
}
