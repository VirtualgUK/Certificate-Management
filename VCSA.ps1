function VCSA {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')]
    [String] $VCSA_FQDN,
    [Parameter(Mandatory = $true)]
    [String] $VCSA_IP,
    [Parameter(Mandatory = $true)]
    [PSCredential] $VCSA_Credential,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')]
    [String] $CA_FQDN,
    [Parameter(Mandatory = $true)]
    [String] $CA_Template,
    [Parameter(Mandatory = $true)]
    [PSCustomObject] $CSR,
    [Parameter(Mandatory = $true)]
    [String] $Cert_Chain_Path,
    [Parameter(Mandatory = $true)]
    [String] $Log_Dir_Path
  )

  $ErrorActionPreference = "Stop"

  <#
  Validate Inputs
  #>
  if (!(Test-Path -Path $("$Cert_Chain_Path"))) {
    Throw "Specified certificate chain file does not exist or is inaccessible: $Cert_Chain_Path"
  }

  if (!(Test-Path -Path $("$Log_Dir_Path"))) {
    Throw "Specified log path directory does not exist or is inaccessible: $Log_Dir_Path"
  }

  if (!([ipaddress]$VCSA_IP)) {
    Throw "Specified VCSA IP address is invalid: $VCSA_IP"
  }

  <#
  Start Script
  #>
  $Date = Get-Date
  $Log_File = $($Log_Dir_Path + "\" + $Date.ToString("yyyy-MM-dd-HH-mm-ss") + "_VCSA.log")

  Start-Transcript -Path $Log_File -Append

  Write-Host "Working on VCSA system: $($VCSA_FQDN)"
  $Auth_String = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($VCSA_Credential.UserName + ':' + $VCSA_Credential.GetNetworkCredential().Password))
  
  $Auth_Header = @{
    'Authorization' = "Basic $Auth_String"
  }
  
  Write-Host "Obtaining session ID for VCSA"
  try {
    $Request_Session_Response = Invoke-WebRequest -Uri $("https://$VCSA_FQDN/rest/com/vmware/cis/session") -Method Post -Headers $Auth_Header -SkipCertificateCheck -SkipHttpErrorCheck
    $Session_ID = (ConvertFrom-Json $Request_Session_Response.Content).value
    Write-Host "Session ID obtained: $($Session_ID)"
  }
  catch {
    Throw "Error obtaining Session ID for VCSA: $($_.Exception.Message)"
    Stop-Transcript
  }
  
  $Request_Header = @{
    'vmware-api-session-id' = $Session_ID
  }
  
  $Body = @{
    spec = @{ 
      common_name       = "$($CSR.Common_Name)"
      country           = "$($CSR.Country)"
      email_address     = "$($CSR.Email_Address)"
      key_size          =  $CSR.Key_Size
      locality          = "$($CSR.Locality)"
      organization      = "$($CSR.Organization)"
      organization_unit = "$($CSR.Organization_Unit)"
      state_or_province = "$($CSR.State)"
      subject_alt_name  = @(
        "$($VCSA_FQDN)",
        "$VCSA_IP"
      )
    }
  }
  
  $Request_Body = $Body | ConvertTo-Json
  $Request_Type = "application/json"
  
  Write-Host "Requesting CSR from VCSA"
  try {
    $Request_CSR_Response = Invoke-WebRequest -Uri $("https://$VCSA_FQDN/rest/vcenter/certificate-management/vcenter/tls-csr") -Method Post -Headers $Request_Header -body $Request_Body -ContentType $Request_Type -SkipCertificateCheck -SkipHttpErrorCheck
    $CSR = (ConvertFrom-Json $Request_CSR_Response.Content).value.csr
    Write-Host "CSR obtained: $($CSR)"
  }
  catch {
    Throw "Error obtaining CSR from VCSA: $($_.Exception.Message)"
    Stop-Transcript
  }

  Write-Host "Creating CSR file from request: $("$VCSA_FQDN.csr")"

  $CSR = (ConvertFrom-Json $Request_CSR_Response.Content).value.csr
  
  if (Test-Path -Path $("$VCSA_FQDN.csr")) {
    Write-Host "CSR file exists, will overwrite"
  }

  try {
    New-Item -Path $("$VCSA_FQDN.csr") -Force
  }
  catch {
    Throw "Error creating CSR file: $($_.Exception.Message)"
    Stop-Transcript
  }

  $CSR_Cert = $CSR.replace('\r\n', '')
  Add-Content -Path $("$VCSA_FQDN.csr") -Value $CSR_Cert
  
  Write-Host "Sign CSR with ECA"
  try{
    $SigningRequest = Invoke-Expression -Command "certreq -submit -q -f -policyserver $(`"$CA_FQDN`") -attrib $(`"CertificateTemplate:$CA_Template`") $(`"$VCSA_FQDN.csr`") $(`"$VCSA_FQDN.cer`") $(`"$VCSA_FQDN.p7b`")"
  }
  catch{
    Throw "Error signing CSR with CA: $($_.Exception.Message)"
    Stop-Transcript
  }

  if ($SigningRequest[2] -ne "Certificate retrieved(Issued) Issued") {
    Throw "certreq encountered an error wne signing the request: $SigningRequest[2]"
    Stop-Transcript
  }

  if (!($LastExitCode -eq 0)) {
    Throw "certreq encountered an error: $SigningRequest"
    Stop-Transcript
  }

  if (!(Test-Path -Path $("$VCSA_FQDN.cer"))) {
    Throw "Signed certificate file is missing"
    Stop-Transcript
  }

  Write-Host "Upload certificate chain"
  $Cert_Chain = Get-Content -Path $($Cert_Chain_Path) -Raw
  $Cert_Chain = $Cert_Chain.replace('\n', '')
  
  $Body = @{
    cert_chain = @{
      cert_chain = @( 
        $($Cert_Chain)
      )
  
    }
  }
  
  $Request_Body = $Body | ConvertTo-Json

  try {
    $Request_Cert_Chain_Upload_Response = Invoke-RestMethod -Uri "https://$VCSA_FQDN/api/vcenter/certificate-management/vcenter/trusted-root-chains" -Method Post -Headers $Request_Header -Body $Request_Body -ContentType $Request_Type  -SkipCertificateCheck -SkipHttpErrorCheck
    Write-Host "Certificate Chain Uploaded"
  }
  catch {
    Throw "Error uploading certificate chain to VCSA: $($_.Exception.Message)"
    Stop-Transcript
  }
  
  Write-Host "Upload server certificate"
  
  $Signed_Cert = Get-Content -Path $("$VCSA_FQDN.cer") -Raw

  $Signed_Cert = $Signed_Cert.replace('\n', '')
  
  $Body = @{
    'cert' = "$($Signed_Cert)"
  }
  
  $Request_Body = $Body | ConvertTo-Json
  try {
    $Request_Signed_Cert_Upload_Response = Invoke-WebRequest -Uri $("https://$VCSA_FQDN/api/vcenter/certificate-management/vcenter/tls") -Method Put -Headers $Request_Header -body $Request_Body -ContentType $Request_Type -SkipCertificateCheck -SkipHttpErrorCheck
    Write-Host "Signed Certificate Uploaded"
    Write-Host "VCSA services will restart now"
  }
  catch {
    Throw "Error uploading signed certificate to VCSA: $($_.Exception.Message)"
    Stop-Transcript
  }

  <#
  Remove files
  #>
  $Files = @($("$VCSA_FQDN.cer"),$("$VCSA_FQDN.csr"),$("$VCSA_FQDN.rsp"))
  Write-Host "Deleting old file:"

  ForEach ($File in $Files){
    if (Test-Path $File) {
      Remove-Item $File -Force
    }
  }

  Stop-Transcript
}

<#
Example Execution
#>

$VCSA_Cred = Get-Credential
$VCSA_FQDN = "vcsa01.example.local"
$VCSA_IP = "1.2.3.4"
$CA_FQDN = "ca01.example.local"
$CA_Template = "WebServer"
$Cert_Chain_Path = "C:\temp\chain.cer"
$Log_Dir_Path = "C:\temp"

$CSR = [PSCustomObject]@{
  Common_Name       = $VCSA_FQDN
  Organization_Unit = "My_OU"
  Organization      = "My_Org"
  Locality          = "MY_Locality"
  State             = "My_State"
  Country           = "US"
  Email_Address     = "me@example.com"
  Key_Size          = 4096
}

VCSA $VCSA_FQDN $VCSA_IP $VCSA_Cred $CA_FQDN $CA_Template $CSR $Cert_Chain_Path $Log_Dir_Path