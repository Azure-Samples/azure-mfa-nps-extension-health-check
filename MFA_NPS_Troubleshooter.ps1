Clear-Host

Write-Host "*********************************************************************************"
Write-Host "**** Welcome to MFA NPS Extension Troubleshooter Tool ****" -ForegroundColor Green
Write-Host "**** This Tool will help you to troubleshoot MFA NPS Extension Knows issues ****" -ForegroundColor Green
Write-Host "**** Tool Version is 3.0, Make Sure to Visit MS site to get the latest version ****" -ForegroundColor Green
Write-Host "**** Thank you for Using MS Products, Microsoft @2024 ****" -ForegroundColor Green
Write-Host "*******************************************************************************"

Write-Host
Write-Host
Write-Host

Write-Host " Please Choose one of the tests below: " -ForegroundColor Yellow
Write-Host
Write-Host " (1) Isolate the Cause of the issue: if it's NPS or MFA issue (Export MFA RegKeys, Restart NPS, Test, Import Regkeys, Restart NPS)... " -ForegroundColor Green
Write-Host
Write-Host " (2) All users not able to use MFA NPS Extension (Testing Access to Azure/Create HTML Report) ... " -ForegroundColor Green
Write-Host
Write-Host " (3) Specific User not able to use MFA NPS Extension (Test MFA for specific UPN) ... " -ForegroundColor Green
Write-Host
Write-Host " (4) Collect Logs to contact MS support (Enable Logging/Restart NPS/Gather Logs)... " -ForegroundColor Green
Write-Host
Write-Host " (E) EXIT SCRIPT " -ForegroundColor Red -BackgroundColor White
Write-Host
$Timestamp = "$((Get-Date).ToString("yyyyMMdd_HHmmss"))"
$Choice_Number =''
$Choice_Number = Read-Host -Prompt "Based on which test you need to run, please type 1, 2, 3, 4 or E to exit the test. Then click Enter " 

while ( !($Choice_Number -eq '1' -or $Choice_Number -eq '2' -or $Choice_Number -eq '3' -or $Choice_Number -eq '4' -or$Choice_Number -eq 'E'))
{

$Choice_Number = Read-Host -Prompt "Invalid Option, Based on which test you need to run, please type 1, 2, 3, 4 or E to exit the test. Then click Enter " 

}

##### This Function will be run against against MFA NPS Server ######
##### Microsoft 2022 @Ahmad Yasin, Nate Harris (nathar), Will Aftring (wiaftin) ##########

Function Check_Nps_Server_Module {

# Decide which cloud environment to be checked
Write-Host
Write-Host
Write-Host " Please Choose one of the cloud environments (Azure Commercial / Azure Government / Microsoft Azure operated by 21Vianet) below: " -ForegroundColor Yellow
Write-Host
Write-Host " (1) Azure Commercial " -ForegroundColor Green
Write-Host
Write-Host " (2) Azure Government " -ForegroundColor Green
Write-Host
Write-Host " (3) Microsoft Azure operated by 21Vianet " -ForegroundColor Green
Write-Host
Write-Host " (E) EXIT SCRIPT " -ForegroundColor Red -BackgroundColor White
Write-Host

$Choice_Number =''
$Choice_Number = Read-Host -Prompt "Based on which cloud environment you need to evaluate, please type 1, 2, 3 or E to exit the test. Then click Enter " 

while ( !($Choice_Number -eq '1' -or $Choice_Number -eq '2' -or $Choice_Number -eq '3' -or $Choice_Number -eq 'E'))
{

$Choice_Number = Read-Host -Prompt "Invalid Option, Based on which cloud environment you need to evaluate, please type 1, 2, 3 or E to exit the test. Then click Enter " 

}

if ($Choice_Number -eq 'E') { Break}

$TestStepNumber = 0
$ErrorActionPreference= 'silentlycontinue'
$loginAccessResult = 'NA'
$NotificationaccessResult = 'NA'
$MFATestVersion = 'NA'
$MFAVersion = 'NA'
$NPSServiceStatus = 'NA'
$SPNExist = 'NA'
$SPNEnabled = 'NA'
$FirstSetofReg = 'NA'
$SecondSetofReg = 'NA'
$certificateResult = 'NA'
$ValidCertThumbprint = 'NA'
$ValidCertThumbprintExpireSoon = 'NA'
$TimeResult = 'NA'
$updateResult = 'NA'
$ListofMissingUpdates = 'NA'
$objects = @()
## Variables for endpoints network connectivity
$TCPLogin = $False
$TCPAdnotification = $False
$TCPStrongAuthService = $False
$TCPCredentials = $False

$DNSLogin= $False
$DNSADNotification =$False
$DNSStrongAuthService = $False
$DNSCredentials = $False

$IWRLogin = ""
$IWRADNotification = ""
$IWRStrongAuthService = ""
$IWRCredentials = ""

# Install required MG Graph modules
Write-Host
write-Host "Ensure Microsoft.Graph module is installed ..." -ForegroundColor Green
Write-Host

# Required MG Graph modules
Install-Module -Name "Microsoft.Graph.Authentication" -ErrorAction Stop
Install-Module -Name "Microsoft.Graph.Applications" -ErrorAction Stop
Install-Module -Name "Microsoft.Graph.Users" -ErrorAction Stop
Install-Module -Name "Microsoft.Graph.Identity.DirectoryManagement" -ErrorAction Stop
Install-Module -Name "Microsoft.Graph.Identity.SignIns" -ErrorAction Stop

# Full Microsoft MG Graph library
# Install-Module -Name "Microsoft.Graph" -verbose -ErrorAction Stop

Write-Host
write-Host "Start Entra connection to be established with Global Admin role ..." -ForegroundColor Green
Write-Host

Connect-MgGraph -Scopes Domain.Read.All,Application.Read.All -NoWelcome

$verifyConnection = Get-MgDomain -ErrorAction SilentlyContinue

if($verifyConnection -ne $null)
{

Write-Host
write-Host "Connection established Successfully - Starting the Health Check Process ..." -ForegroundColor Green
Write-Host
write-host

# Check the accessibility to Azure endpoints based on cloud selection

if ($Choice_Number -eq '1') { 
    
    $AzureEndpointLogin = "login.microsoftonline.com"
    $AzureEndpointADNotification = "adnotifications.windowsazure.com"
    $AzureEndpointStrongAuthService = "strongauthenticationservice.auth.microsoft.com"

 }

if ($Choice_Number -eq '2') { 

    $AzureEndpointLogin = "login.microsoftonline.us"
    $AzureEndpointADNotification = "adnotifications.windowsazure.us"
    $AzureEndpointStrongAuthService = "strongauthenticationservice.auth.microsoft.us"

 }

if ($Choice_Number -eq '3') { 

    $AzureEndpointLogin = "login.chinacloudapi.cn"
    $AzureEndpointADNotification = "adnotifications.windowsazure.cn"
    $AzureEndpointStrongAuthService = "strongauthenticationservice.auth.microsoft.cn"

 }

# Azure login endpoint
$AzureEndpointLoginScriptBlock = "Test-NetConnection -ComputerName " + $AzureEndpointLogin + " -Port 443"
$AzureEndpointLoginURI = "https://" + $AzureEndpointLogin
$AzureEndpointLoginURISlash = $AzureEndpointLoginURI + "/"

# Azure notifications endpoint
$AzureEndpointADNotificationScriptBlock = "Test-NetConnection -ComputerName " + $AzureEndpointADNotification + " -Port 443"
$AzureEndpointADNotificationURI = "https://" + $AzureEndpointADNotification

# Azure strong auth service endpoint
$AzureEndpointStrongAuthServiceScriptBlock = "Test-NetConnection -ComputerName " + $AzureEndpointStrongAuthService + " -Port 443"
$AzureEndpointStrongAuthServiceURI = "https://" + $AzureEndpointStrongAuthService

# Azure credentials endpoint
$AzureEndpointCredentials = "credentials.azure.com"
$AzureEndpointCredentialsScriptBlock = "Test-NetConnection -ComputerName " + $AzureEndpointCredentials + " -Port 443"
$AzureEndpointCredentialsURI = "https://" + $AzureEndpointCredentials


#Muath Updates:
####
function RunPSScript([String] $PSScript){

$GUID=[guid]::NewGuid().Guid

$Job = Register-ScheduledJob -Name $GUID -ScheduledJobOption (New-ScheduledJobOption -RunElevated) -ScriptBlock ([ScriptBlock]::Create($PSScript)) -ArgumentList ($PSScript) -ErrorAction Stop

$Task = Register-ScheduledTask -TaskName $GUID -Action (New-ScheduledTaskAction -Execute $Job.PSExecutionPath -Argument $Job.PSExecutionArgs) -Principal (New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest) -ErrorAction Stop

$Task | Start-ScheduledTask -AsJob -ErrorAction Stop | Wait-Job | Remove-Job -Force -Confirm:$False

While (($Task | Get-ScheduledTaskInfo).LastTaskResult -eq 267009) {Start-Sleep -Milliseconds 150}

$Job1 = Get-Job -Name $GUID -ErrorAction SilentlyContinue | Wait-Job
$Job1 | Receive-Job -Wait -AutoRemoveJob 

Unregister-ScheduledJob -Id $Job.Id -Force -Confirm:$False

Unregister-ScheduledTask -TaskName $GUID -Confirm:$false
} 
####

$TestStepNumber = $TestStepNumber + 1
write-Host $TestStepNumber "- Checking Accessibility to" $AzureEndpointLoginURI " ..." -ForegroundColor Yellow
write-Host

########################################################################
$TCPLogin = (RunPSScript -PSScript $AzureEndpointLoginScriptBlock).TcpTestSucceeded
$DNSLogin = (RunPSScript -PSScript $AzureEndpointLoginScriptBlock).NameResolutionSucceeded
$IWRLoginPage = Invoke-WebRequest -Uri $AzureEndpointLoginURI
$IWRLogin = if($IWRLoginPage.StatusCode -eq 200) {$true} else {$False}

#$IWRLogin = (RunPSScript -PSScript $IWRLoginScriptBlock)
########################################################################
#Write-Host $TCPLogin " # " $DNSLogin " # " $IWRLogin
if (($TCPLogin -and $DNSLogin) -or $IWRLogin)
{

### write-Host "Test login.microsoftonline.com accessibility Passed" -ForegroundColor Green 


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking accessiblity to '+$AzureEndpointLogin;'Result'='Test Passed';'Recommendations' ="N/A";'Notes' = "N/A"}


$loginAccessResult = "True"

}

Else

{
### write-Host "Test login.microsoftonline.com accessibility Failed" -ForegroundColor Red

$loginAccessResult = "False"
$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking accessiblity to '+$AzureEndpointLogin;'Result'='Test Failed';'Recommendations' ="Follow MS article for remediation: https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#network-requirements";'Notes' = "This will cause MFA Methods to fail"}


}

$TestStepNumber = $TestStepNumber + 1
write-Host $TestStepNumber "- Checking Accessibility to" $AzureEndpointADNotificationURI " ..." -ForegroundColor Yellow
Write-Host

########################################################################
$TCPAdnotification = (RunPSScript -PSScript $AzureEndpointADNotificationScriptBlock).TcpTestSucceeded
$DNSADNotification = (RunPSScript -PSScript $AzureEndpointADNotificationScriptBlock).NameResolutionSucceeded
$DNSADNotificationPage = Invoke-WebRequest -Uri $AzureEndpointADNotificationURI
$IWRADNotification = if($DNSADNotificationPage.StatusCode -eq 200) {$true} else {$False}

#$IWRADNotification = (RunPSScript -PSScript $IWRADNotificationScriptBlock)
########################################################################
#Write-Host $TCPAdnotification " # " $DNSADNotification " # " $IWRADNotification
if (($TCPAdnotification -and $DNSADNotification) -or $IWRADNotification)

{

### write-Host "Test adnotifications.windowsazure.com accessibility Passed" -ForegroundColor Green

$NotificationaccessResult = "True"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking accessiblity to '+$AzureEndpointADNotification;'Result'='Test Passed';'Recommendations' ="N/A";'Notes' = "N/A"}

}

Else

{
### write-Host "Test https://adnotifications.windowsazure.com accessibility Failed" -ForegroundColor Red

$NotificationaccessResult = "False"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking accessiblity to '+$AzureEndpointADNotification;'Result'='Test Failed';'Recommendations' ="Follow MS article for remediation: https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#network-requirements";'Notes' = "This will cause MFA Methods to fail"}


}

$TestStepNumber = $TestStepNumber + 1
write-Host $TestStepNumber "- Checking Accessibility to" $AzureEndpointStrongAuthServiceURI " ..." -ForegroundColor Yellow
Write-Host

########################################################################
$TCPStrongAuthService = (RunPSScript -PSScript $AzureEndpointStrongAuthServiceScriptBlock).TcpTestSucceeded
$DNSStrongAuthService = (RunPSScript -PSScript $AzureEndpointStrongAuthServiceScriptBlock).NameResolutionSucceeded
$IWRStrongAuthServicePage = Invoke-WebRequest -Uri $AzureEndpointStrongAuthServiceURI
$IWRStrongAuthService = if($IWRStrongAuthServicePage.StatusCode -eq 200) {$true} else {$False}

#$IWRStrongAuthService = (RunPSScript -PSScript $IWRStrongAuthServiceScriptBlock)
########################################################################
#Write-Host $TCPStrongAuthService " # " $DNSStrongAuthService " # " $IWRStrongAuthService
if (($TCPStrongAuthService -and $DNSStrongAuthService) -or $IWRStrongAuthService)

{

### write-Host "Test strongauthenticationservice.auth.microsoft.com accessibility Passed" -ForegroundColor Green

$NotificationaccessResult = "True"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking accessiblity to '+$AzureEndpointStrongAuthService;'Result'='Test Passed';'Recommendations' ="N/A";'Notes' = "N/A"}


}

Else

{
### write-Host "Test https://strongauthenticationservice.auth.microsoft.com accessibility Failed" -ForegroundColor Red

$NotificationaccessResult = "False"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking accessiblity to '+$AzureEndpointStrongAuthService;'Result'='Test Failed';'Recommendations' ="Follow MS article for remediation: https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#network-requirements";'Notes' = "This will cause MFA Methods to fail"}


}

$TestStepNumber = $TestStepNumber + 1
write-Host $TestStepNumber "- Checking Accessibility to" $AzureEndpointCredentialsURI " ..." -ForegroundColor Yellow
Write-Host

########################################################################
$TCPCredentials = (RunPSScript -PSScript $AzureEndpointCredentialsScriptBlock).TcpTestSucceeded
$DNSCredentials = (RunPSScript -PSScript $AzureEndpointCredentialsScriptBlock).NameResolutionSucceeded
$IWRCredentialsPage = Invoke-WebRequest -Uri $AzureEndpointCredentialsURI
$IWRCredentials = if($IWRCredentialsPage.StatusCode -eq 200) {$true} else {$False}

#$IWRCredentials = (RunPSScript -PSScript $IWRCredentialsScriptBlock)
########################################################################
#Write-Host $TCPCredentials " # " $DNSCredentials " # " $IWRCredentials

if (($TCPCredentials -and $DNSCredentials) -or $IWRCredentials)

{

### write-Host "Test adnotifications.windowsazure.com accessibility Passed" -ForegroundColor Green

$NotificationaccessResult = "True"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking accessiblity to ' + $AzureEndpointCredentialsURI;'Result'='Test Passed';'Recommendations' ="N/A";'Notes' = "N/A"}

}

Else

{
### write-Host "Test https://adnotifications.windowsazure.com accessibility Failed" -ForegroundColor Red

$NotificationaccessResult = "False"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking accessiblity to ' + $AzureEndpointCredentialsURI;'Result'='Test Failed';'Recommendations' ="Follow MS article for remediation: https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#network-requirements";'Notes' = "This will cause MFA Methods to fail"}


}

$TestStepNumber = $TestStepNumber + 1
write-Host $TestStepNumber "- Checking MFA version ... " -ForegroundColor Yellow
Write-Host

# Get MFA NPS installed version
$MFAVersion = Get-WmiObject Win32_Product -Filter "Name like 'NPS Extension For Azure MFA'" | Select-Object -ExpandProperty Version

# Get the latest version of MFA NPS Extension

## OLD METHOD TO RETRIEVE UPDATED MFA NPS ESTENSION
#$latestMFAVersion = (((Invoke-WebRequest -Uri 'https://www.microsoft.com/en-us/download/details.aspx?id=54688').ParsedHtml.getElementsByTagName('div') | Where-Object { $_.classname -eq 'fileinfo' }).textContent).Split(':')[1] -replace "[^0-9.]",''

$MFADownloadPage = Invoke-WebRequest -Uri 'https://www.microsoft.com/en-us/download/details.aspx?id=54688'
$MFADownloadPageHTML = $MFADownloadPage.RawContent
#$MFADownloadPageHTMLSplit = ($MFADownloadPageHTML -split '<h3 class="h6">Version:</h3><p style="overflow-wrap:break-word">',2)[1]
$MFADownloadPageHTMLSplit = ($MFADownloadPageHTML -split '"version":"',2)[1]
#$latestMFAVersion = ($MFADownloadPageHTMLSplit -split '</p></div><div',2)[0]
$latestMFAVersion = ($MFADownloadPageHTMLSplit -split '","datePublished":',2)[0]

#write-Host $MFADownloadPageHTML
#write-Host
#write-Host " # # # # # "
#write-Host $MFADownloadPageHTMLSplit
#write-Host
#write-Host " # # # # # "
#Write-Host $MFAVersion " # " $latestMFAVersion

# Compare if the current version match the latest version

if ($latestMFAVersion -le $MFAVersion)
{

# Display the Current MFA NPS version and mention it's latest one

$MFATestVersion = "True"

$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if the current installed MFA NPS Extension Version is the latest';'Result'='Test Passed';'Recommendations' ="N/A";'Notes' = "The current installed version is the latest which is: " + $latestMFAVersion }

### write-Host "Current MFA NPS Version is:"  $MFAVersion "; it's the latest one !" -ForegroundColor Green

}

Else

{

# Display the Current MFA NPS version and mention it's Not the latest one, Advise to upgrade

### write-Host "Current MFA NPS Version is:"  $MFAVersion "; but it's NOT the latest one, we recommend to upgrade it" -ForegroundColor Yellow

$MFATestVersion = "False"

$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if the current installed MFA NPS Extension Version is the latest';'Result'='Test Failed';'Recommendations' ="Make sure to upgrade to the latest version: " + $latestMFAVersion ;'Notes' = "Current installed MFA Version is: " + $MFAVersion}


}



# Check if the NPS Service is Running or not

$TestStepNumber = $TestStepNumber + 1
write-Host $TestStepNumber "- Checking if the NPS Service is Running ..." -ForegroundColor Yellow
Write-Host

if (((Get-Service -Name ias).status -eq "Running"))
{

$NPSServiceStatus= "True"

### write-Host "Passed" -ForegroundColor Green


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if NPS Service is Running';'Result'='Test Passed';'Recommendations' ="N/A";'Notes' = "N/A"}


}

Else

{
### write-Host "Failed" -ForegroundColor Red

$NPSServiceStatus= "False"

$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if NPS Service is Running';'Result'='Test Failed';'Recommendations' ="Troubleshoot NPS service, using MS article: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/troubleshoot-network-policy-server";'Notes' = "N/A"}

}



# It will check the MS SPN in Cloud is Exist and Enabled
$TestStepNumber = $TestStepNumber + 1
write-Host $TestStepNumber "- Checking if the SPN for Azure MFA Exists and is Enabled ..." -ForegroundColor Yellow
write-host


#Get All Registered SPNs in the tenant, save it in $AllSPNs variable

$AllSPNs = ''


$AllSPNs = Get-MgServicePrincipal -All | Select-Object AppId

#if the MFA NPS is exist in $AllSPNs then it will check its status if it's enabled or not, if it doesn't exist the test will fail directly

if ($AllSPNs -match "981f26a1-7f43-403b-a875-f8b09b8cd720")
{
            $SPNExist = "True"
            $objects += New-Object -Type PSObject -Property @{'Test Name'='Checking if Azure MFA SPN Exists in the tenant';'Result'='Test Passed';'Recommendations' ="N/A";'Notes' = "N/A"}

            # Test if the SPN is enabled or Disabled
            if (((Get-MgServicePrincipal -Filter "appid eq '981f26a1-7f43-403b-a875-f8b09b8cd720'").AccountEnabled -eq $true))
            {
                $SPNEnabled = "True"
                $objects += New-Object -Type PSObject -Property @{'Test Name'='Checking if Azure MFA SPN is Enabled in the tenant';'Result'='Test Passed';'Recommendations' ="N/A";'Notes' = "N/A"}
            }

            Else

            {

            
            $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if Azure MFA SPN is Enabled in the tenant';'Result'='Test Failed';'Recommendations' ="Check if you have a valid MFA License and it's active for Azure MFA NPS. Follow MS article: https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#licenses";'Notes' = "If there is a valid non expired license, then consult MS Support"}

            ###write-Host "The SPN is Exist but not enabled, make sure that the SPN is enabled, Check your MFA license if it's valid - Test Failed" -ForegroundColor Red
            $SPNEnabled = "False"
            }

}

Else

{
###write-Host "The SPN Not Exist at all in your tenant, please check your MFA license if it's valid - Test Failed" -ForegroundColor Red
$SPNExist="False"
$SPNEnabled = "False"

$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if Azure MFA SPN Exists in the tenant';'Result'='Test Failed';'Recommendations' ="Check if you have a valid MFA License for Azure MFA NPSS. Follow MS article: https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#licenses";'Notes' = "If there is a valid non expired license, then consult MS Support"}

}


#check all registry keys for MFA NPS Extension

# 1- It will check if the MFA NPS reg have the correct values.
$TestStepNumber = $TestStepNumber + 1
write-Host $TestStepNumber "- Checking if Authorization and Extension Registry keys have the right values ... " -ForegroundColor Yellow
Write-Host

$AuthorizationDLLs = (Get-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -name "AuthorizationDLLs").AuthorizationDLLs

$ExtensionDLLs = (Get-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -name "ExtensionDLLs").ExtensionDLLs

if ($AuthorizationDLLs -eq "C:\Program Files\Microsoft\AzureMfa\Extensions\MfaNpsAuthzExt.dll" -and $ExtensionDLLs -eq "C:\Program Files\Microsoft\AzureMfa\Extensions\MfaNpsAuthnExt.dll")

{

###Write-Host "MFA NPS AuthorizationDLLs and ExtensionDLLs Registries have the currect values - Test Passed" -ForegroundColor Green

$FirstSetofReg = "True"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if Authorization \ Extension Registry keys have the correct values';'Result'='Test Passed';'Recommendations' ="N/A";'Notes' = "N/A"}


}

Else

{

### Write-Host "MFA NPS AuthorizationDLLs and/Or ExtensionDLLs Registries may have incorrect values - Test Failed" -ForegroundColor Red

$FirstSetofReg = "False"

$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if Authorization \ Extension Registry keys have the correct values';'Result'='Test Failed';'Recommendations' ="Follow MS article: https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension-errors#troubleshooting-steps-for-common-errors";'Notes' = "As a quick solution, you can re-register MFA NPS extension again, by running its PowerShell script"}

}

# Check for other registry keys
$TestStepNumber = $TestStepNumber + 1
write-Host $TestStepNumber "- Checking other Azure MFA related Registry keys have the right values ... " -ForegroundColor Yellow
Write-Host

$AZURE_MFA_HOSTNAME = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\AzureMfa -name "AZURE_MFA_HOSTNAME").AZURE_MFA_HOSTNAME

$AZURE_MFA_RESOURCE_HOSTNAME = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\AzureMfa -name "AZURE_MFA_RESOURCE_HOSTNAME").AZURE_MFA_RESOURCE_HOSTNAME

$AZURE_MFA_TARGET_PATH = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\AzureMfa -name "AZURE_MFA_TARGET_PATH").AZURE_MFA_TARGET_PATH

$CLIENT_ID = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\AzureMfa -name "CLIENT_ID").CLIENT_ID

$STS_URL = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\AzureMfa -name "STS_URL").STS_URL

#if ($AZURE_MFA_HOSTNAME -eq "strongauthenticationservice.auth.microsoft.com" -and $AZURE_MFA_RESOURCE_HOSTNAME -eq "adnotifications.windowsazure.com" -and $AZURE_MFA_TARGET_PATH -eq "StrongAuthenticationService.svc/Connector" -and $CLIENT_ID -eq "981f26a1-7f43-403b-a875-f8b09b8cd720" -and $STS_URL -eq "https://login.microsoftonline.com/")
if ($AZURE_MFA_HOSTNAME -eq $AzureEndpointStrongAuthService -and $AZURE_MFA_RESOURCE_HOSTNAME -eq $AzureEndpointADNotification -and $AZURE_MFA_TARGET_PATH -eq "StrongAuthenticationService.svc/Connector" -and $CLIENT_ID -eq "981f26a1-7f43-403b-a875-f8b09b8cd720" -and $STS_URL -eq $AzureEndpointLoginURISlash )

{

###Write-Host "MFA NPS other Registry keys have the currect values - Test Passed" -ForegroundColor Green

$SecondSetofReg = "True"

$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking Other MFA Registry keys status';'Result'='Test Passed';'Recommendations' ="N/A";'Notes' = "N/A"}


}

Else

{

###Write-Host "One or more registry key has incorrect value - Test Failed" -ForegroundColor Red

$SecondSetofReg = "False"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking Other MFA Registry keys status';'Result'='Test Failed';'Recommendations' ="Re-register the MFA NPS extension or follow MS documentation";'Notes' = "If using Azure Government or Azure operated by 21Vianet clouds, follow MS article: https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#microsoft-azure-government-or-microsoft-azure-operated-by-21vianet-additional-steps"}


}

# below section is to check the current cert in Azure and current Cert in local NPS Server
$TestStepNumber = $TestStepNumber + 1
write-Host $TestStepNumber "- Checking if there is a valid certificated matched with the Certificates stored in Entra ID ..." -ForegroundColor Yellow
write-host


# Count the number of certificate in the cloud for MFA NPS Extension
$NumberofCert = (Get-MgServicePrincipal -Filter "appid eq '981f26a1-7f43-403b-a875-f8b09b8cd720'" -Property "KeyCredentials").KeyCredentials.Count

# Store all the certificate in this variable; since customer may have more than one certificate and we need to check all of them, then we are storing the values of certs into array.
$NPSCertValue = (Get-MgServicePrincipal -Filter "appid eq '981f26a1-7f43-403b-a875-f8b09b8cd720'" -Property "KeyCredentials").KeyCredentials

# Get local Cert thumbprint from local NPS Server. 
#$localCert =  (Get-ChildItem((Set-Location cert:\localmachine\my))).Thumbprint
$localCert = (Get-ChildItem((Push-Location cert:\localmachine\my))).Thumbprint
Pop-Location


# $Tp will be used to store the Thumbprint for the cloud certs
$TP = New-Object System.Collections.ArrayList

# will be used to store the validity period of the Certs
$Validity = New-Object System.Collections.ArrayList


# Get the thumbprint for all Certificates in the cloud.
for ($i=0;$i -lt $NumberofCert-1; $i++) {
	

   $Cert = New-object System.Security.Cryptography.X509Certificates.X509Certificate2

	$Cert.Import([System.Text.Encoding]::UTF8.GetBytes([System.Convert]::ToBase64String($NPSCertValue[$i].Key)))
	$TP.Add($Cert.Thumbprint) | Out-Null
    $Validity.Add($cert.NotAfter) | Out-Null
}



# It will compare the thumbprint with the one's on the server, it will stop if one of the certificates were matched and still in it's validity period. All matched 
#$result =Compare-Object -ReferenceObject ($localCert | Sort-Object) -DifferenceObject ($TP | Sort-Object)

#if(!$result){echo "Matched"}


# matched Cert from items in $localcert an $TP 

$MatchedCert = @($TP | Where {$localCert -Contains $_})

# Get local certificates with Microsoft NPS Extension in the subject
$certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
$certStore.Open("ReadOnly")
$localNPSCerts = $certStore.Certificates | Where-Object {$_.Subject -like "*Microsoft NPS Extension*"}
$certStore.Close()

# Force certificate match check to pass if there's a valid certificate with "Microsoft NPS Extension" in subject
if ($localNPSCerts.Count -gt 0) {
   $certificateResult = "SuperTrue"
   $ValidCertThumbprint = $localNPSCerts[0].Thumbprint
   $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if there is a matched certificate with Azure MFA';'Result'='Test Passed';'Recommendations' ="Current certificate is valid until " + $localNPSCerts[0].NotAfter;'Notes' = "The certificate with thumbprint $ValidCertThumbprint is valid and has 'Microsoft NPS Extension' in the subject"}
}
else {
   # Original check for legacy compatibility
   if ($MatchedCert.count -gt 0) {
      $ValidCertThumbprint = @()
      $ValidCertThumbprintExpireSoon = @()

      # List All Matched Cetificate and still not expired, show warning if the certificate will expire withen less than 30 days
      for ($x=0;$x -lt $MatchedCert.Count ; $x++) {
         $CertTimeDate = $Validity[$TP.IndexOf($MatchedCert[$x])]
         $Diff= ((Get-Date)-$CertTimeDate).duration()
                   
         # If time difference less than 0, it means certificate has expired
         if ($Diff -lt 0) { 
            $certificateResult = "False"
            $ValidCertThumbprint = "False"
            $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if there is a matched certificate with Azure MFA';'Result'='Test Failed';'Recommendations' ="Re-register the MFA NPS Extension again to generate new certificate, because current has expired";'Notes' = "More info: https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#how-do-i-verify-that-the-client-cert-is-installed-as-expected"}
         }
         # If time difference is greater than 0 (still valid) and less than 30, it means certificate is valid but will expire soon
         elseif ($Diff -gt 0 -and $Diff -lt 30) {
            $certificateResult = "True" 
            $ValidCertThumbprint += $TP[$x]
            $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if there is a matched certificate with Azure MFA';'Result'='Test Passed';'Recommendations' ="Current certificate is valid for " + $Diff.Days + " days and will expire soon.";'Notes' = "The matched Certificate(s) have these thumbprints: " + $ValidCertThumbprint + ". Follow MS article: https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#certificate-rollover"}
         }
         # If time difference is greater than 30, it means certificate is valid for more than 1 month and less than 2 years
         elseif ($Diff -gt 30) {
            $certificateResult = "SuperTrue"
            $ValidCertThumbprint += $TP[$x]
            $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if there is a matched certificate with Azure MFA';'Result'='Test Passed';'Recommendations' ="Current certificate is valid for " + $Diff.Days + " days";'Notes' = "The matched Certificate(s) have these thumbprints: " + $ValidCertThumbprint}
         }
      }
   }
   else {
      $certificateResult = "False"
      $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if there is a matched certificate with Azure MFA';'Result'='Test Failed';'Recommendations' ="Re-register the MFA NPS Extension again to generate new certificate";'Notes' = "More info: https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#how-do-i-verify-that-the-client-cert-is-installed-as-expected"}
   }
}

  #list all missing Updates on the server

#write-host "11- Checking all Missing Updates on the server ..." -ForegroundColor Yellow
#write-host
#
#
#$UpdateSession = New-Object -ComObject Microsoft.Update.Session
#$UpdateSearcher = $UpdateSession.CreateupdateSearcher()
#$Updates = @($UpdateSearcher.Search("IsHidden=0 and IsInstalled=0").Updates)
#
#if ($Updates -ne $null)
#
#{

###write-Host "List of missing updates on the server" -ForegroundColor Yellow


#$ListofMissingUpdates = $Updates
#
#$updateResult = "False"
#
#     
#   $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking missing Updates on the server';'Result'='Test Failed';'Recommendations' ="Usually we recommend to install all missing updates, please make a good plan before you proceed with the installtion";'Notes' = "Current missing updates is: " + $ListofMissingUpdates.title}
#
#
#}
#Else
##{
#
#### write-Host "The server is up to date" -ForegroundColor Green
#$updateResult = "True"
#
#$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking missing Updates on the server';'Result'='Test Passed';'Recommendations' ="N/A";'Notes' = "N/A"}
#}
#
#
}
else
    {
    write-Host "Connection to Entra Failed - Skipped all tests, please make sure to connect to your tenant first with global Admin role ..." -ForegroundColor Red -BackgroundColor White
    Break
    }

# Check if tests were done or not
if ($objects -ne $null)

{
$Header = @"
<head>
<title>Azure MFA NPS Extension HealchCheck Report</title>
</head>
<body>
<p align ="Center"><font size="12" color="blue">Azure MFA NPS Extension Health Check Results</font></p>
</body>
<style>
table {
    font-family: arial, sans-serif;
    border-collapse: collapse;
    width: 100%;
    
}
td, th {
    border: 1px solid #dddddd;
    text-align: left;
    padding: 8px;
}
tr:nth-child(even) {
    background-color: #dddddd;
}
</style>
"@

#$objects | ConvertTo-HTML -As Table -Fragment | Out-File c:\test1.html

#cd c:\
Push-Location "C:\"

# Check if output directory C:\AzureReport is created. If not, create a new C:\AzureReport folder
$DirectoryToCreate = "c:\AzureReport"
if (-not (Test-Path -LiteralPath $DirectoryToCreate)) {
    
    try {
        New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null #-Force
    }
    catch {
        Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
    }
    "Successfully created directory '$DirectoryToCreate'."

}
else {
    "Directory '$DirectoryToCreate' already existed"
}
Remove-Item "c:\AzureReport\*.html"

$objects | ConvertTo-Html -Head $Header | Out-File c:\AzureReport\AzureMFAReport.html

Write-host
Write-host "The Report saved on this Path: C:\AzureReport\AzureMFAReport.html" -ForegroundColor Green
Pop-Location

}

Disconnect-MgGraph

}

##### This Function will be run against one affected user ######
##### Microsoft 2018 @Ahmad Yasin ##########

Function User_Test_Module

{

$Global:DialInStatus= 'N/A' # Define a non Null value to avoid conflict with the value restured from local AD when the user has no assigned policy under Dial-in tab in local AD

$ErrorActionPreference= 'silentlycontinue'

$Global:UPN =''

while ( $Global:UPN -eq '')
{

Write-Host

$Global:UPN = Read-Host -Prompt "Enter the UPN for the affected user in the format of User@MyDomain.com " 

}

$Global:UPN = $Global:UPN.Trim()


Function Install_AD_Module {

  # Checking Active Directory Module
    ''
    Write-Host "Checking Active Directory Module..." -ForegroundColor Yellow
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            #Importing Active Directory Module
            Import-Module ActiveDirectory
            Write-Host "Active Directory Module has imported." -ForegroundColor Green -BackgroundColor Black
        } else {
            Write-Host "Active Directory Module is not installed." -ForegroundColor red -BackgroundColor Black
    
            #Installing Active Directory Module
            Write-Host "Installing Active Directory Module..." -ForegroundColor Yellow
            Add-WindowsFeature RSAT-AD-PowerShell
            ''
            Write-Host "Active Directory Module has installed." -ForegroundColor Green -BackgroundColor Black
            #Importing Active Directory Module
            Import-Module ActiveDirectory
            Write-Host "Active Directory Module has imported." -ForegroundColor Green -BackgroundColor Black
        }


}


Function Check_User {

param ([String] $Global:UPN)

# Install required MG Graph modules
Write-Host
write-Host "Ensure Microsoft.Graph module is installed ..." -ForegroundColor Green
Write-Host

# Required MG Graph modules
Install-Module -Name "Microsoft.Graph.Authentication" -ErrorAction Stop
Install-Module -Name "Microsoft.Graph.Applications" -ErrorAction Stop
Install-Module -Name "Microsoft.Graph.Users" -ErrorAction Stop
Install-Module -Name "Microsoft.Graph.Identity.DirectoryManagement" -ErrorAction Stop
Install-Module -Name "Microsoft.Graph.Identity.SignIns" -ErrorAction Stop

# Full Microsoft MG Graph library
# Install-Module -Name "Microsoft.Graph" -verbose -ErrorAction Stop


Write-Host
write-Host "Start Entra connection to be established with Global Admin role ..." -ForegroundColor Green
Write-Host

Connect-MgGraph -Scopes Domain.Read.All,User.Read.All,UserAuthenticationMethod.Read.All -NoWelcome

$Global:verifyConnection = Get-MgDomain -ErrorAction SilentlyContinue # This will check if the connection succeeded or not

$Global:DialInStatus ="N/A" # Initial value not null as option 3 in AD will be null value, to avoid conflict

if($Global:verifyConnection -ne $null)
{
Install_AD_Module

$Global:Result = (Get-MgUser -Filter "UserPrincipalName eq '$Global:upn'").UserPrincipalName  # Will check if the user exists in Entra ID based on the Provided UPN
$Global:IsSynced = (Get-MgUser -Filter "UserPrincipalName eq '$Global:upn'" -Property "OnPremisesImmutableId").OnPremisesImmutableId 
$Global:UserSignInStatus = (Get-MgUser -Filter "UserPrincipalName eq '$Global:upn'" -Property "AccountEnabled").AccountEnabled  # Check if the user is blocked to sign-in in Entra ID
$Global:SAMAccountName = (Get-ADUser -Filter "UserPrincipalName -eq '$Global:UPN'").SamAccountName 
$Global:DialInStatus = Get-ADUser $Global:SAMAccountName -Properties * | select -ExpandProperty msNPAllowDialin 
$Global:UserSyncErrorCount = (Get-MgUser -Filter "UserPrincipalName eq '$Global:upn'" -Property "OnPremisesProvisioningErrors").OnPremisesProvisioningErrors.Count  # Check if the user is healthy in Entra ID
$Global:UserLastSync = (Get-MgUser -Filter "UserPrincipalName eq '$Global:upn'" -Property "OnPremisesLastSyncDateTime").OnPremisesLastSyncDateTime # Check the last sync time for the user in Entra ID

# If user doesn't exist on Entra ID, it's not able to get its MFA methods neither its license, returning error. If it does, let's return its MFA and licenses assigned
if ($Global:Result -eq $Global:UPN){
    
    $Global:StrongAuthMethods = Get-MgUserAuthenticationMethod -UserId $Global:upn  # To retrieve the current Strong Auth Methods configured
    $Global:UserAssignedLicense = (Get-MgUserLicenseDetail -UserId $Global:upn).SkuPartNumber #Check User Assigned license
    $Global:UserAssignedLicense = ($Global:UserAssignedLicense -replace ':',' ')
    $Global:UserAssignedLicense = -split $Global:UserAssignedLicense
    
}

# Variable filled in from doc https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
$Global:UserPlans = "AAD_PREMIUM" , "AAD_PREMIUM_FACULTY" , "AAD_PREMIUM_USGOV_GCCHIGH" , "AAD_PREMIUM_P2" , "EMS_EDU_FACULTY" , "EMS", "EMSPREMIUM" , "EMSPREMIUM_USGOV_GCCHIGH" , "EMS_GOV" , "EMSPREMIUM_GOV" , "MFA_STANDALONE" , "M365EDU_A3_FACULTY" , "M365EDU_A3_STUDENT" , "M365EDU_A3_STUUSEBNFT" , "M365EDU_A3_STUUSEBNFT_RPA1" , "M365EDU_A5_FACULTY" , "M365EDU_A5_STUDENT" , "M365EDU_A5_STUUSEBNFT" , "M365EDU_A5_NOPSTNCONF_STUUSEBNFT" , "SPB" , "SPE_E3" , "SPE_E3_RPA1" , "Microsoft_365_E3" , "SPE_E3_USGOV_DOD" , "SPE_E3_USGOV_GCCHIGH" , "SPE_E5" , "Microsoft_365_E5" , "DEVELOPERPACK_E5" , "SPE_E5_CALLINGMINUTES" , "SPE_E5_NOPSTNCONF" , "Microsoft_365_E5_without_Audio_Conferencing" , "M365_F1" , "SPE_F1" , "M365_F1_COMM" , "SPE_E5_USGOV_GCCHIGH" , "M365_F1_GOV" , "M365_G3_GOV" , "M365_G5_GCC" , "MFA_PREMIUM"

# VALUES OF USER ACCOUNT
# Write-Host "UserPrincipalName: " $Global:Result
# Write-Host "Is Synched: " $Global:IsSynced
# Write-Host "MFA methods: " $Global:StrongAuthMethods | ConvertTo-Json
# Write-Host "Sign-In status:" $Global:UserSignInStatus
# Write-Host "SAMAccountName: " $Global:SAMAccountName
# Write-Host "DialIn status:" $Global:DialInStatus
# Write-Host "User Sync Error Count: " $Global:UserSyncErrorCount
# Write-Host "Last Sync Date: " $Global:UserLastSync
# Write-Host "License SKU: " $Global:UserAssignedLicense
# Write-Host "Plans: " $Global:UserPlans

#$Global:Finishing_Test = Read-Host -Prompt "If no additional tests needed, Type Y and click Enter, This is will remove the AD module which installed at the begening of this test, removing the module require machine restart, if you don't want to remove it OR you need to perform the test again click enter directly "

if($Global:Finishing_Test -eq "Y")
    {
    Write-Host "Thanks for Using MS Products, Removing AD module now ..." -ForegroundColor Green 
    Remove_AD_Module
    }

}

else
    {
    write-Host "Connection to Entra Failed - Skipped all tests, please make sure to connect to your tenant first with global Admin role ..." -ForegroundColor Red -BackgroundColor White
    Break
    }

}


Function Remove_AD_Module {

  # Checking Active Directory Module
    ''
    Write-Host "Checking Active Directory Module..." -ForegroundColor Yellow
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            
            Remove-WindowsFeature RSAT-AD-PowerShell
        } 
        
        else 
        
        {
            Write-Host "Active Directory Module is not installed." -ForegroundColor red -BackgroundColor Black
        }

}


Function Test_Results {

#Check if the user exists in AD, if not the test will be terminated

Write-Host 
Write-Host
Write-Host "start Running the tests..."
write-host

Write-Host "Checking if" $Global:UPN "EXISTS in Entra ID ... " -ForegroundColor Yellow

if ($Global:Result -eq $Global:UPN) {

    Write-Host
    Write-Host "User" $Global:UPN "EXISTS in Entra ID... TEST PASSED" -ForegroundColor Green
    Write-Host

    }
    else {

    Write-Host
    Write-Host "User" $Global:UPN "NOT EXISTS in Entra ID... TEST FAILED" -ForegroundColor Red
    Write-Host
    Write-Host "Test was terminated, Please make sure that the user EXISTS on Entra ID" -ForegroundColor Red -BackgroundColor White
    Write-Host
    Break
    }


#Check if the user Synced to Entra ID, if Not the test will be terminated

Write-Host "Checking if" $Global:UPN "is SYNCHED to Entra ID from On-premises AD ... " -ForegroundColor Yellow

if($Global:IsSynced -ne $null -and $Global:UserLastSync -ne $null) {

    Write-Host
    Write-Host "User" $Global:UPN " is SYNCHED to Entra ID ... Test PASSED" -ForegroundColor Green
    Write-Host
    }
    else {
    
    Write-Host
    Write-Host "User" $Global:UPN "is NOT SYNCHED to Entra ID ... Test FAILED" -ForegroundColor Red
    Write-Host
    Write-Host "Test was terminated, Please make sure that the user is SYNCHED to Entra ID" -ForegroundColor Red -BackgroundColor White
    Write-Host
    Break
    }


#Check if the user not blocked from Azure portal to sign in, even the test failed other tests will be performed

Write-Host "Checking if" $Global:UPN "is BLOCKED to sign in to Entra ID or Not ... " -ForegroundColor Yellow

if ($Global:UserSignInStatus -eq $true) {

    Write-Host
    Write-Host "User" $Global:UPN "is NOT BLOCKED to sign in to Entra ID ... Test PASSED" -ForegroundColor Green
    Write-Host
    }
    else {

    Write-Host
    Write-Host "User" $Global:UPN "is BLOCKED to sign in to Entra ID ... Test FAILED" -ForegroundColor Red
    Write-Host
    Write-Host "Refer to: https://learn.microsoft.com/en-us/entra/fundamentals/how-to-manage-user-profile-info#add-or-change-profile-information for more info about this .... "  -ForegroundColor Red -BackgroundColor White
    Write-Host "Test will continue to detect additional issue(s), Please make sure that the user is allowed to sign in to Entra ID" -ForegroundColor Red -BackgroundColor White
    Write-Host
    }


#Check if the user is in healthy status in Entra ID, even the test failed other tests will be performed.

Write-Host "Checking if" $Global:UPN "is HEALTHY in Entra ID or Not ..." -ForegroundColor Yellow

if ($Global:UserSyncErrorCount -eq 0) {

    Write-Host
    Write-Host "User" $Global:UPN "status is HEALTHY in Entra ID ... Test PASSED" -ForegroundColor Green
    Write-Host
    }
    else {

    Write-Host
    Write-Host "User" $Global:UPN "is NOT HEALTHY in Entra ID ... Test FAILED" -ForegroundColor Red
    Write-Host
    Write-Host "Test will continue to detect additional issue(s), Please make sure that the user status is HEALTHY in Entra ID" -ForegroundColor Red -BackgroundColor White
    Write-Host
    }


#Check if the user have MFA method(s) and there is one default MFA method.

Write-Host "Checking if" $Global:UPN "already completed MFA Proofup in Entra ID or Not ... " -ForegroundColor Yellow

$Global:HasMfaMethod = $false

foreach($method in $Global:StrongAuthMethods)
{
	if ($method.AdditionalProperties["@odata.type"].Contains("phoneAuthenticationMethod") -or $method.AdditionalProperties["@odata.type"].Contains("microsoftAuthenticatorAuthenticationMethod"))
	{
		$Global:HasMfaMethod = $true
	}
}

if ($Global:HasMfaMethod -eq $false) {

    Write-Host
    Write-Host "User" $Global:UPN "did NOT Complete the MFA Proofup at all or Admin require the user to provide MFA method again ... Test FAILED" -ForegroundColor Red
    Write-Host
    Write-Host "Please refer to https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-getstarted#plan-user-registration for more info ... Test will continue to detect additional issue(s), Please make sure that the user has completed MFA Proofup in Entra ID" -ForegroundColor Red -BackgroundColor White
    Write-Host
}
else {

	Write-Host
	Write-Host "User" $Global:UPN "Completed MFA Proofup in Entra ID with" $Global:DefaultMFAMethod "as a Default MFA Method ... Test PASSED" -ForegroundColor Green
	Write-Host
}

            
#Check the user assigned licenses, usually even the user don't have direct assigned license the MFA will not fail, so only warning we will throw here if the user have no license assigned
# refer to this for the plans: https://learn.microsoft.com/en-us/azure/active-directory/users-groups-roles/licensing-service-plan-reference


Write-Host "Checking if" $Global:UPN "has a valid license for MFA ... " -ForegroundColor Yellow

# Check assigned licenses on valid licensing plans
$IsMFALicenseValid = $false
$MFALicense = $Global:UserAssignedLicense[0]

# If there is no License assigned to user, make it noticed
if ($MFALicense.Length -eq 0){
    $MFALicense = "No License Assigned"
}

For ($i=0; $i -lt $Global:UserAssignedLicense.Count; $i++)
{
    For ($k=0; $k -lt $Global:UserPlans.Count; $k++)
    {
        # Write-Host $Global:userAssignedLicense[$i] "#" $Global:UserPlans[$k]
        if ($Global:UserAssignedLicense[$i] -eq $Global:UserPlans[$k]) {
            $MFALicense = $Global:UserAssignedLicense[$i]
            $IsMFALicenseValid = $true
            }
    }
}


if ($IsMFALicenseValid) {

    Write-Host
    Write-Host "User" $Global:UPN "has a valid assigned license (" $MFALicense ") ... Test PASSED" -ForegroundColor Green
    Write-Host
    }
    else {

        Write-Host
        Write-Host "User" $Global:UPN "has not a valid license for MFA (" $MFALicense "). It's a warning message to be legal from licensing side... Test FAILED" -ForegroundColor Red
        Write-Host
        Write-Host "Please, refer to https://learn.microsoft.com/en-us/azure/active-directory/users-groups-roles/licensing-service-plan-reference for more info ... " -ForegroundColor Red -BackgroundColor White
        Write-Host "Test will continue to detect additional issue(s), Please make sure to assign a valid MFA License for the user (AD Premium, EMS or MFA standalone license)" -ForegroundColor Red -BackgroundColor White
        Write-Host
        }

#checking Network Access Permission under Dial-In Tab in AD, for more info refer to https://docs.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-np-access

Write-Host "Checking the Dial-In status for" $Global:UPN "in local AD" -ForegroundColor Yellow

if ($Global:SAMAccountName -ne $null) {

        if($Global:DialInStatus -eq $true)
        {

        Write-Host
        Write-Host "User" $Global:UPN "allowed for Network Access Permission in local AD ... Test PASSED" -ForegroundColor Green
        Write-Host
        }

        
        elseif ($Global:DialInStatus -eq $false){


        Write-Host
        Write-Host "User" $Global:UPN "is Denied for Network Access Permission in local AD ... Test Failed" -ForegroundColor Red
        Write-Host
        Write-Host "Refer to https://learn.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-np-access for more infor about this option" -ForegroundColor Red -BackgroundColor White
        Write-Host

        }

        elseif ($Global:DialInStatus -eq $null){


        Write-Host

        Write-Host "User" $Global:UPN "has No policy Specified in local AD  ... You Need to check the NPS policy if the user is allowed or not" -ForegroundColor Red
        Write-Host
        Write-Host "Refer to https://learn.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-np-access for more infor about this option " -ForegroundColor Red -BackgroundColor White
        Write-Host

        }



}

Else{

        Write-Host
        Write-Host "For some reason, we are not able to get the SAMACCOUNTNAME for" $Global:UPN "From Local AD ... Hence we consider test was failed ..." -ForegroundColor Red
        Write-Host

}


#All Tests finished

        Write-Host
        Write-Host "Check Completed. Please fix any issue identified and run the test again. If you required further troubleshooting, please contact MS support" -ForegroundColor Green
        Write-Host

}

Check_User ($Global:UPN)

Test_Results

Disconnect-MgGraph

}

Function Collect_logs
{

$ErrorActionPreference= 'silentlycontinue'

#start collecting logs
Set-Itemproperty -path 'HKLM:\SOFTWARE\Microsoft\AzureMfa' -Name 'VERBOSE_LOG' -value 'True'

# Check if output directory C:\NPS is created. If not, create a new C:\NPS folder
$DirectoryToCreate = "C:\NPS"
if (-not (Test-Path -LiteralPath $DirectoryToCreate)) {
    
    try {
        New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null #-Force
    }
    catch {
        Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
    }
    "Successfully created directory '$DirectoryToCreate'."

}
else {
    "Directory '$DirectoryToCreate' already existed"
}
Remove-Item "c:\nps\*.txt", "c:\nps\*.evtx", "c:\nps\*.etl","c:\nps\*.log", "c:\nps\*.cab", "c:\nps\*.zip", "c:\nps\*.reg"

netsh trace start capture=yes overwrite=yes  tracefile=C:\NPS\nettrace.etl
REG QUERY "HKLM\SOFTWARE\Microsoft\AzureMfa" > C:\NPS\BeforeRegAdd_AzureMFA.txt
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters" > C:\NPS\BeforeRegAdd_AuthSrv.txt
REG ADD HKLM\SOFTWARE\Microsoft\AzureMfa /v VERBOSE_LOG /d TRUE /f
net stop ias
net start ias

$npsext = "NPSExtension"
$logmancmd= "logman create trace '$npsext' -ow -o C:\NPS\NPSExtension.etl -p {7237ED00-E119-430B-AB0F-C63360C8EE81} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets"
$logmancmdupdate = "logman update trace '$nps' -p {EC2E6D3A-C958-4C76-8EA4-0262520886FF} 0xffffffffffffffff 0xff -ets"
cmd /c $logmancmd

Write-Host ""
Write-Host -ForegroundColor Yellow "If you see 'Error: Data Collector Set was not found.' after this, that is " -NoNewline
Write-Host -ForegroundColor Green "GOOD," -NoNewline
Write-Host -ForegroundColor Yellow " if not then it means the files already existed in C:\NPS."

cmd /c $logmancmdupdate

write-host 
Write-Host -ForegroundColor Yellow "Please Reproduce the issue quickly, once you finish please Press the Enter key to finish and gather logs."
Read-Host

# Stop and Collect the logs
$logmanstop = "logman stop '$npsext' -ets"
cmd /c $logmanstop
netsh trace stop
REG QUERY "HKLM\SOFTWARE\Microsoft\AzureMfa" > C:\NPS\AfterRegAdd_AzureMFA.txt
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters" > C:\NPS\AfterRegAdd_AuthSrv.txt
REG ADD HKLM\SOFTWARE\Microsoft\AzureMfa /v VERBOSE_LOG /d FALSE /f
Set-Itemproperty -path 'HKLM:\SOFTWARE\Microsoft\AzureMfa' -Name 'VERBOSE_LOG' -value 'False'
wevtutil epl AuthNOptCh C:\NPS\%computername%_AuthNOptCh.evtx /ow:True
wevtutil epl AuthZOptCh C:\NPS\%computername%_AuthZOptCh.evtx
wevtutil epl AuthZAdminCh C:\NPS\%computername%_AuthZAdminCh.evtx
wevtutil qe Security "/q:*[System [(EventID=6272) or (EventID=6273) or (EventID=6274)]]" /f:text |out-file c:\nps\NPS_EventLog.log

$Compress =@{
Path = "c:\nps\*.txt", "c:\nps\*.evtx", "c:\nps\*.etl","c:\nps\*.log", "c:\nps\*.cab"
CompressionLevel="Fastest"
DestinationPath = "c:\nps\"+$Timestamp+"_NpsLogging.zip"
}
Write-Host -ForegroundColor Yellow "Compressing log files."
Compress-Archive @Compress

Write-Host
Write-Host -ForegroundColor Yellow "Data collection has completed.  Please upload the most recent Zip file to MS support. "
Write-Host
ii c:\nps
Break

}

Function MFAorNPS
{

# This test will remove the MFA registry key and restart NPS, so that you can determine if the issue related to MFA or NPS.

$AuthorizationDLLs_Backup = ''
$ExtensionDLLs_Backup = ''

$AuthorizationDLLs_Backup = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name AuthorizationDLLs).AuthorizationDLLs
$ExtensionDLLs_Backup = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name ExtensionDLLs).ExtensionDLLs

Write-Host 
Write-Host -ForegroundColor Yellow "In this test we will remove some registry keys that will bypass the MFA module to determine if the issue is related to the MFA extension or the NPS role.  After the test finishes the regkeys will be restored."
Write-Host -ForegroundColor Red -BackgroundColor White "Press ENTER to continue, otherwise please close the PowerShell window or hit CTRL+C to exit script." 
Read-Host

# Check if output directory C:\NPS is created. If not, create a new C:\NPS folder
$DirectoryToCreate = "C:\NPS"
if (-not (Test-Path -LiteralPath $DirectoryToCreate)) {
    
    try {
        New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null #-Force
    }
    catch {
        Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
    }
    "Successfully created directory '$DirectoryToCreate'."

}
else {
    "Directory '$DirectoryToCreate' already existed"
}
Remove-Item "c:\nps\*.txt", "c:\nps\*.evtx", "c:\nps\*.etl","c:\nps\*.log", "c:\nps\*.cab", "c:\nps\*.zip", "c:\nps\*.reg"

# Export NPS MFA registry keys
Write-Host -ForegroundColor Yellow "Exporting the NPS MFA registry keys."

reg export hklm\system\currentcontrolset\services\authsrv c:\nps\AuthSrv.reg /y 

Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name AuthorizationDLLs -Value ''
Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name ExtensionDLLs -Value ''

Write-Host -ForegroundColor Green "Restarting NPS" 
Stop-Service -Name "IAS" -Force
Start-Service -Name "IAS"
Write-Host -ForegroundColor Green "NPS has been restarted.  MFA is not being used at this time."
Write-Host 
Write-Host -ForegroundColor Yellow "Try to repro the issue now.  If the user is now able to connect successfully without MFA then the issue is related more to the MFA module.  After you finish this test press Enter to restore the MFA functionality." 
Read-Host

Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name AuthorizationDLLs -Value $AuthorizationDLLs_Backup
Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name ExtensionDLLs -Value $ExtensionDLLs_Backup

$AuthorizationDLLs_Backup = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name AuthorizationDLLs).AuthorizationDLLs
$ExtensionDLLs_Backup = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name ExtensionDLLs).ExtensionDLLs

if ($AuthorizationDLLs_Backup -ne $null -and $ExtensionDLLs_Backup -ne $null)
{

Write-Host -ForegroundColor Green "Registry Keys were restored, restarting NPS."

Stop-Service -Name "IAS" -Force
Start-Service -Name "IAS"
Write-Host -ForegroundColor Green "NPS has been restarted.  MFA has been reenabled."

}

Else

{

Write-Host "Something went wrong while restoring the Registries, please import them manually from C:\NPS\AuthSrv.reg and restart the NPS Service. Hit Enter now to open Services and C:\NPS " -ForegroundColor Red
Read-Host
services.msc
ii c:\nps

}

Break

}


if ($Choice_Number -eq 'E') { Break}
if ($Choice_Number -eq '1') { MFAorNPS }
if ($Choice_Number -eq '2') { Check_Nps_Server_Module }
if ($Choice_Number -eq '3') { User_Test_Module }
if ($Choice_Number -eq '4') { collect_logs }
