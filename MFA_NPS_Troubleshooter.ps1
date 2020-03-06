Write-Host "*********************************************************************************"

Write-Host "**** Welcome to MFA NPS Extension Troubleshooter Tool ****" -ForegroundColor Green

Write-Host "**** This Tool will help you to troubleshoot MFA NPS Extension Knows issues ****" -ForegroundColor Green

Write-Host "**** Tool Version is 1.0, Make Sure to Visit MS site to get the latest version ****" -ForegroundColor Green

Write-Host "**** Thank you for Using MS Products, Microsoft @2019 ****" -ForegroundColor Green

Write-Host "*******************************************************************************"

Write-Host

Write-Host

Write-Host

Write-Host " Please Choose one of the tests below: " -ForegroundColor Yellow
Write-Host
Write-Host " (0) Isolate the Cause of the issue: if it's NPS or MFA issue (Recomended)... " -ForegroundColor Green
Write-Host
Write-Host " (1) All users not able to use MFA NPS Extension ... " -ForegroundColor Green
Write-Host
Write-Host " (2) Specific User not able to use MFA NPS Extension ... " -ForegroundColor Green
Write-Host
Write-Host " (3) Collect Logs to contact MS support ... " -ForegroundColor Green
Write-Host

$Choice_Number =''
$Choice_Number = Read-Host -Prompt "Based on which test you need to run, please type 0,1,2 or 3, E to exit the test, then click enter " 

while ( !($Choice_Number -eq '0' -or $Choice_Number -eq '1' -or $Choice_Number -eq '2' -or $Choice_Number -eq '3' -or$Choice_Number -eq 'E'))
{

$Choice_Number = Read-Host -Prompt "Invalid Option, Based on which test you need to run, please type 1 or 2, E to exit the test, then click enter " 

}




##### This Function will be run against against MFA NPS Server ######
##### Microsoft 2018 @Ahmad Yasin ##########

Function Check_Nps_Server_Module {

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
$TCPLogin = $False
$TCPAdnotification = $False
$DNSLogin= $False
$DNSADNotification =$False


Connect-MsolService

$verifyConnection = Get-MsolDomain -ErrorAction SilentlyContinue

if($verifyConnection -ne $null)
{
 
write-Host "Connection established Succesfully - Starting the HealthCheck Process ..." -ForegroundColor Green
Write-Host
Write-Host
write-host

# Check the accessibility to login.microsoftonline.com and adnotifications.windowsazure.com

write-Host "1- Checking Accessibility to https://login.microsoftonline.com ..." -ForegroundColor Yellow
write-Host

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

########################################################################
$TCPLogin = (RunPSScript -PSScript "Test-NetConnection -ComputerName  login.microsoftonline.com -Port 443").TcpTestSucceeded
$DNSLogin = (RunPSScript -PSScript "Test-NetConnection -ComputerName  login.microsoftonline.com -Port 443").NameResolutionSucceeded

########################################################################
$TCPAdnotification = (RunPSScript -PSScript "Test-NetConnection -ComputerName adnotifications.windowsazure.com -Port 443").TcpTestSucceeded
$DNSADNotification = (RunPSScript -PSScript "Test-NetConnection -ComputerName adnotifications.windowsazure.com -Port 443").NameResolutionSucceeded






#######################################################################

if ($TCPLogin -and $DNSLogin)
{

### write-Host "Test login.microsoftonline.com accessibility Passed" -ForegroundColor Green 


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Access To https://login.MicrosoftOnline.Com';'Result'='Test Passed';'Recomendations' ="N/A";'Notes' = "N/A"}


$loginAccessResult = "True"

}

Else

{
### write-Host "Test login.microsoftonline.com accessibility Failed" -ForegroundColor Red

$loginAccessResult = "False"
$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking accessiblity to https://login.MicrosoftOnline.Com';'Result'='Test Failed';'Recomendations' ="Follow MS article for remediation: https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#network-requirements";'Notes' = "This will cause MFA Methods to fail"}


}


write-Host "2- Checking Accessibility to https://adnotifications.windowsazure.com ..." -ForegroundColor Yellow
Write-Host


if ($TCPAdnotification -and $DNSADNotification)

{

### write-Host "Test adnotifications.windowsazure.com accessibility Passed" -ForegroundColor Green

$NotificationaccessResult = "True"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking accessiblity to https://adnotifications.windowsazure.com';'Result'='Test Passed';'Recomendations' ="N/A";'Notes' = "N/A"}



}

Else

{
### write-Host "Test https://adnotifications.windowsazure.com accessibility Failed" -ForegroundColor Red

$NotificationaccessResult = "False"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking accessiblity to adnotifications.windowsazure.com accessibility';'Result'='Test Failed';'Recomendations' ="Follow MS article for remediation:https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#network-requirements";'Notes' = "This will cause MFA Methods to fail"}


}

write-Host "3- Checking MFA version ... " -ForegroundColor Yellow
Write-Host

# Get MFA NPS installed version
$MFAVersion = Get-WmiObject Win32_Product -Filter "Name like 'NPS Extension For Azure MFA'" | Select-Object -ExpandProperty Version

# Get the latest version of MFA NPS Extension

$web = New-Object Net.WebClient
$latesMFAVersion = $web.DownloadString("https://www.microsoft.com/en-us/download/details.aspx?id=54688")

# Compare if the current version match the latest version

if ($latesMFAVersion -match $MFAVersion)
{

# Display the Current MFA NPS version and mention it's latest one

$MFATestVersion = "True"



$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if the current installed MFA NPS Extension Version is the latest';'Result'='Test Passed';'Recomendations' ="N/A";'Notes' = "The current installed version is the latest which is: " + $MFAVersion}



### write-Host "Current MFA NPS Version is:"  $MFAVersion "; it's the latest one !" -ForegroundColor Green

}

Else

{

# Display the Current MFA NPS version and mention it's Not the latest one, Advise to upgrade

### write-Host "Current MFA NPS Version is:"  $MFAVersion "; but it's NOT the latest one, we recomend to upgrade it" -ForegroundColor Yellow

$MFATestVersion = "False"

$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if the current installed MFA NPS Extension Version is the latest';'Result'='Test Failed';'Recomendations' ="Make sure to Upgrade to the latest version";'Notes' = "Current installed MFA Version is: " +$MFAVersion}


}



# Check if the NPS Service is Running or not


write-Host "4- Checking if the NPS Service is Running ..." -ForegroundColor Yellow
Write-Host

if (((Get-Service -Name ias).status -eq "Running"))
{

$NPSServiceStatus= "True"

### write-Host "Passed" -ForegroundColor Green


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if NPS Service is Running';'Result'='Test Passed';'Recomendations' ="N/A";'Notes' = "N/A"}


}

Else

{
### write-Host "Failed" -ForegroundColor Red

$NPSServiceStatus= "False"

$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if NPS Service is Running';'Result'='Test Failed';'Recomendations' ="MS Article may help: https://blogs.technet.microsoft.com/sbs/2009/02/20/the-network-policy-server-service-ias-fails-to-start-or-be-installed/";'Notes' = "N/A"}

}



# It will check the MS SPN in Cloud is Exist and Enabled

write-Host "5- Checking if the SPN for Azure MFA is Exist and Enabled ..." -ForegroundColor Yellow
write-host


#Get All Registered SPNs in the tenant, save it in $AllSPNs variable

$AllSPNs = ''

$AllSPNs = Get-MsolServicePrincipal | select AppPrincipalId 

#if the MFA NPS is exist in $AllSPNs then it will check it's status if it's enabled or not, if it's not exist the test will faile directly

if ($AllSPNs -match "981f26a1-7f43-403b-a875-f8b09b8cd720")

{
            $SPNExist = "True"

            
            $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if Azure MFA SPN is Exist in the tenant';'Result'='Test Passed';'Recomendations' ="N/A";'Notes' = "N/A"}


            # Test if the SPN is enabled or Disabled
            if (((Get-MsolServicePrincipal -AppPrincipalId 981f26a1-7f43-403b-a875-f8b09b8cd720).AccountEnabled -eq "True"))
 
            {

            $SPNEnabled = "True"
            
            $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if Azure MFA SPN is Enabled in the tenant';'Result'='Test Passed';'Recomendations' ="N/A";'Notes' = "N/A"}


            ###write-Host "SPN is Exist and Enabled - Test Passed" -ForegroundColor Green


            }

            Else

            {

            
            $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if Azure MFA SPN is Enabled in the tenant';'Result'='Test Failed';'Recomendations' ="Check if you have a valid MFA License and it's active for Azure MFA NPS: https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#licenses";'Notes' = "If there is a valid Non expired license, then consult MS Support"}

            ###write-Host "The SPN is Exist but not enabled, make sure that the SPN is enabled, Check your MFA license if it's valid - Test Failed" -ForegroundColor Red
            $SPNEnabled = "False"
            }

}

Else

{
###write-Host "The SPN Not Exist at all in your tenant, please check your MFA license if it's valid - Test Failed" -ForegroundColor Red
$SPNExist="False"
$SPNEnabled = "False"

$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if Azure MFA SPN is Exist in the tenant';'Result'='Test Failed';'Recomendations' ="Check if you have a valid MFA License for Azure MFA NPS: https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#licenses";'Notes' = "If there is a valid Non expired license, then consult MS Support"}

}


#check all registry keys for MFA NPS Extension

# 1- It will check if the MFA NPS reg have the correct values.

Write-Host "6- Checking if Authorization and Extension Registry keys have the right values ... " -ForegroundColor Yellow
Write-Host

$AuthorizationDLLs = (Get-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -name "AuthorizationDLLs").AuthorizationDLLs


$ExtensionDLLs = (Get-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -name "ExtensionDLLs").ExtensionDLLs

if ($AuthorizationDLLs -eq "C:\Program Files\Microsoft\AzureMfa\Extensions\MfaNpsAuthzExt.dll" -and $ExtensionDLLs -eq "C:\Program Files\Microsoft\AzureMfa\Extensions\MfaNpsAuthnExt.dll")

{

###Write-Host "MFA NPS AuthorizationDLLs and ExtensionDLLs Registries have the currect values - Test Passed" -ForegroundColor Green

$FirstSetofReg = "True"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if Auth\Extension Registries have the correct values';'Result'='Test Passed';'Recomendations' ="N/A";'Notes' = "N/A"}


}

Else

{

### Write-Host "MFA NPS AuthorizationDLLs and/Or ExtensionDLLs Registries may have incorrect values - Test Failed" -ForegroundColor Red

$FirstSetofReg = "False"

$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if Auth\Extension Registries have the correct values';'Result'='Test Failed';'Recomendations' ="Follow MS article: https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension-errors#troubleshooting-steps-for-common-errors";'Notes' = "As a quick solution, you can Re-register MFA extension again"}

}

# 2- Check for other registry keys

Write-Host "7- Checking other Azure MFA related Registry keys have the right values ... " -ForegroundColor Yellow
Write-Host

$AZURE_MFA_HOSTNAME = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\AzureMfa -name "AZURE_MFA_HOSTNAME").AZURE_MFA_HOSTNAME

$AZURE_MFA_TARGET_PATH = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\AzureMfa -name "AZURE_MFA_TARGET_PATH").AZURE_MFA_TARGET_PATH

$CLIENT_ID = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\AzureMfa -name "CLIENT_ID").CLIENT_ID

$STS_URL = (Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\AzureMfa -name "STS_URL").STS_URL

if ($AZURE_MFA_HOSTNAME -eq "adnotifications.windowsazure.com" -and $AZURE_MFA_TARGET_PATH -eq "StrongAuthenticationService.svc/Connector" -and $CLIENT_ID -eq "981f26a1-7f43-403b-a875-f8b09b8cd720" -and $STS_URL -eq "https://login.microsoftonline.com/")

{

###Write-Host "MFA NPS other Registry keys have the currect values - Test Passed" -ForegroundColor Green

$SecondSetofReg = "True"

$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking Other MFA regstries status';'Result'='Test Passed';'Recomendations' ="N/A";'Notes' = "N/A"}


}

Else

{

###Write-Host "One or more registry key has incorrect value - Test Failed" -ForegroundColor Red

$SecondSetofReg = "False"


$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking Other MFA regstries status';'Result'='Test Failed';'Recomendations' ="Re-register the MFA extension or Consult MS Support";'Notes' = "N/A"}


}

# below section is to check the current cert in Azure and current Cert in local NPS Server

Write-Host "8- Checking if there is a valid certificated matched with the Certificates stored in Azure AD ..." -ForegroundColor Yellow
write-host


#Count the number of certificate in the cloud for MFA NPS Extension
$NumberofCert = (Get-MsolServicePrincipalCredential -AppPrincipalId "981f26a1-7f43-403b-a875-f8b09b8cd720" -ReturnKeyValues 1).count

#store all the certificate in this variable;since customer may have more than one certificate and we need to check all of them, then we are storing the values of certs into array.
$NPSCertValue =  (Get-MsolServicePrincipalCredential -AppPrincipalId "981f26a1-7f43-403b-a875-f8b09b8cd720" -ReturnKeyValues 1).Value

# Get local Cert thumbprint from local NPS Server. 
$localCert =  (Get-ChildItem((Set-Location cert:\localmachine\my))).Thumbprint

# $Tp will be used to store the Thumbprint for the cloud certs
$TP = New-Object System.Collections.ArrayList

# will be used to store the validity period of the Certs
$Validity = New-Object System.Collections.ArrayList


# Get the thumbprint for all Certificates in the cloud.
for ($i=0;$i -lt $NumberofCert-1; $i++) {
	

   $Cert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2

	$Cert.Import([System.Text.Encoding]::UTF8.GetBytes( $NPSCertValue[$i]))
	$TP.Add($Cert.Thumbprint) | Out-Null
    $Validity.Add($cert.NotAfter) | Out-Null
}



# It will compare the thumbprint with the one's on the server, it will stop if one of the certificates were matched and still in it's validity period. All matched 
#$result =Compare-Object -ReferenceObject ($localCert | Sort-Object) -DifferenceObject ($TP | Sort-Object)

#if(!$result){echo "Matched"}


# matched Cert from items in $localcert an $TP 

$MatchedCert = $TP | Where {$localCert -Contains $_}

if ($MatchedCert.count -gt 0)
   {

   $ValidCertThumbprint = @()
   $ValidCertThumbprintExpireSoon = @()

# List All Matched Cetificate and still not expired, show warning if the certificate will expire withen less than 30 days

for ($x=0;$x -lt $MatchedCert.Count ; $x++) {
	
   
                   $CertTimeDate = $Validity[$TP.IndexOf($MatchedCert[$x])]
   
  
                   $Diff= ((Get-Date)-$CertTimeDate).duration()

                   if ($Diff -lt 0) 
                   
                   { 
                   
                  ### Write-Host 'No Valid Cert' -ForegroundColor Red 
                   
                   $certificateResult = "False"
                   $ValidCertThumbprint = "False"
                   
$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if there is a matched certificate with Azure MFA';'Result'='Test Failed';'Recomendations' ="Re-register the MFA NPS Extension again to generate new certifictae, more info: https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#how-do-i-verify-that-the-client-cert-is-installed-as-expected";'Notes' = "N/A"}

                   }

                   Elseif ($Diff -gt 0 -and $Diff -lt 30 )
                   {

                  ### Write-Host 'Certificate valid but will expire soon'

                 ###  Write-host
    
                  #### Write-Host $TP[$x] $Diff -ForegroundColor Green
                   
                   $certificateResult = "True" 
                   $ValidCertThumbprint += $TP[$x]

                   
                   }

                   Elseif ($Diff -gt 30 )

                   {

                  ### Write-Host 'Certificate(s) Matched, Below the Thumprint(s):'

                  #### Write-host

                  ### Write-Host $TP[$x] -ForegroundColor Green 

                   $certificateResult = "SuperTrue"

                   $ValidCertThumbprint += $TP[$x]

                                   


                   }
                   

  }

  $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking if there is a matched certificate with Azure MFA';'Result'='Test Passed';'Recomendations' ="N/A";'Notes' = "The matched Certificate(s) have these thumbprints: " + $ValidCertThumbprint}


  }

  else
  {

 ### Write-Host 'No Valid certificate' -ForegroundColor Red

  $certificateResult = "False"
  $objects += New-Object -Type PSObject -Prop @{'Test Name'='Check if there is a matched certificate with Azure MFA';'Result'='Test Failed';'Recomendations' ="Re-register the MFA NPS Extension again to generate new certifictae, more info: https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#how-do-i-verify-that-the-client-cert-is-installed-as-expected";'Notes' = "N/A"}


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
#   $objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking missing Updates on the server';'Result'='Test Failed';'Recomendations' ="Usually we recomend to install all missing updates, please make a good plan before you proceed with the installtion";'Notes' = "Current missing updates is: " + $ListofMissingUpdates.title}
#
#
#}
#Else
##{
#
#### write-Host "The server is up to date" -ForegroundColor Green
#$updateResult = "True"
#
#$objects += New-Object -Type PSObject -Prop @{'Test Name'='Checking missing Updates on the server';'Result'='Test Passed';'Recomendations' ="N/A";'Notes' = "N/A"}
#}
#
#
}
else
{
write-Host "Connection to Azure Failed - Skipped all tests, please make sure to connect to your tenant first with global Admin role ..." -ForegroundColor Red


}

cd c:\


mkdir c:\AzureReport



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

$objects | ConvertTo-Html -Head $Header | Out-File c:\AzureReport\AzureMFAReport.html

Write-host "The Report saved on this Path: C:\AzureReport\AzureMFAReport.html" -ForegroundColor Green

}


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

 Connect-MsolService # To connect to Azure AD

$Global:verifyConnection = Get-MsolDomain -ErrorAction SilentlyContinue # This will check if the connection successed or Not

$Global:DialInStatus ="N/A" # Initial value not null as option 3 in AD will be null value, to avoid conflict

if($Global:verifyConnection -ne $null)
{

Install_AD_Module

$Global:Result = (Get-MsolUser -UserPrincipalName $Global:upn).UserPrincipalName  # Will check if the user exist in Azure AD based on the Provided UPN
$Global:IsSynced = (Get-MsolUser -UserPrincipalName $Global:upn).ImmutableId 
$Global:StrongAuthMethod = ((Get-MsolUser -UserPrincipalName $Global:upn).StrongAuthenticationMethods).MethodType  # To retrieve the current Strong Auth Method configured
$Global:DefaultMFAMethod =  ((Get-MsolUser -UserPrincipalName $Global:UPN).StrongAuthenticationMethods | where-object Isdefault -Contains "true").MethodType  # To retrieve the default MFA method
$Global:UserSignInStatus = (Get-MsolUser -UserPrincipalName $Global:upn).BlockCredential  # Check if the user blocked to sign-in in Azure AD
$Global:SAMAccountName = (Get-ADUser -Filter "UserPrincipalName -eq '$Global:UPN'").SamAccountName 
$Global:DialInStatus = Get-ADUser $Global:SAMAccountName -Properties * | select -ExpandProperty msNPAllowDialin 
$Global:UserStatus = (Get-MsolUser -UserPrincipalName $Global:upn).ValidationStatus  # Check if the user is health in Azure AD
$Global:UserLastSync = (Get-MsolUser -UserPrincipalName $Global:upn).LastDirSyncTime # Check the last sync time for the user in Azure AD
$Global:UserAssignedLicense = (Get-MsolUser -UserPrincipalName $Global:upn).Licenses.AccountSkuId  #Check User Assigned license


#$Global:Finishing_Test = Read-Host -Prompt "If no additional tests needed, Type Y and click Enter, This is will remove the AD module which installed at the begening of this test, removing the module require machine restart, if you don't want to remove it OR you need to perform the test again click enter directly "

if($Global:Finishing_Test -eq "Y")
{

Write-Host "Thanks for Using MS Products, Removing AD module now ..." -ForegroundColor Green 

Remove_AD_Module

}

}


else
{
write-Host "Connection to Azure Failed - Skipped all tests, please make sure to connect to your tenant first with global Admin role ..." -ForegroundColor Red

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

#Check if the user is exist in AD, if not the test will be terminated

Write-Host 
Write-Host
Write-Host "start Running the tests..."
write-host

Write-Host "Checking if" $Global:UPN "is EXIST in Azure AD ... " -ForegroundColor Yellow

if ($Global:Result -eq $Global:UPN) {

Write-Host

Write-Host "User" $Global:UPN "is EXIST in Azure AD... TEST PASSED" -ForegroundColor Green

Write-Host

} else {

Write-Host

Write-Host "User" $Global:UPN "is NOT EXIST in Azure AD... TEST FAILED" -ForegroundColor Red

Write-Host

Write-Host "Test was terminated, Please make sure that the user is EXIST to Azure AD" -ForegroundColor Red

Write-Host

Break

}

#Check if the user Synced to Azure AD, if Not the test will be terminated

Write-Host "Checking if" $Global:UPN "is SYNED to Azure AD from On-premises AD ... " -ForegroundColor Yellow


if($Global:IsSynced -ne $null -and $Global:UserLastSync -ne $null) {

Write-Host

Write-Host "User " $Global:UPN " is SYNCED to Azure AD ... Test PASSED" -ForegroundColor Green

Write-Host

} else {

Write-Host

Write-Host "User" $Global:UPN "is NOT SYNCED to Azure AD ... Test FAILED" -ForegroundColor Red

Write-Host "Test was terminated, Please make sure that the user is SYNCED to Azure AD" -ForegroundColor Red

Write-Host

Break

}

Write-Host "Checking if" $Global:UPN "is BLOCKED to sign in to Azure AD or Not ... " -ForegroundColor Yellow

#Check if the user not blocked from Azure portal to sign in, even the test failed other tests will be performed

if ($Global:UserSignInStatus -eq $false) {

Write-Host


Write-Host "User" $Global:UPN "is NOT BLOCKED to sign in to Azure AD ... Test PASSED" -ForegroundColor Green

Write-Host

}
else {

Write-Host

Write-Host "User" $Global:UPN "is Blocked to sign in to Azure AD ... Test FAILED" -ForegroundColor Red

Write-Host "Refer to: https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-users-profile-azure-portal#to-add-or-change-profile-information for more info about this .... Test will continue to detect additional issue(s), Please make sure that the user is allowed to sign in to Azure AD" -ForegroundColor Red

Write-Host



}


#Check if the user is in healthy status in Azure AD, even the test failed other tests will be performed.

Write-Host "Checking if" $Global:UPN "is HEALTHY in Azure AD or Not ..." -ForegroundColor Yellow

if ($Global:UserStatus -eq 'healthy') {

Write-Host


Write-Host "User "$Global:UPN "status is HEALTHY in Azure AD ... Test PASSED" -ForegroundColor Green

Write-Host

} else {

Write-Host

Write-Host "User" $Global:UPN "is NOT HEALTHY in Azure AD ... Test FAILED" -ForegroundColor Red

Write-Host "Test will continue to detect additional issue(s), Please make sure that the user status is HEALTHY in Azure AD" -ForegroundColor Red

Write-Host



}


#Check if the user have MFA method(s) and there is one default MFA method.

Write-Host "Checking if" $Global:UPN "already completed MFA Proofup in Azure AD or Not ... " -ForegroundColor Yellow

if ($Global:StrongAuthMethod -eq $null) {


Write-Host

Write-Host "User" $Global:UPN "did NOT Complete the MFA Proofup at all or Admin require the user to provide MFA method again ... Test FAILED" -ForegroundColor Red

Write-Host "Please refer to https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-getstarted#get-users-to-enroll for more info ... Test will continue to detect additional issue(s), Please make sure that the user status is HEALTHY in Azure AD" -ForegroundColor Red

Write-Host

} elseif ($Global:DefaultMFAMethod -eq $null ){


Write-Host

Write-Host "User" $Global:UPN "may did before the MFA Proofup but the admin require the user to Provide MFA Methods again ... Test FAILED" -ForegroundColor Red

Write-Host "Test will continue to detect additional issue(s), Please make sure that the user status is HEALTHY in Azure AD" -ForegroundColor Red

Write-Host

} else {

Write-Host


Write-Host "User" $Global:UPN "Completed MFA Proofup in Azure AD with" $Global:DefaultMFAMethod "as a Default MFA Method ... Test PASSED" -ForegroundColor Green


Write-Host

}



#Check the user assigned licenses, usually even the user don't have direct assigned license the MFA will not fail, so only warning we will throw here if the user have no license assigned
# refer to this for the plans: https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/licensing-service-plan-reference


Write-Host "Checking if" $Global:UPN "has a valid license for MFA ... " -ForegroundColor Yellow

if ($Global:UserAssignedLicense -eq 'AAD_PREMIUM' -or $Global:UserAssignedLicense -eq 'MFA_PREMIUM' -or $Global:UserAssignedLicense -eq 'AAD_PREMIUM_P2' -or $Global:UserAssignedLicense -eq 'EMSPREMIUM' -or $Global:UserAssignedLicense -eq 'EMS') {

Write-Host

Write-Host "User " $Global:UPN "has a valid assigned license ... Test PASSED" -ForegroundColor Green

Write-Host

} else {

Write-Host

Write-Host "User " $Global:UPN "has not a valid license for MFA, it's a warning message to be legal from licensing side... Test FAILED" -ForegroundColor Red

Write-Host "Test will continue to detect additional issue(s), Please make sure to assign a valid MFA License for the user (AD Premium, EMS or MFA standalone license" -ForegroundColor Red

Write-Host



}

#checking Network Access Permission under Dial-In Tab in AD, for more info refer to https://docs.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-np-access

Write-Host "Checking the Dial-In status for" $Global:UPN "in local AD" -ForegroundColor Yellow

if ($Global:SAMAccountName -ne $null) {

        if($Global:DialInStatus -eq $true)
        {

        Write-Host
        Write-Host "User" $Global:UPN "Allowed for Network Access Permission in local AD ... Test PASSED" -ForegroundColor Green
        Write-Host "Refer to https://docs.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-np-access for more infor about this option" -ForegroundColor Green
        Write-Host
        }

        
        elseif ($Global:DialInStatus -eq $false){


        Write-Host
        Write-Host "User" $Global:UPN "is Denied for Network Access Permission in local AD ... Test Failed" -ForegroundColor Red
        Write-Host "Refer to https://docs.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-np-access for more infor about this option" -ForegroundColor Red
        Write-Host

        }

        elseif ($Global:DialInStatus -eq $null){


        Write-Host

        Write-Host "User" $Global:UPN "has No policy Specified in local AD  ... You Need to check the NPS policy if the user is allowed or not" -ForegroundColor Red
        Write-Host "Refer to https://docs.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-np-access for more infor about this option " -ForegroundColor Red
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
        Write-Host "Check Completed, please fix any issue run the test again, if no issues found please contact MS support" -ForegroundColor Green
        Write-Host

}





Check_User ($Global:UPN)

Test_Results

}

Function Collect_logs
{

$ErrorActionPreference= 'silentlycontinue'

#start collecting logs
Set-Itemproperty -path 'HKLM:\SOFTWARE\Microsoft\AzureMfa' -Name 'VERBOSE_LOG' -value 'True'

mkdir c:\NPS
cd C:\NPS
netsh trace start Scenario=NetConnection capture=yes tracefile=C:\NPS\nettrace.etl
REG QUERY "HKLM\SOFTWARE\Microsoft\AzureMfa" > C:\NPS\%computername%_BeforeRegAdd_AzureMFA.txt
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters" > C:\NPS\%computername%BeforeRegAdd_AuthSrv.txt
REG ADD HKLM\SOFTWARE\Microsoft\AzureMfa /v VERBOSE_LOG /d TRUE /f
net stop ias
net start ias
$npsext = "NPSExtension"
$logmancmd= "logman create trace '$npsext' -ow -o C:\NPS\NPSExtension.etl -p {7237ED00-E119-430B-AB0F-C63360C8EE81} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets"
$logmancmdupdate = "logman update trace '$nps' -p {EC2E6D3A-C958-4C76-8EA4-0262520886FF} 0xffffffffffffffff 0xff -ets"
cmd /c $logmancmd
cmd /c $logmancmdupdate


Read-Host "Please Reproduce the issue quickly, once you finish please Press any key .... "


# Stop and Collect the logs
$logmanstop = "logman stop '$npsext' -ets"
cmd /c $logmanstop
netsh trace stop
REG QUERY "HKLM\SOFTWARE\Microsoft\AzureMfa" > C:\NPS\%computername%_AfterRegAdd_AzureMFA.txt
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters" > C:\NPS\%computername%AfterRegAdd_AuthSrv.txt
REG ADD HKLM\SOFTWARE\Microsoft\AzureMfa /v VERBOSE_LOG /d FALSE /f
Set-Itemproperty -path 'HKLM:\SOFTWARE\Microsoft\AzureMfa' -Name 'VERBOSE_LOG' -value 'False'
wevtutil epl AuthNOptCh C:\NPS\%computername%_AuthNOptCh.evtx
wevtutil epl AuthZOptCh C:\NPS\%computername%_AuthZOptCh.evtx
wevtutil epl AuthZAdminCh C:\NPS\%computername%_AuthZAdminCh.evtx
Start .






Write-Host
Write-Host "Data collection finished, Please compress the folder under C:\NPS and upload it to MS support request ... " -ForegroundColor Green
Write-Host

Break

}

Function MFAorNPS
{

# This test will remove the MFA registry key,to be able to decide if the issue related to MFA or NPS.

$AuthorizationDLLs_Backup = ''
$ExtensionDLLs_Backup = ''

$AuthorizationDLLs_Backup = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name AuthorizationDLLs).AuthorizationDLLs
$ExtensionDLLs_Backup = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name ExtensionDLLs).ExtensionDLLs

Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name AuthorizationDLLs -Value ''
Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name ExtensionDLLs -Value ''


Write-Host 

Write-Host -ForegroundColor DarkYellow "In this test we will remove some registry keys that will bypass the MFA module to isolate if the issue related directly to MFA or the NPS role, after the test finish the script will restore these regitry keys automatically, Press Any key to continue, otherwise please close the powershell box ..." 

Read-Host   

Write-Host 

Write-Host -ForegroundColor Yellow "Try to repro the issue again now without pressing anything here, if the user now able to connect without MFA successfully, then the issue related more to the MFA module, try to run the other test in this script, if the user still failing to connect then the issue with the NPS, hence please engage Network team, once you finish this test press any key to restore the MFA module .... " 

Read-Host

Write-Host

Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name AuthorizationDLLs -Value $AuthorizationDLLs_Backup

Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name ExtensionDLLs -Value $ExtensionDLLs_Backup

Write-Host 

$AuthorizationDLLs_Backup = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name AuthorizationDLLs).AuthorizationDLLs
$ExtensionDLLs_Backup = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AuthSrv\Parameters -Name ExtensionDLLs).ExtensionDLLs

if ($AuthorizationDLLs_Backup -ne $null -and $ExtensionDLLs_Backup -ne $null)
{

Write-Host "Registry Keys were restored, Proceed with other tests in this script if required" -ForegroundColor Green

}

Else

{

Write-Host "OPs ... Something wnet wrong while restoring the Registries, please follow this article: " -ForegroundColor Red

}

Break

}


if ($Choice_Number -eq 'E') { Break}
if ($Choice_Number -eq '0') { MFAorNPS }
if ($Choice_Number -eq '1') { Check_Nps_Server_Module }
if ($Choice_Number -eq '2') { User_Test_Module }
if ($Choice_Number -eq '3') { collect_logs }