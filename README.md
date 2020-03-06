---
page_type: sample
languages:
- powershell
products:
- azure-active-directory
description: "Script to run against Azure MFA NPS Extension servers to perform some basic checks to detect any issues. The output will be in HTML format."
urlFragment: "azure-mfa-nps-extension-health-check"
---

# Azure MFA NPS extension health check script

Script to run against Azure MFA NPS Extension servers to perform some basic checks to detect any issues. The output will be in HTML format.

## Script requirements

The script needs to be run as a user with local admin privilege on the server, and will ask for global admin on the tenant to be run against.

## How to run the script

Download and run the `MFA_NPS_Troubleshooter.ps1` script from this GitHub repo.

## What tests the script performs

The script performs the following test against MFA Extension Server:

1. Check accessibility to https://login.microsoftonline.com
1. Check accessibility to https://adnotifications.windowsazure.com
1. Check MFA version.
1. Check if the NPS Service is *Running*.
1. Check if the SPN for Azure MFA is *Exist* and *Enabled*.
1. Check if *Authorization* and *Extension* registry keys have the right values.
1. Check other Azure MFA related registry keys have the right values.
1. Check if there is a valid certificated matched with the certificates stored in Azure AD.
1. Check the time synchronization in the Server.
1. Compare server time with reliable time server.
1. Check all missing updates on the server.

## How the results will be displayed

In PowerShell console it will only display the tests name, then it will convert the result to HTML file located at `C:\AzureMFAReport.html`.

Example console output:

![Example PowerShell output](media/console_output.jpg)

Example HTML output:

![Example HTML output](media/html_output.jpg)

## Frequently asked questions

### In case the script detect some issues, will it fix then automatically?

No, but the script will suggest some remediation steps, as shown in the previous example HTML output.

### The script is not checking everything, right?

No, here I need your help! Feel free to share your ideas with me and we can work together to improve it. Open a GitHub issue or pull request in this repo.

### Do you think that the HTML design is cool?

No, help to make it better! Open a GitHub pull request in this repo with your improvements.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
