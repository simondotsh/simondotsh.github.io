---
layout: post
title:  "An Azure Tale of VPN, Conditional Access and MFA Bypass"
date:   2023-08-15 00:00:00 -0500
categories: infosec
---
Cloud service providers (CSP) enable organizations to deploy modern solutions with impressive swiftness. Part of this is due to providers' responsibility of tackling harder problems both on a functional and security level, while consumers are in charge of minimal configuration. With this in mind, one has to consider that CSPs face the challenge of designing security controls with an adequate threshold of effectiveness compatible with the desired user experience. Thus, when relying on these controls, consumers must ensure to be aware of potential weaknesses to avoid wildly claiming "if you manage to bypass this, you've broken Azure."

Recently, I reviewed an implementation of a virtual private network (VPN) server using Azure AD (now Entra ID) as its identity provider (idP), allowing to easily enforce controls such as multi-factor authentication (MFA). The main objective of the assessment was straightforward: manage to authenticate on the VPN without solving an MFA challenge.

This post does not introduce novel or undocumented techniques, but aims to present a methodology to approach a similar problem along with mitigation opportunities.

## Basis
Before diving into the analysis, crucial elements will be described.

### Setup
In order to reproduce a simplified test environment, the following components were configured:

* [Microsoft 365 E5 sandbox](https://developer.microsoft.com/en-us/microsoft-365/dev-program) with an Azure AD tenant.
* Cisco ASA v9.7+ device running on a private network with the VPN server AnyConnect.
* Cisco AnyConnect enterprise application to achieve SAML-based authentication with Azure AD on the ASA.
* Azure AD conditional access policies applying to various applications and identities.
* Azure AD user with access to the Cisco AnyConnect enterprise application.
* Azure AD-joined Windows 10 device managed by Intune with the Cisco AnyConnect client v4.6+.

### The Analyst's Privileges
In my experience, when it comes to these kinds of assessments or any penetration test, hiding technical details to an analyst accomplishes no good. In fact, it limits the depth at which vulnerabilities may be found, and enables a malicious actor to exploit what was difficultly done in a limited time frame.

As such, the investigation will be conducted with [Global Reader](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-reader) privileges.

### Expected Authentication Flow
When connecting to the VPN server on the Windows device, the user is prompted to authenticate:
<figure>
  <img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/anyconnect-auth01.png" width="70%"/>
  <figcaption>The integrated Internet Explorer 11 browser has trouble with rudimentary CSS.</figcaption>
</figure>

Since `user@weakest.cloud` has logged into Windows, they have obtained a primary refresh token (PRT) claiming satisfaction for the first factor requirement (you can read about this process [here](https://learn.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token#browser-sso-using-prt)), and can therefore proceed to solving the second factor:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/anyconnect-auth02.png" width="70%"/>

Once this challenge succeeds, the VPN server allows the connection:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/anyconnect-auth03.png" width="70%"/>

## Analysis
As previously stated, the goal is to bypass MFA, but the context matters significantly. For instance, depending on your threat model, an ill-intended actor with local or physical access to an Azure-joined device managing to circumvent MFA is likely to be less concerning than achieving the deed with a set of phished credentials, simply due to the vast difference in exposure. This must be regarded when looking for potential vectors.

### Sign-in Logs
In a scenario where the interaction between an identity and an application must be inspected, it makes sense to review the user's sign-in logs and visualize which conditional access policies were applied after authenticating on the application.

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/sign-in-logs-cap.png"/>

Pay attention to the `Result` column and consider the following: except the policy stating `Not Applied`, controls in the other two must be satisfied; failure to meet one of these yields access denied. For a primer on conditional access, refer to this [article](https://danielchronlund.com/2018/11/23/how-multiple-conditional-access-policies-are-applied/).

Put into words, we can conclude that when authenticating on the AnyConnect application, `user@weakest.cloud` must solve an MFA challenge and originate from a device deemed as compliant by Intune due to the policies `CA200-AnyConnectUsers-AppProtection-AnyConnect-WindowsmacOSLinux-MFA` and `CA001-Global-AppProtection-AllApps-AnyPlatform-Compliant` respectively.

Now, onto reading the pair's configuration.

### MFA Policy
`CA200-AnyConnectUsers-AppProtection-AnyConnect-WindowsmacOSLinux-MFA` follows the nomenclature [suggested by Microsoft](https://learn.microsoft.com/en-us/azure/architecture/guide/security/conditional-access-framework) which, in return, allows to quickly get an idea of how it is configured, but should be validated concretely nonetheless.

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/mfa-cap.png" width="40%"/>

The following can already be seen: it applies to specific users without any exclusion, targets a single application (the AnyConnect enterprise application since it applied to us when connecting), and one category of conditions is used.

Let's look into the users first:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/mfa-cap-users.png" width="40%"/>

To facilitate delegation, only the security group named `AnyConnect Users` appears to handle access to the application, but must be confirmed.

What about the condition?

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/mfa-cap-devices.png" width="30%"/>

The policy applies only to users connecting from Windows, macOS and Linux. Does this mean a connection from a mobile device would not trigger an MFA challenge? This will be validated later on.

### Compliance Policy
`CA001-Global-AppProtection-AllApps-AnyPlatform-Compliant` is much simpler:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/compliance-cap.png" width="40%"/>

All users must authenticate from compliant devices to be permitted on applications where Azure AD handles access. Some exceptions exist, like [Microsoft Intune Enrollment](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-compliant-device#create-a-conditional-access-policy), where its critical feature of enrolling devices would no longer be possible.

So, the AnyConnect client must initiate a connection from a compliant device to avoid denial. This implies possessing a device managed (enrolled) by Intune and meeting compliance prerequisites; mere device registration would not do the trick.

## Validations
This section serves to validate some hypotheses crafted from the previous analysis:

* Users other than `AnyConnect Users` may have access to the AnyConnect enterprise application.
* Only a specific set of device platforms may be governed by a policy enforcing MFA.
* `user@weakest.cloud` may be able to enroll mobile devices.

### Enterprise Application Access
As only members of the group `AnyConnect Users` are covered by the MFA policy, two questions arise: do users need explicit access to the application and if so, can more identities access it? These can be easily checked through the Azure portal.

After browsing to the enterprise application, in the properties, the `Assignment required?` entry dictates whether explicit access to the application is needed:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/app-assignment-required.png" width="70%"/>

This is the desired value, otherwise anyone not a member of the group `AnyConnect Users` would get access to the application without MFA, unless another policy would save the day.

To answer the last question, the section `Users and groups` lists who can access this application:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/app-assigned-users.png" width="70%"/>

This looks good: only expected users are authorized to connect. With that being said, further checkups could be done such as looking into owners and other principals able to control the application, but is left out of this exercise.

### Device Platforms Without MFA
The `What If` feature of conditional access policies is a convenient way to conclude what policies apply when certain parameters are selected. As an example, when setting the test user and the AnyConnect application on a Windows device, the two aforementioned policies are reported as applying:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/what-if-anyconnect-config.png" width="70%"/>

<figure>
  <img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/what-if-anyconnect-results.png"/>
  <figcaption>The Azure portal also has trouble with rudimentary CSS.</figcaption>
</figure>

What if the device is iOS instead?

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/what-if-anyconnect-ios-results.png"/>

As previously guessed, MFA is not required to connect to AnyConnect on a mobile device, but it must be enrolled and compliant. A stroll into the compliance policies of the Intune admin center lets on that compliance will not be an issue.

### Mobile Device Enrollment
To validate if the user can enroll a device, the same strategy with the `What If` feature is used, but will target the Microsoft Intune Enrollment application instead:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/what-if-enrollment-ios-results.png"/>

The policy `CA002-Global-AppProtection-IntuneEnrollment-AnyPlatformExceptWindows-Block` blocks enrollment of any mobile device, but as its name states, allows all users to enroll Windows devices. Further checks reveal that out of the various ways to enforce MFA, none would apply during enrollment.

## Chaining Findings
Operations in the last section confirmed these next statements:

* `user@weakest.cloud` can enroll Windows devices without MFA.
* iOS devices are not subject to MFA when authenticating on AnyConnect.

Now is the time to trick Azure AD to let us enroll an iOS device and authenticate on AnyConnect without MFA.

### My iPad Is A Windows Device
A critical piece of information about conditional access policies filtering on device platforms must be known: they rely on data sent by clients in the HTTP request upon authenticating, and can be altered except when a token with a device ID claim is involved. In the latter case, this claim is used to match the device platform in Azure AD, so no alteration is possible (thanks to [Dirk-jan](https://twitter.com/_dirkjan) for confirming this); however, no such claim is needed during the enrollment of an iPad device.

Before proxying and modifying the key request, the Company Portal application is installed. After authenticating with `user@weakest.cloud` and attempting enrollment of the iPad device, the inability is witnessed concretely:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/ipad-enrollment-denied.png" width="90%"/>

After going back one step in the process, this screen is reached:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/ipad-enrollment-before-proxy.png" width="90%"/>

At this point, the iPad is configured to use a proxy server, and requests sent by the client are captured. Once the button `Continue` is pressed, eventually a request to `login.microsoft.com` will be sent. Two parts of it must be tweaked: the `GET` parameter `x-client-SKU=MSAL.iOS` has to be removed, and the `User-Agent` header needs to match one from a Windows device, for instance `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19045`.

<figure>
  <img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/ipad-enrollment-capturing.png"/>
  <figcaption>For the curious, this Montréal-based Burp-alternative software is named <a href="https://caido.io/">Caido</a>.</figcaption>
</figure>

Once the request is forwarded, the user is prompted to download a configuration profile, confirming the policy conditions have been met:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/ipad-enrollment-success.png"/>

Then, the rest of the process has to be completed normally, which leads to having a compliant device as can be seen in Azure AD:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/ipad-compliant.png"/>

### Authenticating on VPN
All that is left to gain access to the internal network is to install Cisco Secure Client on the iPad and connect to the VPN server:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/ipad-anyconnect-connected.png"/>

Similarly to the presented authentication flow, the client was asked to authenticate but with a significant difference: no MFA was demanded. The sign-in logs reflect this:

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/logs-no-mfa01.png" width="70%"/>

<img src="/assets/img/azure-tale-vpn-ca-mfa-bypass/logs-no-mfa02.png" width="80%"/>

### What About the Windows Device?
The main reason why this bypass was possible is due to the policy enforcing MFA on the VPN applying only to Windows, macOS and Linux. What if from our Windows device, we also change the user agent on authentication to state a different uncovered OS?

In the current setup, as far as I know this cannot be done, simply because the device must be compliant, and compliance validation implies supplying a token with a device ID claim. As mentioned before, this ID is also used to match the device platform, so the user agent is ignored. On the iPad, the user agent was modified while enrolling, not during authentication on the VPN.

## Mitigation
In this demonstration, the environment would benefit from adjusting conditional access policies and device platform restrictions.

### Do Not Scope on Specific Platforms
Instead of forcing MFA on precise platforms, the weak policy should instead include `Any device` without exclusions to ensure unknown and unexpected platforms would also be prompted to solve the challenge.

### No MFA No Enrollment
When taking the big picture into account, this control neutralizes the biggest threat: compromised credentials used to access cloud applications. Currently, the configuration allows an attacker with `user@weakest.cloud`'s password to enroll their own device, then browse any application where the only condition is having a compliant device. In the case where MFA is required to enroll, it would instead force the compromission of a device to achieve the same, which definitely requires more effort.

### Using Device Platform Restrictions
While I have not fully investigated the complete bulletproofness of this control, Intune offers the possibility to restrict the enrollment of specific platforms for desired principals instead of relying on an easily-bypassable conditional access policy. See the [documentation](https://learn.microsoft.com/en-us/mem/intune/enrollment/create-device-platform-restrictions) for more information.

## Conclusion
Using Azure AD as the idP for cloud and on-premises software is convenient and powerful, but does not avoid complexity especially in large tenants. Conditional access policies can quickly become a mess of loosely scoped conditions and exclusions leading to gaps when a different context is considered. Assessment of these controls in accordance to the identified threats definitely benefit organizations to assure full coverage.