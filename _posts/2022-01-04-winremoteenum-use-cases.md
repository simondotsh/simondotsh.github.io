---
layout: post
title:  "WinRemoteEnum Use Cases"
date:   2022-01-12 00:00:00 -0500
categories: infosec
---
Enumeration is a key phase of penetration testing. When done in-depth, it can swiftly shift the dreadful "I cannot find anything" to the desirable "I can pivot everywhere".

In the Windows world, this activity has countless layers due to the complex nature of Active Directory, and the myriad of protocols willing to answer specific questions requested by any domain user.

Typically, when one seeks to get a good context of a domain privileges-wise, they instantly think of [BloodHound](https://github.com/BloodHoundAD/BloodHound) and I absolutely agree, but is there an alternative?

Often, I found myself in situations where I was given a scope of 10 to 20 Windows hosts. While BloodHound supports the `-ComputerFile` argument to collect information from specific hosts, it feels like there is quite a bit of overhead to answer particular questions, such as "who are the local administrators?" and "what users are logged in?". In that case, I had to rely on various enumeration tools here and there, without ever feeling like I could get it done efficiently, and more importantly, thoroughly.

This has lead to the development of [WinRemoteEnum](https://github.com/simondotsh/WinRemoteEnum).

## What is WinRemoteEnum?
WinRemoteEnum is a module-based collection of operations achievable by a low-privileged domain user, sharing the goal of remotely gathering information of Windows hosts, and their hardening status on commonly-leveraged techniques.

| Module | Enumerates |
| ----------- | ----------- |
| [users](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-users) | Local users, groups and their members. |
| [sessions](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-sessions) | Net sessions established. |
| [logged_on](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-logged_on) | Users logged on. |
| [shares](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-shares) | Shares and their first-level content. |
| [host_info](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-host_info) | Various OS info and whether the executing user has administrative privileges. |

Since most is enumerated through exposed built-in MS-RPC methods, it is heavily based off [impacket](https://github.com/SecureAuthCorp/impacket).

## Execution
When executing the tool, domain credentials and targets will be required as minimal input. If a list of modules is not given, all will be executed. Once the enumeration has completed, the `results/` directory contains another directory matching the timestamp at which the execution has taken place, and stores easy-to-consume HTML and JSON enumeration result files.

`python3 winremoteenum.py -u $USER -p $PASSWORD -d $DOMAIN $TARGET`

<figure>
  <img src="/assets/img/winremoteenum-use-cases/wre-execution.png"/>
  <figcaption>A typical do-it-all execution on a single target.</figcaption>
</figure>

As this is the bare minimum, ensure to read the `--help` for possible parameters and options.

## Module users
This module is without a doubt my favorite, and the main reason behind the development of the tool. Prior to this, I did not have an efficient and easy-to-parse way to enumerate local users, groups, and their members from hosts. Thanks to [MS-SAMR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380), this is indeed possible from a low-privileged domain user on hosts, as long as access to the SAM Remote has not been hardened.

### Use Case: Basic Reconnaissance
Before digging into the host, I like to get a general idea of its context by browsing the `users.html` file. Quickly, you should be able to tell if it is properly maintained or has gone through years of misuse, simply by looking at the local users and groups, and then answering some questions as such:

* How many local users does it have?
* Is the entire cosmos a local administrator?
* Are SIDs getting resolved by the DC, or the users and groups most-likely no longer exist?

<figure>
  <img src="/assets/img/winremoteenum-use-cases/wre-users-html.png"/>
  <figcaption>An example users.html results file.</figcaption>
</figure>

### Use Case: Analysis of Remote Access Groups
I use the term "Remote Access Group" to refer to any group allowing a user to compromise a host remotely, whether the end result is a privileged access or not.

The newly released version 1.1 of WinRemoteEnum contains an [analysis script](https://github.com/simondotsh/WinRemoteEnum/blob/master/analysis/users/analyze.py) that can be ran manually by a user, resulting in a list of members of the groups in question. This yields a map of which users must be compromised in order to gain access to the host, or if you are able to leverage previously-compromised users.

`python3 analysis/users/analyze.py results/$RESULTS_DIR/json/users.json`

<figure>
  <img src="/assets/img/winremoteenum-use-cases/wre-analysis-users.png"/>
  <figcaption>A sample analysis of users without filtering.</figcaption>
</figure>

Visit the [wiki](https://github.com/simondotsh/WinRemoteEnum/wiki/Analysis-users) for usage information about the script. Do note that some techniques are using services bound on different ports, meaning that proper firewalling may block you from accessing the host.

In the next section, each remote access group will be explained.

#### BUILTIN\Remote Management Users
This group provides access to [Windows Remote Management](https://docs.microsoft.com/en-us/windows/win32/winrm/portal) (WinRM).

On Windows, [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2) allows to leverage this easily by using `Enter-PSSession` or `Invoke-Command`.

On Linux, [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) includes a nice implementation, which can be used like so:

`./cme winrm $HOST -u $USER -p $PASSWORD -d $DOMAIN -x $COMMAND`

#### BUILTIN\Remote Desktop Users
If the `Remote Desktop Services` are started on the host, simply fire up your favorite Remote Desktop client, and authenticate on the host to gain access.

#### BUILTIN\Distributed COM Users and BUILTIN\Performance Log Users
When running the analysis script, these groups are listed as "potential" since they do not grant access to the host out-of-the-box, as opposed to the other groups.

If you wish to learn about these groups and the additional privileges required, you can read about it in my previous post [Non-administrative DCOM Execution: Exploring BloodHound's ExecuteDCOM](https://simondotsh.com/infosec/2021/12/29/dcom-without-admin.html), or note that you will need `Remote Launch` and `Remote Activation` over the DCOM object that you want to instantiate.

impacket's [dcomexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py) can be used to perform the object instantiation: 

`python3 dcomexec.py -object MMC20 -silentcommand $DOMAIN/$USER:$PASSWORD\$@$HOST $COMMAND`

#### BUILTIN\Administrators
This is evidently the Holy Grail of groups, allowing to gain privileged access to the host using the aforementioned techniques, or a multitude of different ones. For instance, impacket additionally offers [atexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py), [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py), [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py), and [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py).

If you require to execute commands as the user instead of `NT AUTHORITY\SYSTEM`, use `dcomexec.py` (ensure to supply the `-object MMC20` parameter), or `wmiexec.py`.

## Modules sessions and logged_on
These two have been grouped due to usually sharing the same goal: hunting users to dump their NT hash.

`sessions` enumerates net sessions established on a target. A net session is created when a client accesses a target's resource remotely, such as a network share.

On the other hand, `logged_on` returns users logged onto a target by enumerating registry keys through the Remote Registry service.

### Use Case: Basic Reconnaissance
As goes for most modules, I begin with browsing the `sessions.html` and `logged_on.html` to get a general idea of what is happening on the host.

Many sessions might very well indicate a file server that has significant traffic. Combined with a writable network share, one may be able to leverage NTLM relay.

<figure>
  <img src="/assets/img/winremoteenum-use-cases/wre-sessions-html.png"/>
  <figcaption>An example sessions.html results file.</figcaption>
</figure>

Additionally, logged on users can help understanding the purpose of the host, and how it is used.

<figure>
  <img src="/assets/img/winremoteenum-use-cases/wre-logged-on-html.png"/>
  <figcaption>An example logged_on.html results file.</figcaption>
</figure>

### Use Case: Hunting Users
In the results of `sessions`, the `source` field indicates where the user has initiated the connection from, meaning that in the case where this user has authenticated on this source using a protocol that caches NT hashes in the LSASS process, a privileged user may leverage credential dumping.

Regarding `logged_on`, similarly to `sessions`, the users may have authenticated on the target using a protocol that caches their NT hash.

When looking for the location of a specific user, I suggest simply using the `grep` command on `sessions.json` and `logged_on.json`, and see if you get any results back.

## Module shares
The `shares` module offers precisely what it states: a view of the network shares available on a host through SMB, and if the executing user can read them. It also lists the name of the first-level files and directories. In the case where the count of items exceeds __MAX_SHARE_LIST_ITEMS (currently 30), a total of files and directories will be reported instead.

The tool currently does not report whether the user has write access due to the possibility of polluting the share. You can read about it in the [wiki](https://github.com/simondotsh/WinRemoteEnum/wiki/Module-shares#does-my-user-have-write-privileges).

### Use Case: Basic Reconnaissance
The `shares.html` file quickly shows the state of the host shares-wise, and how many of these can be read.

<figure>
  <img src="/assets/img/winremoteenum-use-cases/wre-shares-html.png"/>
  <figcaption>An example shares.html results file.</figcaption>
</figure>

### Use Case: Finding Sensitive Information
Network shares are often a successful vector to get initial access on a host, either by getting your hands on some credentials, or through NTLM relay when they are writable.

Since the first-level content of shares are listed, this is a convenient way to identify at a first glance which ones might be worth digging into.

## Module host_info
This module is dedicated to reporting information about the host, such as its OS version, role, domain, SMB hardening, and if the executing user is a local administrator.

### Use Case: Basic Reconnaissance
Similarly to other modules, `host_info.html` helps to understand further the context of the host, by revealing information regarding the OS, and more.

<figure>
  <img src="/assets/img/winremoteenum-use-cases/wre-host-info-html.png"/>
  <figcaption>An example host_info.html results file.</figcaption>
</figure>

### Use Case: Local Administrator Privileges
By attempting to open the Service Control Manager (SCM) database with all privileges, one can conclude remotely if they have administrative privileges on the host.

This can be seen in the `local_admin` field.

### Use Case: Finding NTLM Relay Targets
To successfully relay a NTLM authentication on a target, it must have SMB signing disabled, which otherwise validates that the message has not been tampered with.

The `smb_signing_required` field denotes this.

## Audit
WinRemoteEnum offers an auditing feature, accessible simply by providing the `-a` parameter. This will report if the enumeration vectors have been hardened against low-privileged users, since most of them are indeed hardenable.

Head over to the audit section of the [wiki](https://github.com/simondotsh/WinRemoteEnum/wiki#audit) for a description of what is audited for each module.

## Learn More
Make sure to go through the [README](https://github.com/simondotsh/WinRemoteEnum/blob/master/README.md) and  the [wiki](https://github.com/simondotsh/WinRemoteEnum/wiki) for information about optimization, credentials validation, reporting, modules, auditing, and analysis.