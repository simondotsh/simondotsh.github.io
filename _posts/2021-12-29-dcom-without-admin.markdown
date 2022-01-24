---
layout: post
title:  "Non-administrative DCOM Execution: Exploring BloodHound's ExecuteDCOM"
date:   2021-12-29 00:00:00 -0500
categories: infosec
---
Object instantiation through DCOM has been a popular technique to perform lateral movement since Matt Nelson ([@enigma0x3](https://twitter.com/enigma0x3)) [unveiled its possibility](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) in 2017, while focusing on the administrative privileges required.

When analyzing a [BloodHound](https://github.com/BloodHoundAD/BloodHound/) graph, one may see from time to time an edge where a user or group can compromise a host via [ExecuteDCOM](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#executedcom), described as the following:

> This can allow code execution under certain conditions by instantiating a COM object on a remote machine and invoking its methods.

What are these certain conditions, exactly?

## The Non-administrative Possibility
In a blog post about [BloodHound version 2.0](https://blog.cptjesus.com/posts/bloodhound20) by Rohan Vazarkar ([@CptJesus](https://twitter.com/cptjesus)), it is stated that the edge ExecuteDCOM is newly introduced, justified by the possibility that a member of the `BUILTIN\Distributed COM Users` group may be able to instantiate objects remotely:

> The ExecuteDCOM edge runs from a user or a group to a computer and indicates that the principals are part of the **Distributed COM Users** local group on the target system. Depending on the security descriptor on the target system, users in this group sometimes have remote code execution privileges without corresponding administrative permissions on the target system. This provides another lateral movement method that does not require administrative access. Collection of this edge belongs to the new DCOM collection method.

This changes the impact of the technique from "I can execute code because I have all privileges" to "I can execute code when people might not expect me as able to". We also learn more about the conditions: they are security descriptors.

So, what if we were to attempt to instantiate one of those convenient objects offering a method with code execution?

## Tracking It Down
The following operations have been performed on a domain-joined Windows 10 host.

### Validating the Default Behavior
To begin, impacket's [dcomexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py) was used to achieve object instantiation remotely, providing credentials of a domain user having no particular privileges:

`python3 dcomexec.py -object MMC20 -silentcommand -debug $DOMAIN/$USER:$PASSWORD\$@$HOST 'notepad.exe'`

* `-object MMC20` specifies that we wish to instantiate the `MMC20.Application` object.
* `-silentcommand` executes the command without attempting to retrieve the output. This is desirable since the script is using an SMB share to write and fetch the output, and our low-privileged user cannot write to any.
* `notepad.exe` is ran on the target as a simple proof of concept.

<img src="/assets/img/dcom-without-admin/dcomexec-rpc-denied.png"/>

RPC access denied. This is expected as currently, the user is not a member of the `BUILTIN\Distributed COM Users` group, and therefore cannot call [MS-DCOM](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0)'s [IRemoteSCMActivator::RemoteCreateInstance](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/64af4c57-5466-4fdf-9761-753ea926a494).

This can also be seen from Wireshark:

<img src="/assets/img/dcom-without-admin/wireshark-rpc-denied.png"/>

Then, the user is added to the `BUILTIN\Distributed COM Users` group, which yields a different error but not from RPC itself:

<img src="/assets/img/dcom-without-admin/dcomexec-dcom-sessionerror.png"/>

This confirms that only having access to the group is not enough, and that we have already reached the point where these descriptors must be investigated.

### Leveraging Windows Events
Before chanting a spell to summon a vile creature from the abyss in hopes of compromising the integrity of your soul to obtain, yet again, a glimpse of answer regarding obscure Windows behavior, paying a visit to the Event Viewer may be worthwhile.

In this case, it was indeed quite insightful:

<img src="/assets/img/dcom-without-admin/windows-event-dcom-error.png"/>

So, `Remote Activation` permission issues. Further testing revealed that `Remote Launch` privileges were also missing.

### Looking Into DCOM Security
Tuning DCOM security appeared to be quite the task until reading another of Matt Nelson's [blog post](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/). In the "Defenses" section, he discusses the possibility of restricting DCOM access to local administrators by removing their `Remote Launch` and `Remote Activation` privileges, and goes in depth explaining how to concretely achieve this.

Simply put, DCOM objects can be configured in two ways: either they follow system-wide security configuration, or their own. Therefore, the member of `BUILTIN\Distributed COM Users` also needs to have been given `Remote Launch` and `Remote Activation` privileges according to the object's configuration, which is not the case out-of-the-box for the `MMC20.Application` object as demonstrated above.

By default, the `MMC20.Application` object follows system configuration. Once `Remote Launch` and `Remote Activation` is given system-wide to the group `BUILTIN\Distributed COM Users` (I suppose this is a mistake that could be seen in the wild), we test the same command as before:

<img src="/assets/img/dcom-without-admin/dcomexec-successful.png"/>

The instantiation worked and our command was executed, which I confirmed by seeing that `notepad.exe` was running on the host as our executing user.

## About Other Objects
### ShellWindows and ShellBrowserWindow
These two built-in objects are also known to offer command execution capabilities. As the instantiated objects offer an interface to `Explorer.exe`, the command will be executed as the logged on user and therefore should be avoided, since a non-administrative user will most-likely not be able to run commands as them.

### Custom Objects
Keep in mind that other than the built-in objects, a user could have been given privileges over a custom object that may offer methods capable of code execution; however I am unaware of any decent way to investigate these without having local access on the host, which usually defeats the purpose of attempting to find a way to pivot on it.

## Another Group: BUILTIN\Performance Log Users
A member of the group `BUILTIN\Performance Log Users` will essentially get the same privileges as `BUILTIN\Distributed COM Users`, meaning that they will also be able to call the `RemoteCreateInstance` method. Remote object instantiation will be possible, as long as they have been given the `Remote Launch` and `Remote Activation` privileges.

I believe that this is much less likely that a member of this group will also have the aforementioned remote privileges on a relevant object, but worth noting that it is possible.

## To Conclude
I do not expect this technique to be possible very often in the wild as a non-administrator due to the extra remote privileges required on the objects, but it is interesting to observe another misconfiguration in the Windows world that has significant consequences.

Food for thought: since I could not find a way to tell if my user had the required privileges over an object other than by attempting to create the instance, and since the system logs quite well that a user has attempted to do so, some might like the idea of creating a honeypot in your domain where some key principals are reported as having the `ExecuteDCOM` edge on a host.
