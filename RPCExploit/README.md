# Vulnerability Enumerator
This project aims to build basic pattern matching around common vulnerable indicators that can be identified using Procmon. I'm a total noob at hunting for LPEs so I wanted a way to get very specific about:
1) What potentially vulnerable behavior looks like in procmon
2) Where to look for this behavior

My hope is that once I understand and can check for more high fidelity indicators that I'll be able to add fuzzing for something like RPC servers. Then we can fuzz against everything and we'll know how to cause interesting behavior.

The default procmon filter being used in this project is:

`Integrity|is|medium|Exclude` - We want SYSTEM

`Detail|contains|Impersonating: desktop|Exclude` - My user is in the desktop-asdf group so we don't care about those

## Checks
http://sandboxescaper.blogspot.com/2019/12/chasing-polar-bears-part-one.html

This blog goes through an example of a vulnerable indicator that I have implemented a check for. The gist is that there's an msi file in C:\Windows\Installer that is authored by VMWare. 
When my code is kicked off, `msiexec /fa C:\Windows\Installer\whatever.msi`will run and procmon will record its behavior. Those results will then be saved, converted into csv, and then checked against the following logic:

`if there's a CreateFile NAME NOT FOUND and CreateFile with delete permission and SetRenameInformationFile near each other for the same path and the user has write access to the folder then this is a potential file modify vuln`

Running that results in many potential file modify vulns being identified, including the one chosen in that blog post: *stop-listener.bat,* as we would expect.

## Adding fuzzing
https://googleprojectzero.blogspot.com/2019/12/calling-local-windows-rpc-servers-from.html

James Forshaw recently released a library that can be used to call local windows RPC servers from .NET. This seems like a cool idea because you can do crazy stuff in .NET like reflection. Basically his blog post walks you through generating a ton of .cs files. You then add one to your visual studio project, import the generated class name and you can make calls to all the functions over RPC as you would expect in .NET. At some point I want to see if I can import _all_ RPC servers into the visual studio project, then use reflection to invoke all "normal" functions (that take params like string, int, etc).
