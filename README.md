# UserManagerEoP

This is exploit for CVE-2023-36047 i found last year.

The flaw was in usermanager service which copied files from user controllable directory which results in EoP.
After first fix MSRC only fixed write part of copy operation while read operation was still performed in NT AUTHORITY\SYSTEM context. This can be abused to SAM/SYSTEM/SECURITY hives from shadow copy, today MSRC fixed this vulnerability and is tracked as CVE-2024-21447
