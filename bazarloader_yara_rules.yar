/*
 * BazarLoader YARA Rule 1
 * Authors: Victor Hoac
 * Date: 2026-03-17
 */

rule BazarLoader_DLL_EnterDLL {
    meta:
        description = "Detects BazarLoader DLL via EnterDLL export and C2 URI patterns"
        author      = "Victor Hoac"
        date        = "2026-03-17"
        reference   = "https://www.trendmicro.com/en_us/research/21/k/bazarloader-adds-compromised-installers-iso-to-arrival-delivery-vectors.html"
    strings:
        $export  = "EnterDLL" ascii
        $uri1    = "/data/service" ascii
        $uri2    = "/stat/var/upd" ascii
        $ua      = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" ascii
        $mz      = { 4D 5A }
    condition:
        ($mz at 0) and
        $export and
        (1 of ($uri*) or $ua)
}

/*
 * BazarLoader YARA Rule 2
 * Authors: Hoang Vinh Nguyen
 * Date: 2026-03-17
 */

rule BazarLoader_ProcessHollowing {
    meta:
        description = "Detects BazarLoader via process hollowing API sequence and BCryptDecrypt"
        author      = "Hoang Vinh Nguyen"
        date        = "2026-03-17"
        reference   = "https://cybersecurity.att.com/blogs/labs-research/trickbot-bazarloader-in-depth"
    strings:
        $api1   = "CreateProcessA" ascii
        $api2   = "NtWriteVirtualMemory" ascii
        $api3   = "SetThreadContext" ascii
        $api4   = "ResumeThread" ascii
        $runkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii nocase
        $bcrypt = "BCryptDecrypt" ascii
    condition:
        uint16(0) == 0x5A4D and
        all of ($api*) and
        ($runkey or $bcrypt)
}
