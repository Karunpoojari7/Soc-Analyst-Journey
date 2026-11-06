\## Time-Window Detection Analysis



\*\*Detection window:\*\* 5 minutes  

\*\*Illustrative threshold:\*\* 5 failed logons  

\*\*Events analysed:\*\* 3



| Window start | Failures within 5 minutes |

|---|---:|

| 02 Nov 2026, 16:32:48 | 1 |

| 03 Nov 2026, 19:12:12 | 1 |

| 05 Nov 2026, 10:04:47 | 1 |



\### Result



No five-minute window contained more than one observed failed logon.



The available events did not meet the illustrative brute-force detection threshold.



\### Assessment



No rapid brute-force pattern was detected in the available seven-day Security log data.



This finding does not exclude password spraying, activity outside the retained log history, or attempts against other authentication services.



\### Detection limitation



The analysis used locally retained Windows Security events. It does not represent a complete enterprise-wide authentication dataset.

