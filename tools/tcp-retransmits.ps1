# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

# Sample Windows' TCP counters and report the retransmission rate.
#
# Run this alongside a transfer through the tunnel. It answers one question:
# is the connection carrying the tunnel losing packets?
#
#   powershell -ExecutionPolicy Bypass -File tools\tcp-retransmits.ps1
#
# WMI property names rather than `netstat -s`, because netstat's output is
# translated and any text filter breaks on a non-English Windows.
#
# Around 0.2-0.3% sustained is enough to hold a single TCP connection near
# 1 MB/s at 30 ms -- loss, not bandwidth, is what limits it. Near 0% means the
# ceiling is somewhere else: a policer, or the far end.
#
# The counters are machine-wide, so keep other traffic quiet while measuring.

param([int]$IntervalSeconds = 5)

$previous = Get-CimInstance Win32_PerfRawData_Tcpip_TCPv4
Write-Host "sampling every ${IntervalSeconds}s; Ctrl-C to stop`n"
Write-Host ("{0,10} {1,10} {2,8}   {3}" -f "sent", "resent", "rate", "verdict")

while ($true) {
    Start-Sleep -Seconds $IntervalSeconds
    $now = Get-CimInstance Win32_PerfRawData_Tcpip_TCPv4

    $sent = $now.SegmentsSentPersec - $previous.SegmentsSentPersec
    $resent = $now.SegmentsRetransmittedPersec - $previous.SegmentsRetransmittedPersec
    $previous = $now

    if ($sent -le 0) { continue }
    $rate = 100.0 * $resent / $sent

    $verdict = if ($rate -ge 0.15) {
        "loss is enough to explain a slow connection"
    } elseif ($rate -ge 0.02) {
        "some loss, probably not the whole story"
    } else {
        "essentially lossless -- look elsewhere"
    }

    Write-Host ("{0,10} {1,10} {2,7:N3}%   {3}" -f $sent, $resent, $rate, $verdict)
}
