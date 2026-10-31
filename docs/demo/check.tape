# Re-record on a disposable Ubuntu/Debian VM with working systemd and key SSH.
# This tape did NOT generate the committed GIF; see README.md for provenance.
# Before starting: verify a second key-based login and open an out-of-band console.
# During the 8s pause below, establish another fresh SSH connection from a
# separate terminal. Abort the tape before "yes" if that connection fails.
# The tape approves two changes; never run it against a production host.
Output docs/demo/check.gif

Require witshield
Require sudo

Set Shell "bash"
Set Width 1440
Set Height 900
Set FontFamily "Noto Sans Mono CJK SC"
Set FontSize 21
Set Theme "Catppuccin Mocha"
Set Padding 24
Set TypingSpeed 25ms
Set PlaybackSpeed 1

Hide
Type "test \"${WITSHIELD_DEMO_DISPOSABLE:-}\" = yes || exit 1"
Enter
Type "sudo -v && clear"
Enter
Sleep 1s
Show

Type "sudo witshield check --no-color"
Enter
Wait+Screen /分享：/
Sleep 3s
Type "sudo witshield check --fix --no-color --ssh-confirm-seconds 60"
Enter
Wait+Screen /现在修改/
Sleep 2s
Type "y"
Enter
Wait+Screen /新窗口能登录吗/
Sleep 8s
# Only keep this confirmation if a separate fresh key-based login succeeded.
Type "yes"
Enter
Wait+Screen /root:shadow 0640/
Sleep 1s
Type "y"
Enter
Wait+Screen /修复结束/
Sleep 2s
Hide
Type "clear"
Enter
Show
Type "sudo witshield check --no-color"
Enter
Wait+Screen /分享：/
Sleep 5s
