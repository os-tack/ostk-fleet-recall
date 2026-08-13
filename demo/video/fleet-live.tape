Output demo/video/generated/fleet-live.mp4

Require jq
Require tmux

Set Shell bash
Set FontSize 15
Set FontFamily "Menlo"
Set Width 1600
Set Height 900
Set Padding 12
Set Margin 16
Set MarginFill "#11111b"
Set BorderRadius 10
Set WindowBar RingsRight
Set Theme "Catppuccin Mocha"
Set Framerate 30
Set TypingSpeed 12ms
Set CursorBlink false

Env FLEET_VIDEO_VHS "1"

Hide
Type "clear && ./demo/video/run.sh --fleet-live"
Enter
Sleep 750ms
Show

Wait+Screen@55s /SCENARIO VERIFIED/
Sleep 4s
Ctrl+B
Type "d"
Sleep 1s

Hide
Type "exit"
Enter
