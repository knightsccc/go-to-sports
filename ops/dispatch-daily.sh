#!/bin/sh
# Called once per day by go-to-sports-dispatch.timer at 21:30 Asia/Shanghai.
set -eu
today="$(TZ=Asia/Shanghai date +%F)"
/usr/bin/gh workflow run 382966126   --repo knightsccc/go-to-sports   --ref master   -f "scheduled_date=$today"
printf 'Daily GitHub workflow dispatched for Beijing day %s\n' "$today"
