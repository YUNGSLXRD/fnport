#!/bin/sh
# Remakes the static Inter files here from the variable font in Google Fonts:
# regular and semibold at text optical size, only Latin, Cyrillic and the signs the window uses.
# Needs Python with fonttools (pip install fonttools).
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -sSfo "$tmp/var.ttf" "https://raw.githubusercontent.com/google/fonts/main/ofl/inter/Inter%5Bopsz%2Cwght%5D.ttf"
curl -sSfo OFL.txt https://raw.githubusercontent.com/google/fonts/main/ofl/inter/OFL.txt
UNI="U+0020-007E,U+00A0-00FF,U+0400-045F,U+0490-0491,U+2010-2027,U+2030-203A,U+2116,U+2190-2195,U+2212,U+2264-2265,U+20BD"
for w in 400:Regular 600:SemiBold; do
	fonttools varLib.instancer -q "$tmp/var.ttf" wght="${w%%:*}" opsz=14 -o "$tmp/i.ttf"
	pyftsubset "$tmp/i.ttf" --unicodes="$UNI" --layout-features='kern,liga,calt,tnum,case' --output-file="Inter-${w##*:}.ttf"
done
ls -l Inter-*.ttf
