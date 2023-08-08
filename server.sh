#!/bin/bash
set -eux
exec ffmpeg -re -f lavfi -i aevalsrc="sin(400*2*PI*t)" -ar 8000 -f s16le -acodec pcm_s16le -f sap 'sap://239.0.0.1:1234'
