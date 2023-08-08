#!/bin/bash
set -eux

cmake --build build --target rtp_sap_demo --config Debug

ffmpeg -re -f lavfi -i aevalsrc="sin(440*2*PI*t)" -ar 8000 -f s16le -acodec pcm_s16le -f sap 'sap://239.0.0.1:1234' &
SERVER_PID_A=$!
ffmpeg -re -f lavfi -i aevalsrc="sin(880*2*PI*t)" -ar 8000 -f s16le -acodec pcm_s16le -f sap 'sap://239.0.0.1:1236' &
SERVER_PID_B=$!


function cleanup() {
    kill $SERVER_PID_A
    kill $SERVER_PID_B
}
trap cleanup EXIT

./build/rtp_sap_demo

