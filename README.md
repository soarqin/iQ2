Usage
=====
1. Install [npcap(for Win7/8/10)](https://nmap.org/npcap/) or [winpcap(WinXP/7/8/10)](https://winpcap.org)
2. [optional] Install [FFmpeg](https://ffmpeg.zeranoe.com/builds/) in PATH so that you can use ffmpeg to call it anywhere.
3. Open terminal and run `iQ2` to see ethernet device list with their index
4. Run `iQ2 <number>` to select a device to capture
5. Open anime episode on iQIYI, slide the video @ every 3-6 minutes (depends, iQIYI splits videos into 3 or 6 minutes)
6. Press CTRL+C in terminal to stop capturing, the program will start downloading anime episodes automatically and merge them into a single mp4 if FFmpeg is installed
