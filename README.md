Usage
=====
1. [optional] Install [FFmpeg](https://ffmpeg.zeranoe.com/builds/) in PATH so that you can type `ffmpeg` to call it anywhere.
2. Chrome-based browser, press F12 to call up `DevTools` and switch to `Network` tab
3. Open anime episode on iQIYI, slide the video @ every 3-6 minutes (depends, iQIYI splits videos into 3 or 6 minutes)
4. Right-click in `Network` tab and choose `Save as HAR with content`, save HAR file to local disk
5. Open terminal and run `iQ2 <filename>`, that `<filename>` is the HAR file just saved. The program will start downloading anime episodes automatically and merge them into a single mp4 if FFmpeg is installed
