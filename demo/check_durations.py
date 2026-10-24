import subprocess, re, glob, os

ffmpeg = r"C:\Users\Om Avinash Watane\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg.Essentials_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-9.0.1-essentials_build\bin\ffmpeg.exe"

for i in range(1, 14):
    v_files = glob.glob(f"demo/clips/scene_{i:02d}_*.mp4")
    a_files = glob.glob(f"demo/audio/scene_{i:02d}_*.wav")
    if not v_files or not a_files:
        continue
    vf = v_files[0]
    af = a_files[0]
    
    # Probe video
    res_v = subprocess.run([ffmpeg, "-i", vf], stderr=subprocess.PIPE, text=True)
    mv = re.search(r"Duration:\s*(\d+):(\d+):(\d+\.\d+)", res_v.stderr)
    vdur = float(mv.group(1))*3600 + float(mv.group(2))*60 + float(mv.group(3)) if mv else 0
    
    # Probe audio
    res_a = subprocess.run([ffmpeg, "-i", af], stderr=subprocess.PIPE, text=True)
    ma = re.search(r"Duration:\s*(\d+):(\d+):(\d+\.\d+)", res_a.stderr)
    adur = float(ma.group(1))*3600 + float(ma.group(2))*60 + float(ma.group(3)) if ma else 0
    
    diff = vdur - adur
    print(f"Scene {i:02d}: Video = {vdur:5.2f}s | Audio = {adur:5.2f}s | Slack = {diff:5.2f}s")
