import subprocess, re, os, glob, json

repo_root = os.path.abspath(os.path.dirname(__file__) + "/..")
ffmpeg = r"C:\Users\Om Avinash Watane\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg.Essentials_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-9.0.1-essentials_build\bin\ffmpeg.exe"

scenes_data = [
    {
        "num": 1,
        "id": "scene_01_auth_roles",
        "caption": "Admin cannot read investigative narratives or approve filings.",
        "pitch": "Respected Reserve Bank of India Supervisory Committee. During major cyber incidents, commercial banks face severe operational and regulatory exposure. In CYBERQ, we enforce bank-grade separation of duties. Notice that system administrators are strictly blocked from reading investigative narratives or approving regulatory filings, preserving investigative integrity."
    },
    {
        "num": 2,
        "id": "scene_02_new_incident_triggers",
        "caption": "Simultaneous dual triggers bind CERT-In and RBI clocks at identical timestamps.",
        "pitch": "Consider a live commercial banking crisis: at two o'clock in the morning, our core border switch handling RTGS interbank payment traffic experiences route flapping and packet drops. In traditional banks, triage takes hours before anyone notifies the regulator. In CYBERQ, the incident is logged immediately under bank standard operating procedure. Watch closely as the SOC analyst asserts the statutory trigger. Under RBI Cyber Security circulars and CERT-In directions, both statutory clocks, CERT-In six hours for notice, and RBI DAKSH six hours for detection, bind simultaneously with an immutable, identical cryptographic timestamp. Neither clock can be backdated or suppressed. Regulatory accountability begins the exact second the anomaly is detected."
    },
    {
        "num": 3,
        "id": "scene_03_active_clocks",
        "caption": "Active statutory countdowns with hoverable IST and UTC deadlines.",
        "pitch": "Once triggered, CYBERQ's statutory clock strip displays real-time countdown dials visible across the enterprise. Notice the synchronized six-hour deadlines for CERT-In and RBI DAKSH, with instant local Indian Standard Time and UTC hover calibration. Obligations not yet triggered, like DPDP, are honestly marked as pending trigger, preventing false alarms."
    },
    {
        "num": 4,
        "id": "scene_04_pii_guard",
        "caption": "PII Guard flags real Aadhaar numbers while ignoring technical hashes.",
        "pitch": "A critical compliance risk in bank incident filing is accidental leakage of customer personal data into regulatory portals. CYBERQ features an intelligent air-gapped PII Guard. Technical strings like IP addresses, UUIDs, and SHA-256 hashes are recognized as operational telemetry and safely passed without false alarms. But when an analyst pastes a valid twelve-digit Aadhaar number, the Verhoeff mathematical algorithm immediately intercepts it with a soft warning banner. Analysts cannot bypass this without an explicit, audited override recorded in the permanent ledger."
    },
    {
        "num": 5,
        "id": "scene_05_precautionary_rule",
        "caption": "Precautionary principle: answering 'No' keeps the statutory clock running.",
        "pitch": "Under RBI precautionary principles, a frontline triage analyst who answers 'No' to personal data or reportability cannot unilaterally halt a statutory countdown. Notice here: even after answering 'No', statutory countdown clocks continue running. Only a designated senior checker can confirm an exemption."
    },
    {
        "num": 6,
        "id": "scene_06_maker_checker",
        "caption": "Dual-control maker-checker: makers cannot approve their own exemption requests.",
        "pitch": "This brings us to dual-control maker-checker governance. Under RBI IT Governance Directions 2023, the maker who logs an exemption request cannot approve it. A compliance checker must inspect the decision ledger, review technical rationale, and provide formal dual-authorization before any clock is stopped."
    },
    {
        "num": 7,
        "id": "scene_07_corridor_3d_fallback",
        "caption": "3D spatial runway tracks deadlines; falls back to 2D on mobile.",
        "pitch": "To provide incident commanders spatial clarity under stress, CYBERQ provides an air-gapped 3D Statutory Runway built on Three.js. Deadlines are visualized as physical distance with collision-free billboards. On mobile devices or low-spec crisis laptops, the runway automatically unmounts into high-contrast 2D cards."
    },
    {
        "num": 8,
        "id": "scene_08_wallboard",
        "caption": "Wallboard displays incident clocks with zero confidential narrative leakage.",
        "pitch": "For trading floors, SOC video walls, and executive dispatch centers, CYBERQ provides the ambient wallboard. By architectural guarantee, the wallboard displays countdown horizons and severity metrics, while leaking zero customer account details, confidential narratives, or operator identities to open room cameras."
    },
    {
        "num": 9,
        "id": "scene_09_audit_ledger",
        "caption": "Cryptographic SHA-256 hash chains detect offline log tampering instantly.",
        "pitch": "For RBI inspection teams and IS auditors, CYBERQ replaces editable databases with an immutable SHA-256 cryptographic hash chain with Ed25519 signatures. Every trigger, edit, and approval links to the prior event. When an offline inspector verifies the export, any unauthorized modification triggers an immediate integrity violation."
    },
    {
        "num": 10,
        "id": "scene_10_themes_security",
        "caption": "Self-hosted air-gapped security headers with WCAG AA Day/Night themes.",
        "pitch": "Banking software must operate in zero-trust, air-gapped environments. CYBERQ bundles self-hosted IBM Plex typography with zero runtime CDN calls. Strict Content Security Policy headers protect the session, and both Day Ledger and Night Desk themes strictly pass WCAG AA contrast standards."
    },
    {
        "num": 11,
        "id": "scene_11_fail_closed",
        "caption": "Fail-closed design: NTP drift over 1 second triggers manual fallback.",
        "pitch": "What happens if server time drifts? Under statutory guidelines, timestamps must be legally defensible. If Network Time Protocol drift exceeds one second, CYBERQ immediately fails closed, returns HTTP 503, and activates the documented manual filing runbook per bank standard operating procedure."
    },
    {
        "num": 12,
        "id": "scene_12_quality_gates",
        "caption": "All 9 quality gates and 19 browser E2E tests pass.",
        "pitch": "Every deployment of CYBERQ is backed by rigorous automated verification. As an RBI examiner would expect, our CI/CD pipeline enforces nine automated quality gates, including strict typing, AST security scans, secret leak checks, and nineteen browser end-to-end tests, ensuring production readiness before bank deployment."
    },
    {
        "num": 13,
        "id": "scene_13_roadmap",
        "caption": "Honest roadmap: Filing packets in M3, Board pack in M4.",
        "pitch": "Finally, CYBERQ upholds complete transparency. Future capabilities, including automated PDF board packs and formal DAKSH XML filing packets, are marked honestly as roadmap. We show you only verified, working code. CYBERQ transforms cyber crisis management into defensible, board-ready governance."
    }
]

print(">>> Step 1: Generating Speech Audio Tracks...")
os.makedirs("demo/audio", exist_ok=True)
os.makedirs("demo/clips_with_audio", exist_ok=True)

# Generate audio via PowerShell script
ps_script = """
Add-Type -AssemblyName System.Speech
$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
$synth.SelectVoice("Microsoft David Desktop")
$synth.Rate = 1
"""

for s in scenes_data:
    clean_pitch = s["pitch"].replace('"', '`"')
    ps_script += f"""
$synth.SetOutputToWaveFile("demo/audio/{s['id']}.wav")
$synth.Speak("{clean_pitch}")
"""

ps_script += """
$synth.Dispose()
Write-Output "Done generating all audio."
"""

with open("demo/gen_tts_tmp.ps1", "w", encoding="utf-8") as f:
    f.write(ps_script)

res_ps = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", "demo/gen_tts_tmp.ps1"], capture_output=True, text=True)
print("TTS generation:", res_ps.stdout.strip())
if os.path.exists("demo/gen_tts_tmp.ps1"):
    os.remove("demo/gen_tts_tmp.ps1")

print("\n>>> Step 2: Muxing Audio with Each Scene Video (with padding to exact length)...")
input_files = []
filter_inputs = []

for idx, s in enumerate(scenes_data):
    v_path = f"demo/clips/{s['id']}.mp4"
    a_path = f"demo/audio/{s['id']}.wav"
    muxed_path = f"demo/clips_with_audio/{s['id']}.mp4"
    
    # Delay audio by 350ms for natural start, then apad to fill video length
    mux_cmd = [
        ffmpeg, "-y",
        "-i", v_path,
        "-i", a_path,
        "-filter_complex", "[1:a]adelay=350|350,apad[a]",
        "-map", "0:v", "-map", "[a]",
        "-c:v", "copy",
        "-c:a", "aac", "-b:a", "192k", "-ar", "44100",
        "-shortest",
        muxed_path
    ]
    subprocess.run(mux_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"  Muxed Scene {s['num']:02d}: {s['id']}")
    
    input_files.extend(["-i", muxed_path])
    filter_inputs.append(f"[{idx}:v][{idx}:a]")

print("\n>>> Step 3: Concatenating and Re-encoding All 13 Scenes into Unified Master Stream...")
concat_filter = "".join(filter_inputs) + f"concat=n={len(scenes_data)}:v=1:a=1[v][a]"

out_video = "demo/CYBERQ_demo.mp4"
final_cmd = [
    ffmpeg, "-y"
] + input_files + [
    "-filter_complex", concat_filter,
    "-map", "[v]", "-map", "[a]",
    "-c:v", "libx264", "-preset", "fast", "-crf", "20",
    "-pix_fmt", "yuv420p", "-r", "30", "-g", "60",
    "-c:a", "aac", "-b:a", "192k", "-ar", "44100",
    out_video
]

print("Encoding master video (this creates a continuous unbroken elementary stream)...")
res_master = subprocess.run(final_cmd, capture_output=True, text=True)
if res_master.returncode == 0:
    print(f"Master video created successfully: {out_video}")
else:
    print("Master video encoding error:", res_master.stderr[-1000:])

print("\n>>> Step 4: Generating Synchronized SRT and Narration Script...")
# Measure final timestamps from muxed clips
def format_srt_time(seconds):
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    ms = int(round((seconds - int(seconds)) * 1000))
    if ms >= 1000:
        ms = 999
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"

def format_clock_time(seconds):
    m = int(seconds // 60)
    s = int(seconds % 60)
    return f"{m:02d}:{s:02d}"

srt_blocks = []
narration_blocks = []
current_time = 0.0

for s in scenes_data:
    muxed_path = f"demo/clips_with_audio/{s['id']}.mp4"
    probe = subprocess.run([ffmpeg, "-i", muxed_path], stderr=subprocess.PIPE, text=True)
    m = re.search(r"Duration:\s*(\d+):(\d+):(\d+\.\d+)", probe.stderr)
    dur = float(m.group(1))*3600 + float(m.group(2))*60 + float(m.group(3)) if m else 23.0
    
    start_t = current_time
    end_t = current_time + dur
    current_time = end_t
    
    srt_blocks.append(f"{s['num']}\n{format_srt_time(start_t)} --> {format_srt_time(end_t)}\n{s['caption']}\n")
    
    w_count = len(s["pitch"].split())
    wpm = (w_count / dur) * 60.0
    narration_blocks.append(
        f"[{format_clock_time(start_t)} - {format_clock_time(end_t)}] Scene {s['num']}: {s['caption']}\n"
        f"Duration: {dur:.1f}s | Word Count: {w_count} words | Presentation Pacing: {wpm:.1f} wpm\n"
        f"RBI Pitch Narration:\n\"{s['pitch']}\"\n"
    )

with open("demo/captions.srt", "w", encoding="utf-8") as f:
    f.write("\n".join(srt_blocks))
print("Wrote demo/captions.srt")

header = (
    "# CYBERQ Executive Pitch & Demonstration Narration Script\n\n"
    "Audience: Reserve Bank of India (RBI) Senior Supervisory Team / IT Examination Cell\n"
    f"Total Presentation Duration: {format_clock_time(current_time)} ({current_time:.1f}s)\n"
    "Tone: Authoritative, respectful, regulatory-compliant, banking-grade.\n\n"
    "---\n\n"
)
with open("demo/narration.txt", "w", encoding="utf-8") as f:
    f.write(header + "\n".join(narration_blocks))
print("Wrote demo/narration.txt")

# Copy to artifacts directory
artifact_dir = r"C:\Users\Om Avinash Watane\.gemini\antigravity\brain\5805ddb1-1b03-4c70-9000-4730144da056"
if os.path.exists(artifact_dir):
    import shutil
    dest = os.path.join(artifact_dir, "CYBERQ_demo.mp4")
    shutil.copy2(out_video, dest)
    print(f"Copied master video to artifact: {dest}")

print("\nAll done!")
