import subprocess, re, os

ffmpeg = r"C:\Users\Om Avinash Watane\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg.Essentials_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-9.0.1-essentials_build\bin\ffmpeg.exe"

scenes_meta = [
    (1, "scene_01_auth_roles",
     "Admin cannot read investigative narratives or approve filings.",
     "CYBERQ enforces bank-grade separation of duties. Even full system administrators cannot read sensitive incident narratives or approve regulatory filings."),
    (2, "scene_02_new_incident_triggers",
     "Simultaneous dual triggers bind CERT-In and RBI clocks at identical timestamps.",
     "Following bank incident commander SOP, CYBERQ simultaneously binds both CERT-In and RBI DAKSH statutory clocks with an immutable identical timestamp."),
    (3, "scene_03_active_clocks",
     "Active statutory countdowns with hoverable IST and UTC deadlines.",
     "Live statutory countdown dials calculate depleting deadlines monotonically, while pending obligations like DPDP remain honestly marked as pending trigger."),
    (4, "scene_04_pii_guard",
     "PII Guard flags real Aadhaar numbers while ignoring technical hashes.",
     "CYBERQ's PII Guard employs the Verhoeff algorithm to catch real personal data without generating false positives on IP addresses, hashes, or UUIDs."),
    (5, "scene_05_precautionary_rule",
     "Precautionary principle: answering 'No' keeps the statutory clock running.",
     "Under bank policy, a triage analyst cannot unilaterally stop a statutory clock. Answering 'no' keeps the countdown active until an approver confirms."),
    (6, "scene_06_maker_checker",
     "Dual-control maker-checker: makers cannot approve their own exemption requests.",
     "Dual-control maker-checker ensures regulatory integrity. The maker cannot approve their own exemption, requiring a senior approver's written sign-off."),
    (7, "scene_07_corridor_3d_fallback",
     "3D spatial runway tracks deadlines; falls back to 2D on mobile.",
     "The 3D Depth Runway maps time into physical distance with collision-free billboards, automatically falling back to 2D for mobile or low-spec displays."),
    (8, "scene_08_wallboard",
     "Wallboard displays incident clocks with zero confidential narrative leakage.",
     "Designed for open floor dispatch, the SOC Wallboard displays operational counters while verifiably leaking zero incident titles, narratives, or personnel names."),
    (9, "scene_09_audit_ledger",
     "Cryptographic SHA-256 hash chains detect offline log tampering instantly.",
     "Every state change is cryptographically chained. If an attacker or insider alters a single character in the audit log, offline verification immediately fails."),
    (10, "scene_10_themes_security",
     "Self-hosted air-gapped security headers with WCAG AA Day/Night themes.",
     "CYBERQ runs entirely air-gapped with self-hosted fonts and strict security headers, paired with tested high-contrast Day Ledger and Night Desk themes."),
    (11, "scene_11_fail_closed",
     "Fail-closed design: NTP drift over 1 second triggers manual fallback.",
     "To protect statutory deadline accuracy, CYBERQ fails closed if clock drift exceeds one second, directing staff to manual filing runbooks."),
    (12, "scene_12_quality_gates",
     "All 9 quality gates and 19 browser E2E tests pass.",
     "Every build passes nine automated supply-chain, security, and type gates, backed by nineteen comprehensive browser tests executing against the production build."),
    (13, "scene_13_roadmap",
     "Honest roadmap: Filing packets in M3, Board pack in M4.",
     "CYBERQ demonstrates only working software. Upcoming milestones—including human-approved filing packets and quarterly Board packs—are clearly marked on our roadmap.")
]

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

concat_lines = []
srt_blocks = []
narration_blocks = []

current_time = 0.0

for num, name, caption, narration in scenes_meta:
    clip_path = f"demo/clips/{name}.mp4"
    abs_clip_path = os.path.abspath(clip_path).replace("\\", "/")
    concat_lines.append(f"file '{abs_clip_path}'")
    
    res = subprocess.run([ffmpeg, "-i", clip_path], stderr=subprocess.PIPE, text=True)
    m = re.search(r"Duration:\s*(\d+):(\d+):(\d+\.\d+)", res.stderr)
    dur = float(m.group(1))*3600 + float(m.group(2))*60 + float(m.group(3)) if m else 25.0
    
    start_t = current_time
    end_t = current_time + dur
    current_time = end_t
    
    # SubRip block
    srt_blocks.append(f"{num}\n{format_srt_time(start_t)} --> {format_srt_time(end_t)}\n{caption}\n")
    
    # Narration block
    w_count = len(narration.split())
    wpm = (w_count / dur) * 60.0
    narration_blocks.append(
        f"[{format_clock_time(start_t)} - {format_clock_time(end_t)}] Scene {num}: {caption}\n"
        f"Duration: {dur:.1f}s | Word Count: {w_count} words | Pacing: {wpm:.1f} wpm\n"
        f"Narration: \"{narration}\"\n"
    )

with open("demo/concat_list.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(concat_lines) + "\n")
print("Wrote demo/concat_list.txt")

with open("demo/captions.srt", "w", encoding="utf-8") as f:
    f.write("\n".join(srt_blocks))
print("Wrote demo/captions.srt")

header = (
    "# CYBERQ Demonstration Narration Script\n\n"
    "Paced at standard professional presenter tempo (~130 words per minute).\n"
    f"Total Duration: {format_clock_time(current_time)} ({current_time:.1f}s)\n\n"
    "---\n\n"
)
with open("demo/narration.txt", "w", encoding="utf-8") as f:
    f.write(header + "\n".join(narration_blocks))
print("Wrote demo/narration.txt")

output_mp4 = "demo/CYBERQ_demo.mp4"
cmd = [ffmpeg, "-y", "-f", "concat", "-safe", "0", "-i", "demo/concat_list.txt", "-c", "copy", output_mp4]
print("Running FFmpeg concat...")
run_res = subprocess.run(cmd, capture_output=True, text=True)
if run_res.returncode == 0:
    print(f"Successfully assembled {output_mp4}!")
else:
    print("Concat failed:", run_res.stderr)
