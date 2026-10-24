Add-Type -AssemblyName System.Speech
$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
$synth.SelectVoice("Microsoft David Desktop")
$synth.Rate = 1

$scenes = @(
    @{
        id = "scene_01_auth_roles"
        text = "Respected Reserve Bank of India Supervisory Committee. During major cyber incidents, banks face severe operational and regulatory exposure. In CYBERQ, we enforce bank-grade separation of duties. Notice that system administrators are strictly blocked from reading investigative narratives or approving regulatory filings, preserving integrity."
    },
    @{
        id = "scene_02_new_incident_triggers"
        text = "Consider a live commercial banking crisis: at two o'clock in the morning, our core border switch handling RTGS interbank payment traffic experiences route flapping. In traditional banks, triage takes hours before anyone notifies the regulator. In CYBERQ, the incident is logged immediately under standard operating procedure. Watch closely as the SOC analyst asserts the statutory trigger. Under RBI Cyber Security circulars and CERT-In directions, both statutory clocks, CERT-In six hours for notice, and RBI DAKSH six hours for detection, bind simultaneously with an immutable, identical cryptographic timestamp. Neither clock can be backdated or suppressed. Regulatory accountability begins the exact second the anomaly is detected."
    },
    @{
        id = "scene_03_active_clocks"
        text = "Once triggered, CYBERQ's statutory clock strip displays real-time countdown dials visible across the enterprise. Notice the synchronized six-hour deadlines for CERT-In and RBI DAKSH, with instant local Indian Standard Time and UTC hover calibration. Obligations not yet triggered, like DPDP, are honestly marked as pending trigger."
    },
    @{
        id = "scene_04_pii_guard"
        text = "A major compliance risk in bank incident filing is accidental leakage of customer personal data into regulatory portals. CYBERQ features an air-gapped PII Guard. Technical strings like IP addresses, UUIDs, and SHA-256 hashes are recognized and safely passed. But when a valid twelve-digit Aadhaar number is pasted, the Verhoeff algorithm intercepts it with a soft warning. Analysts cannot bypass this without an explicit, audited override recorded in the permanent ledger."
    },
    @{
        id = "scene_05_precautionary_rule"
        text = "Under RBI precautionary principles, a frontline triage analyst who answers 'No' to personal data or reportability cannot unilaterally halt a statutory countdown. Notice here: even after answering 'No', statutory countdown clocks continue running. Only a designated senior checker can confirm an exemption."
    },
    @{
        id = "scene_06_maker_checker"
        text = "This brings us to dual-control maker-checker governance. Under RBI IT Governance Directions 2023, the maker who logs an exemption request cannot approve it. A compliance checker must inspect the decision ledger, review technical rationale, and provide formal dual-authorization before any clock is stopped."
    },
    @{
        id = "scene_07_corridor_3d_fallback"
        text = "To provide incident commanders spatial clarity under stress, CYBERQ provides an air-gapped 3D Statutory Runway built on Three.js. Deadlines are visualized as physical distance with collision-free billboards. On mobile devices or low-spec crisis laptops, the runway automatically unmounts into high-contrast 2D cards."
    },
    @{
        id = "scene_08_wallboard"
        text = "For trading floors, SOC video walls, and executive dispatch centers, CYBERQ provides the ambient wallboard. By architectural guarantee, the wallboard displays countdown horizons and severity metrics, while leaking zero customer account details, confidential narratives, or operator identities to open room cameras."
    },
    @{
        id = "scene_09_audit_ledger"
        text = "For RBI inspection teams and IS auditors, CYBERQ replaces editable databases with an immutable SHA-256 cryptographic hash chain with Ed25519 signatures. Every trigger, edit, and approval links to the prior event. When an offline inspector verifies the export, any unauthorized modification triggers an immediate integrity violation."
    },
    @{
        id = "scene_10_themes_security"
        text = "Banking software must operate in zero-trust, air-gapped environments. CYBERQ bundles self-hosted IBM Plex typography with zero runtime CDN calls. Strict Content Security Policy headers protect the session, and both Day Ledger and Night Desk themes strictly pass WCAG AA contrast standards."
    },
    @{
        id = "scene_11_fail_closed"
        text = "What happens if server time drifts? Under statutory guidelines, timestamps must be legally defensible. If Network Time Protocol drift exceeds one second, CYBERQ immediately fails closed, returns HTTP 503, and activates the documented manual filing runbook per bank standard operating procedure."
    },
    @{
        id = "scene_12_quality_gates"
        text = "Every deployment of CYBERQ is backed by rigorous automated verification. As an RBI examiner would expect, our CI/CD pipeline enforces nine automated quality gates, including strict typing, AST security scans, secret leak checks, and nineteen browser end-to-end tests, ensuring production readiness before bank deployment."
    },
    @{
        id = "scene_13_roadmap"
        text = "Finally, CYBERQ upholds complete transparency. Future capabilities, including automated PDF board packs and formal DAKSH XML filing packets, are marked honestly as roadmap. We show you only verified, working code. CYBERQ transforms cyber crisis management into defensible, board-ready governance."
    }
)

if (-not (Test-Path "demo/audio")) {
    New-Item -ItemType Directory -Path "demo/audio" | Out-Null
}

foreach ($s in $scenes) {
    $outPath = "demo/audio/$($s.id).wav"
    $synth.SetOutputToWaveFile($outPath)
    $synth.Speak($s.text)
    Write-Output "Generated: $outPath"
}

$synth.Dispose()
Write-Output "All 13 audio tracks generated successfully."
