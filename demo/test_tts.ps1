Add-Type -AssemblyName System.Speech
$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
$synth.GetInstalledVoices() | ForEach-Object {
    Write-Output "Voice: $($_.VoiceInfo.Name) ($($_.VoiceInfo.Culture))"
}
$synth.SetOutputToWaveFile("demo/test_voice.wav")
$synth.Speak("Respected Reserve Bank of India Manager, welcome to the demonstration of CYBERQ.")
$synth.Dispose()
Write-Output "Test WAV created successfully."
