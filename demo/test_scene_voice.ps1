Add-Type -AssemblyName System.Speech
$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
$synth.SelectVoice("Microsoft David Desktop")
$synth.Rate = 0

$text1 = "Respected Reserve Bank of India Supervisory Committee. Today, commercial banks face severe operational and regulatory challenges during cyber incidents. Here in CYBERQ, we enforce strict separation of duties. Notice that even system administrators cannot read sensitive incident narratives or approve filings. Only authorized compliance officers have filing authority."

$synth.SetOutputToWaveFile("demo/scene_01_voice.wav")
$synth.Speak($text1)
$synth.Dispose()

Write-Output "Scene 1 voice generated."
