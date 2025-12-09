Set objShell = CreateObject("WScript.Shell")
strPath = "C:\Users\Lenovo\OneDrive\Документи\Навчання 3 курс\Важливо\SM4_Encryption_v2\sm4_app.py"
objShell.Run "python """ & strPath & """", 0
