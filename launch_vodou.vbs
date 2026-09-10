' Launches Vodou with its optional live-control surface enabled (loopback,
' token-gated -- see remote_control.py and mcp_server/vodou_mcp.py). This is
' Supports desktop shortcuts and an optional URL/file argument.
' Running main.py directly (e.g. from a terminal) still launches with control
' OFF unless you set VODOU_ENABLE_CONTROL=1 yourself, same as before.
'
' Runs pythonw.exe hidden, exactly like a normal launch -- no console window,
' no visible script window.

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
projectDir = fso.GetParentFolderName(WScript.ScriptFullName)
shell.Environment("Process")("VODOU_ENABLE_CONTROL") = "1"
shell.CurrentDirectory = projectDir

' Create the environment first; see the Windows setup in README.md.
interpreter = fso.BuildPath(projectDir, ".venv\Scripts\pythonw.exe")
If Not fso.FileExists(interpreter) Then
    MsgBox "Vodou's Python environment is missing. Follow the Windows setup instructions in README.md to create .venv and install dependencies.", vbExclamation, "Vodou setup required"
    WScript.Quit 1
End If
pythonw = """" & interpreter & """"
mainpy = """" & fso.BuildPath(projectDir, "main.py") & """"

If WScript.Arguments.Count > 0 Then
    shell.Run pythonw & " " & mainpy & " """ & WScript.Arguments(0) & """", 0, False
Else
    shell.Run pythonw & " " & mainpy, 0, False
End If
