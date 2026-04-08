#include "..\HashPassword.au3"

; Example: upgrade a verified legacy hash to the new PBKDF2 format.
; Replace the sample values with your own password input and stored hash lookup.

Local $sPassword = InputBox("HashPassword", "Enter the password to verify", "", "*")
Local $sStoredHash = "PUT_YOUR_STORED_HASH_HERE"

If Not _CheckPassword($sPassword, $sStoredHash) Then
	MsgBox(16, "HashPassword", "Password verification failed.")
	Exit 1
EndIf

If StringLeft($sStoredHash, StringLen($HP_PASSWORD_ALGORITHM) + 1) = $HP_PASSWORD_ALGORITHM & "$" Then
	MsgBox(0, "HashPassword", "Hash is already using the modern format.")
	Exit 0
EndIf

Local $sUpgradedHash = _HashPassword($sPassword)
If $sUpgradedHash = -1 Then
	MsgBox(16, "HashPassword", "Failed to create the upgraded hash.")
	Exit 1
EndIf

; Persist $sUpgradedHash in your database after successful verification.
MsgBox(0, "HashPassword", "Replace the legacy hash with:" & @CRLF & $sUpgradedHash)
