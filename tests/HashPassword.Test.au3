#include "..\HashPassword.au3"

Global $g_iFailures = 0

_TestKnownPBKDF2Vector()
_TestModernHashVerification()
_TestLegacyHashVerification()

If $g_iFailures = 0 Then
	ConsoleWrite("All tests passed." & @CRLF)
	Exit 0
EndIf

	ConsoleWrite("Tests failed: " & $g_iFailures & @CRLF)
Exit 1

Func _TestKnownPBKDF2Vector()
	Local Const $sName = "Known PBKDF2-SHA256 vector"
	Local $sActual = _HashPassword("password", "73616C7473616C74")
	Local $sExpected = "pbkdf2-sha256$600000$73616C7473616C74$165C4D71855789D71C8CB8B444958E5A0906FCB536EA2677F9D0A708106AE9D2"

	_AssertEquals($sName, $sExpected, $sActual)
EndFunc   ;==>_TestKnownPBKDF2Vector

Func _TestModernHashVerification()
	Local Const $sName = "Modern hash verification"
	Local $sHash = _HashPassword("Correct Horse Battery Staple")

	If $sHash = -1 Then
		_Fail($sName, "Hash generation returned -1.")
		Return
	EndIf

	_AssertTrue($sName & " accepts the correct password", _CheckPassword("Correct Horse Battery Staple", $sHash))
	_AssertFalse($sName & " rejects the wrong password", _CheckPassword("wrong", $sHash))
EndFunc   ;==>_TestModernHashVerification

Func _TestLegacyHashVerification()
	Local Const $sName = "Legacy hash compatibility"
	Local $sLegacyHash = __HashPassword_HashLegacy(" password ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcd")

	If $sLegacyHash = -1 Then
		_Fail($sName, "Legacy hash generation returned -1.")
		Return
	EndIf

	_AssertTrue($sName & " keeps legacy verification working", _CheckPassword(" password ", $sLegacyHash))
	_AssertTrue($sName & " preserves trimmed legacy behavior", _CheckPassword("password", $sLegacyHash))
EndFunc   ;==>_TestLegacyHashVerification

Func _AssertEquals($sName, $vExpected, $vActual)
	If $vExpected = $vActual Then
		ConsoleWrite("[PASS] " & $sName & @CRLF)
		Return
	EndIf

	_Fail($sName, "Expected '" & $vExpected & "' but got '" & $vActual & "'.")
EndFunc   ;==>_AssertEquals

Func _AssertTrue($sName, $bCondition)
	If $bCondition Then
		ConsoleWrite("[PASS] " & $sName & @CRLF)
		Return
	EndIf

	_Fail($sName, "Expected True but got False.")
EndFunc   ;==>_AssertTrue

Func _AssertFalse($sName, $bCondition)
	If Not $bCondition Then
		ConsoleWrite("[PASS] " & $sName & @CRLF)
		Return
	EndIf

	_Fail($sName, "Expected False but got True.")
EndFunc   ;==>_AssertFalse

Func _Fail($sName, $sMessage)
	$g_iFailures += 1
	ConsoleWrite("[FAIL] " & $sName & ": " & $sMessage & @CRLF)
EndFunc   ;==>_Fail
