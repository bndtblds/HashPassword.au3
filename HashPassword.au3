; SPDX-FileCopyrightText: 2012 HashPassword.au3 contributors
; SPDX-License-Identifier: MIT

#include-once
#include <Crypt.au3>

Global Const $HP_VERSION = "2.0.0"
Global Const $HP_PASSWORD_ALGORITHM = "pbkdf2-sha256"
Global Const $HP_PASSWORD_ITERATIONS = 600000
Global Const $HP_PASSWORD_SALT_SIZE = 16
Global Const $HP_PASSWORD_KEY_SIZE = 32
Global Const $HP_BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008
Global Const $HP_BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002

; Hashes a password using PBKDF2-HMAC-SHA256.
; Introduced as the default format in HashPassword.au3 v2.0.0.
; Returns "pbkdf2-sha256$iterations$salthex$derivedkeyhex" on success, or -1 on failure.
; $inSalt is optional and may be passed as Binary, hex string, or plain text.
Func _HashPassword($inPwd, $inSalt = "")
	Local $bSalt = __HashPassword_NormalizeSalt($inSalt)
	If @error Then Return SetError(@error, @extended, -1)

	If BinaryLen($bSalt) = 0 Then
		$bSalt = __HashPassword_GenerateRandom($HP_PASSWORD_SALT_SIZE)
		If @error Then Return SetError(@error, @extended, -1)
	EndIf

	Local $bPassword = StringToBinary($inPwd, 4)
	Local $bDerivedKey = __HashPassword_PBKDF2($bPassword, $bSalt, $HP_PASSWORD_ITERATIONS, $HP_PASSWORD_KEY_SIZE)
	If @error Then Return SetError(@error, @extended, -1)

	Return $HP_PASSWORD_ALGORITHM & "$" & $HP_PASSWORD_ITERATIONS & "$" & Hex($bSalt) & "$" & Hex($bDerivedKey)
EndFunc   ;==>_HashPassword

; Verifies a password against a stored hash.
; Supports the current PBKDF2 format and the legacy "hash$salt" format.
; Legacy compatibility is retained in HashPassword.au3 v2.0.0 to support migration.
; Returns True when the password matches, otherwise False.
Func _CheckPassword($inPwd, $inHash)
	Local $aHash = StringSplit($inHash, "$")
	If Not IsArray($aHash) Then Return False

	If $aHash[0] = 4 And $aHash[1] = $HP_PASSWORD_ALGORITHM Then
		Local $iIterations = Int($aHash[2])
		If $iIterations < 1 Then Return False
		If Not __HashPassword_IsHex($aHash[3]) Then Return False
		If Not __HashPassword_IsHex($aHash[4]) Then Return False

		Local $bSalt = Binary("0x" & $aHash[3])
		Local $bExpected = Binary("0x" & $aHash[4])
		Local $bPassword = StringToBinary($inPwd, 4)
		Local $bActual = __HashPassword_PBKDF2($bPassword, $bSalt, $iIterations, BinaryLen($bExpected))
		If @error Then Return False

		Return __HashPassword_ConstantTimeEquals($bActual, $bExpected)
	EndIf

	If $aHash[0] = 2 Then
		Return __HashPassword_CheckLegacy($inPwd, $inHash)
	EndIf

	Return False
EndFunc   ;==>_CheckPassword

Func __HashPassword_PBKDF2($bPassword, $bSalt, $iIterations, $iKeyLength)
	Local $aOpen = DllCall("bcrypt.dll", "long", "BCryptOpenAlgorithmProvider", "handle*", 0, "wstr", "SHA256", "ptr", 0, "ulong", $HP_BCRYPT_ALG_HANDLE_HMAC_FLAG)
	If @error Or $aOpen[0] <> 0 Then Return SetError(1, @error, -1)

	Local $hAlgorithm = $aOpen[1]
	Local $tPassword = 0
	Local $tSalt = 0
	Local $tDerived = DllStructCreate("byte[" & $iKeyLength & "]")
	Local $iPasswordLength = BinaryLen($bPassword)
	Local $iSaltLength = BinaryLen($bSalt)
	Local $aDerive

	If $iPasswordLength > 0 Then
		$tPassword = DllStructCreate("byte[" & $iPasswordLength & "]")
		DllStructSetData($tPassword, 1, $bPassword)
	EndIf

	If $iSaltLength > 0 Then
		$tSalt = DllStructCreate("byte[" & $iSaltLength & "]")
		DllStructSetData($tSalt, 1, $bSalt)
	EndIf

	Switch True
		Case $iPasswordLength = 0 And $iSaltLength = 0
			$aDerive = DllCall("bcrypt.dll", "long", "BCryptDeriveKeyPBKDF2", "handle", $hAlgorithm, "ptr", 0, "ulong", 0, "ptr", 0, "ulong", 0, "uint64", $iIterations, "struct*", $tDerived, "ulong", $iKeyLength, "ulong", 0)
		Case $iPasswordLength = 0
			$aDerive = DllCall("bcrypt.dll", "long", "BCryptDeriveKeyPBKDF2", "handle", $hAlgorithm, "ptr", 0, "ulong", 0, "struct*", $tSalt, "ulong", $iSaltLength, "uint64", $iIterations, "struct*", $tDerived, "ulong", $iKeyLength, "ulong", 0)
		Case $iSaltLength = 0
			$aDerive = DllCall("bcrypt.dll", "long", "BCryptDeriveKeyPBKDF2", "handle", $hAlgorithm, "struct*", $tPassword, "ulong", $iPasswordLength, "ptr", 0, "ulong", 0, "uint64", $iIterations, "struct*", $tDerived, "ulong", $iKeyLength, "ulong", 0)
		Case Else
			$aDerive = DllCall("bcrypt.dll", "long", "BCryptDeriveKeyPBKDF2", "handle", $hAlgorithm, "struct*", $tPassword, "ulong", $iPasswordLength, "struct*", $tSalt, "ulong", $iSaltLength, "uint64", $iIterations, "struct*", $tDerived, "ulong", $iKeyLength, "ulong", 0)
	EndSwitch

	Local $iDeriveError = @error
	Local $aClose = DllCall("bcrypt.dll", "long", "BCryptCloseAlgorithmProvider", "handle", $hAlgorithm, "ulong", 0)
	Local $iCloseError = @error
	If $iDeriveError Then Return SetError(2, $iDeriveError, -1)
	If $iCloseError Then Return SetError(3, $iCloseError, -1)
	If $aDerive[0] <> 0 Then Return SetError(3, $aDerive[0], -1)
	If $aClose[0] <> 0 Then Return SetError(4, $aClose[0], -1)

	Return DllStructGetData($tDerived, 1)
EndFunc   ;==>__HashPassword_PBKDF2

Func __HashPassword_GenerateRandom($iLength)
	Local $tRandom = DllStructCreate("byte[" & $iLength & "]")
	Local $aCall = DllCall("bcrypt.dll", "long", "BCryptGenRandom", "ptr", 0, "struct*", $tRandom, "ulong", $iLength, "ulong", $HP_BCRYPT_USE_SYSTEM_PREFERRED_RNG)
	If @error Or $aCall[0] <> 0 Then Return SetError(1, @error, -1)
	Return DllStructGetData($tRandom, 1)
EndFunc   ;==>__HashPassword_GenerateRandom

Func __HashPassword_NormalizeSalt($vSalt)
	If IsBinary($vSalt) Then Return $vSalt
	If $vSalt = "" Then Return Binary("")

	If __HashPassword_IsHex($vSalt) Then
		Return Binary("0x" & StringRegExpReplace($vSalt, "(?i)^0x", ""))
	EndIf

	Return StringToBinary($vSalt, 4)
EndFunc   ;==>__HashPassword_NormalizeSalt

Func __HashPassword_IsHex($sValue)
	Local $sHex = StringRegExpReplace($sValue, "(?i)^0x", "")
	If $sHex = "" Then Return False
	If Mod(StringLen($sHex), 2) <> 0 Then Return False
	Return StringRegExp($sHex, "(?i)^[0-9a-f]+$")
EndFunc   ;==>__HashPassword_IsHex

Func __HashPassword_ConstantTimeEquals($bLeft, $bRight)
	Local $sLeft = Hex($bLeft)
	Local $sRight = Hex($bRight)
	If StringLen($sLeft) <> StringLen($sRight) Then Return False

	Local $iDiff = 0
	Local $iLength = StringLen($sLeft)
	Local $i
	For $i = 1 To $iLength Step 2
		$iDiff = BitOR($iDiff, BitXOR(Dec(StringMid($sLeft, $i, 2)), Dec(StringMid($sRight, $i, 2))))
	Next

	Return $iDiff = 0
EndFunc   ;==>__HashPassword_ConstantTimeEquals

Func __HashPassword_CheckLegacy($inPwd, $inHash)
	Return __HashPassword_HashLegacy($inPwd, StringTrimLeft($inHash, StringInStr($inHash, "$"))) = $inHash
EndFunc   ;==>__HashPassword_CheckLegacy

Func __HashPassword_HashLegacy($inPwd, $inSalt = "")
	Local Const $CALG_SHA512 = 0x0000800e
	Local $hAlg = $CALG_SHA512
	Local $sSalt = ""
	Local $sHash = ""
	Local $i
	Local $sPassword = StringStripWS($inPwd, 1 + 2)
	Local $aSalt = StringSplit("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "")

	If $inSalt = "" Then
		For $i = 1 To 40
			$sSalt &= $aSalt[Random(1, $aSalt[0], 1)]
		Next
	Else
		$sSalt = $inSalt
	EndIf

	If _Crypt_Startup() = False Then
		Return -1
	EndIf

	$sHash = $sPassword & $sSalt
	For $i = 1 To 256
		$sHash = _Crypt_HashData($sHash, $hAlg)
		If $sHash = -1 Then
			_Crypt_Shutdown()
			Return -1
		EndIf
		$sHash = StringMid($sHash, 3)
	Next
	_Crypt_Shutdown()

	Return $sHash & "$" & $sSalt
EndFunc   ;==>__HashPassword_HashLegacy
