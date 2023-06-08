message = "Please enter your user principal name:"
title = "Convert UPN to DN"

Set shell = WScript.CreateObject("WScript.Shell")
samAccountName = shell.ExpandEnvironmentStrings("%USERNAME%")
realm = shell.ExpandEnvironmentStrings("%USERDNSDOMAIN%")

userPrincipalName = samAccountName & "@" & realm
userPrincipalName = InputBox(message, title, userPrincipalName)

If Not IsEmpty(userPrincipalName) And Len(userPrincipalName) <> 0 Then
	Const ADS_NAME_INITTYPE_GC = 3
	Const ADS_NAME_TYPE_USER_PRINCIPAL_NAME = 9
	Const ADS_NAME_TYPE_1779 = 1

	Set nameTranslate = CreateObject("NameTranslate")
	nameTranslate.Init ADS_NAME_INITTYPE_GC, ""
	nameTranslate.Set ADS_NAME_TYPE_USER_PRINCIPAL_NAME, userPrincipalName
	distinguishedName = nameTranslate.Get(ADS_NAME_TYPE_1779)

	title = "Converted DN"
	message = "The DN for the UPN '" & userPrincipalName & "' is '" & distinguishedName & "'"

	MsgBox message, 64, title
End If
