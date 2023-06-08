message = "Please enter your distinguished name:"
title = "Convert DN to UPN"

Set sysInfo = CreateObject("ADSystemInfo")
distinguishedName = sysInfo.UserName

distinguishedName = InputBox(message, title, distinguishedName)

If Not IsEmpty(distinguishedName) And Len(distinguishedName) <> 0 Then
	Const ADS_NAME_INITTYPE_GC = 3
	Const ADS_NAME_TYPE_USER_PRINCIPAL_NAME = 9
	Const ADS_NAME_TYPE_1779 = 1

	Set nameTranslate = CreateObject("NameTranslate")
	nameTranslate.Init ADS_NAME_INITTYPE_GC, ""
	nameTranslate.Set ADS_NAME_TYPE_1779, distinguishedName
	userPrincipalName = nameTranslate.Get(ADS_NAME_TYPE_USER_PRINCIPAL_NAME)

	title = "Converted UPN"
	message = "The UPN for the DN '" & distinguishedName & "' is '" & userPrincipalName & "'"

	MsgBox message, 64, title
End If
