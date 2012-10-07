REM @echo off

SET PATH_JARSIGNER="c:\Program Files (x86)\Java\jdk1.7.0_04\bin\jarsigner.exe"

REM sign applet
%PATH_JARSIGNER% -keystore firmacodigo.p12 -storetype pkcs12 -signedJar appletCATCERTs.jar  appletCATCERT.jar firmacodigo