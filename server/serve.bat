@echo off
setlocal

title TSI Privacy Vault
:: Check if .env file exists
if not exist ".env" (
    echo Error: .env file not found. Please create it.
    exit /b 1
)

:: Parse .env file line by line
:: /F "tokens=1* delims==" means:
:: - read each line
:: - "tokens=1*" splits the line at the first '='
::   - token 1 gets the part before '=' (the variable name)
::   - token * gets all the rest of the line (the value), including spaces
:: - "delims==" specifies that '=' is the delimiter
for /f "tokens=1* delims==" %%A in (.env) do (
    :: Check if the line is not empty and not a comment (starts with #)
    if not "%%A"=="" (
        if not "%%A"=="::" (
            if not "%%A"=="#" (
                :: Set the environment variable
                set "%%A=%%B"
            )
        )
    )
)

set JAVA_HOME=%JAVA_HOME%
set TSI_PRIVACY_VAULT_ENV=%TSI_PRIVACY_VAULT_ENV%
set TSI_PRIVACY_VAULT_HOME=%TSI_PRIVACY_VAULT_HOME%
set POSTGRES_HOST=%POSTGRES_HOST%
set POSTGRES_DB=%POSTGRES_DB%
set POSTGRES_USER=%POSTGRES_USER%
set POSTGRES_PASSWD=%POSTGRES_PASSWD%
set JETTY_HOME=%JETTY_HOME%
set JETTY_BASE=%JETTY_BASE%
set AWS_ACCESS_KEY_ID=%AWS_ACCESS_KEY_ID%
set AWS_SECRET_ACCESS_KEY=%AWS_SECRET_ACCESS_KEY%
set AWS_REGION=%AWS_REGION%
set AWS_KMS_KEY_IDENTIFIER=%AWS_KMS_KEY_IDENTIFIER%
set TSI_LOOKUP_SALT=%TSI_LOOKUP_SALT%
copy %TSI_PRIVACY_VAULT_HOME%\target\tsi_privacy_vault.war %JETTY_BASE%\webapps\ROOT.war >NUL
java -jar %JETTY_HOME%/start.jar
