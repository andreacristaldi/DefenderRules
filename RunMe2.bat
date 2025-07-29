@echo off
setlocal

set "folder_path1=output_mpasbase"

REM Check if the folder exists
if not exist "%folder_path1%" (
    echo The folder does not exist. Creating...
    mkdir "%folder_path1%"
    echo Folder successfully created.
) else (
    echo The folder already exists.
)

echo The folder already exists.

DefenderRules.exe mpasbase.vdm.decompressed "%folder_path1%"

set "folder_path2=output_mpasdlta"

REM Check if the folder exists
if not exist "%folder_path2%" (
    echo The folder does not exist. Creating...
    mkdir "%folder_path2%"
    echo Check if the folder exists
) else (
    echo The folder already exists.
)

echo The folder already exists.

DefenderRules.exe mpasdlta.vdm.decomprressed "%folder_path2%"



set "folder_path3=output_mpavbase"

REM Check if the folder exists
if not exist "%folder_path3%" (
    echo The folder does not exist. Creating...
    mkdir "%folder_path3%"
    echo Check if the folder exists
) else (
    echo The folder already exists.
)

echo Recovering rules...

DefenderRules.exe mpavbase.vdm.decompressed "%folder_path3%"


set "folder_path4=output_mpavdlta"

REM Check if the folder exists

if not exist "%folder_path4%" (
    echo The folder does not exist. Creating...
    mkdir "%folder_path4%"
    echo Folder successfully created.
) else (
    echo The folder already exists.
)

echo Recovering rules...

DefenderRules.exe mpavdlta.vdm.decompressed "%folder_path4%"


echo Operation completed.
echo Use DefenderRuleParser to view the rule details. 

endlocal





