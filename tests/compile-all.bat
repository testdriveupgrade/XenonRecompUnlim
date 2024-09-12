@echo off

pushd PowerAnalyse
for %%f in (*.cpp) do call ..\compile.bat %%f
popd