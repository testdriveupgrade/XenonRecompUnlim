@echo off

pushd XenonAnalyse
for %%f in (*.cpp) do call ..\compile.bat %%f
popd
