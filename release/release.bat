@echo off
setlocal enabledelayedexpansion

:: 设置默认标签，如果未指定则使用日期+版本号
if "%1"=="" (
    for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
    set "DATE=!dt:~0,8!"
    set "VERSION=01"
    set "TAG=!DATE!-!VERSION!"
) else (
    set "TAG=%1"
)

echo 使用标签: !TAG!

:: 处理Go模块依赖
go mod vendor
tar -cvzf vendor.tar.gz vendor

set "PACKAGE=btcd"
set "MAINDIR=!PACKAGE!-!TAG!"
mkdir "!MAINDIR!"

copy vendor.tar.gz "!MAINDIR!\"
del vendor.tar.gz
rmdir /s /q vendor

:: 创建源文件归档
set "PACKAGESRC=!MAINDIR!\!PACKAGE!-source-!TAG!.tar"
git archive -o "!PACKAGESRC!" HEAD
gzip -f "!PACKAGESRC!"

cd "!MAINDIR!"

:: 定义要构建的系统和架构列表
set "SYS=darwin-amd64 darwin-arm64 linux-386 linux-amd64 linux-armv6 linux-armv7 linux-arm64 linux-ppc64 linux-ppc64le linux-mips linux-mipsle linux-mips64 linux-mips64le linux-s390x windows-386 windows-amd64"

:: 获取GOPATH和提交信息
for /f "tokens=1" %%g in ('go env GOPATH') do set "GOPATH=%%g"
for /f "delims=" %%c in ('git describe --abbrev=40 --dirty') do set "COMMIT=%%c"
set "PKG=github.com/btcsuite/btcd"

:: 循环构建每个目标平台
for %%i in (!SYS!) do (
    for /f "tokens=1,2 delims=-" %%a in ("%%i") do (
        set "OS=%%a"
        set "ARCH=%%b"
        set "ARM="

        if "!ARCH!"=="armv6" (
            set "ARCH=arm"
            set "ARM=6"
        ) else if "!ARCH!"=="armv7" (
            set "ARCH=arm"
            set "ARM=7"
        )

        set "DIR=!PACKAGE!-%%i-!TAG!"
        mkdir "!DIR!"
        cd "!DIR!"

        echo 正在构建: !OS! !ARCH! !ARM!
        set "LDFLAGS=-s -w -buildid= -X main.commit=!COMMIT!"

        :: 构建btcd
        set "GOOS=!OS!"
        set "GOARCH=!ARCH!"
        set "GOARM=!ARM!"
        go build -v -trimpath -ldflags "!LDFLAGS!" "!PKG!"

        :: 构建btcctl
        go build -v -trimpath -ldflags "!LDFLAGS!" "!PKG!/cmd/btcctl"

        cd ..

        :: 打包构建结果
        if "!OS!"=="windows" (
            zip -r "!DIR!.zip" "!DIR!"
        ) else (
            tar -cvzf "!DIR!.tar.gz" "!DIR!"
        )

        rmdir /s /q "!DIR!"
    )
)

:: 生成校验和
certutil -hashfile *.* SHA256 > "manifest-!TAG!.txt"

:: 构建本地版本
go build -o bitcoin.exe .

cd ..

echo 构建完成，输出目录: !MAINDIR!
endlocal
