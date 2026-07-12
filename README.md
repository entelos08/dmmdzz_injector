# dmmdzz_injector — Educational Windows Kernel Learning Tool

**EDUCATIONAL PROJECT ONLY.** 本项目用于学习 Windows 内核驱动开发、IRP 处理、
IRQL 规则和用户态/内核态通信。演示目标进程为占位符 `target.exe`，请勿用于
非自有系统或非法用途。

---

## 1. 项目结构

```
dmmdzz_injector/
├── build.sh                      # Linux: 交叉编译用户态 .exe
├── build_driver.ps1              # Windows: 编译内核驱动 .sys (推荐)
├── build_driver.bat              # Windows: 同上 (CMD 版本)
├── CMakeLists.txt
├── cmake/
│   ├── toolchain-mingw-x86_64.cmake
│   └── FindWDK.cmake
├── driver/                       # 内核驱动源码
│   ├── driver.h                  # 共享 IOCTL 定义 (用户态/内核态共用)
│   ├── main.c                    # DriverEntry / 卸载 / 派发表
│   ├── ioctl.c                   # IRP_MJ_DEVICE_CONTROL 处理
│   ├── process.c                 # PID 查找 + PEB->Ldr 模块枚举
│   ├── memory.c                  # MmCopyVirtualMemory 读写
│   ├── dmmdzz_injector.inf       # 驱动安装 INF
│   └── dmmdzz_injector.vcxproj   # MSBuild 工程文件 (备用)
├── usermode/                     # 用户态控制器
│   ├── main.cpp                  # 端到端演示 (自动加载驱动)
│   ├── driver_ctl.hpp / .cpp     # DeviceIoControl 封装
│   ├── driver_loader.hpp / .cpp  # SCM 自动加载/卸载驱动服务
│   └── process.hpp / .cpp        # Win32 toolhelp 对照实现
└── asm/                          # 教学汇编模块 (可选)
    ├── syscall_demo.asm
    └── example.c
```

---

## 2. 两套构建流程

| 构建脚本 | 运行平台 | 产物 | 工具链 |
|----------|----------|------|--------|
| `build.sh` | **Linux** | `build/bin/dmmdzz_ctl.exe` | MinGW-w64 + CMake |
| `build_driver.ps1` | **Windows** | `build_driver/dmmdzz_injector.sys` | MSVC + WDK |

两者独立，可分别在不同机器上运行。

---

## 3. Linux 上编译用户态 `.exe`

### 3.1 安装依赖

```bash
sudo apt install mingw-w64 cmake nasm
```

### 3.2 一键编译

```bash
cd dmmdzz_injector
chmod +x build.sh
./build.sh                        # 默认 Release
./build.sh Debug                  # Debug 模式
./build.sh Release skipasm        # 跳过 asm 模块 (无 nasm 时)
```

### 3.3 产物

```
build/bin/dmmdzz_ctl.exe          # 用户态控制器 (静态链接, 无运行时依赖)
build/bin/dmmdzz_asm_demo.exe     # 汇编演示 (可选)
```

将 `dmmdzz_ctl.exe` 拷贝到 Windows 目标机即可运行。

---

## 4. Windows 上编译内核驱动 `.sys`

### 4.1 前置要求

| 组件 | 说明 |
|------|------|
| Visual Studio 2022+ | 需要 "使用 C++ 的桌面开发" 工作负载 |
| WDK (Windows Driver Kit) | 提供 `km\ntddk.h` 和 `ntoskrnl.lib` |
| Windows SDK | 通常随 WDK 一起安装 |

> **重要: Windows SDK ≠ WDK**
> - SDK 提供 `um\windows.h` 等用户态头文件
> - WDK 额外提供 `km\ntddk.h`、`km\ntifs.h` 等内核头文件和 `ntoskrnl.lib`
> - 检查方法: 如果 `D:\Windows Kits\10\Include\<版本>\km\ntddk.h` 存在，WDK 已安装

### 4.2 安装 WDK

如果尚未安装 WDK:

1. 下载: https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk
2. 运行 `wdksetup.exe`
3. 安装完成后确认 `D:\Windows Kits\10\Include\<版本>\km\ntddk.h` 存在

### 4.3 一键编译

```powershell
cd d:\Project\dmmdzz_injector
powershell -ExecutionPolicy Bypass -File build_driver.ps1
```

或在 CMD 中:

```cmd
build_driver.bat
```

### 4.4 产物

```
build_driver\dmmdzz_injector.sys    # 内核驱动
build_driver\dmmdzz_injector.inf    # 安装信息文件
build_driver\dmmdzz_injector.pdb    # 调试符号
```

### 4.5 编译细节

脚本使用 `cl.exe` 直接编译 (不依赖 WDK 的 VS 集成)，步骤:

1. 用 `vswhere` 定位 Visual Studio
2. 查找 WDK 的 `km` 目录 (自动选最新版本)
3. 加载 `vcvars64.bat` (MSVC 编译环境)
4. 清除 `INCLUDE`/`LIB` 环境变量 (避免 `um\` 与 `km\` 头文件冲突)
5. 用 `/kernel` 标志编译 4 个 `.c` 文件
6. 用 `/DRIVER /ENTRY:DriverEntry /NODEFAULTLIB` 链接成 `.sys`

关键编译参数:
```
cl.exe /c /kernel /GS- /Zl /W3 /O2 /utf-8
       /I"km"  /I"km\crt"  /I"shared"  /I"ucrt"
       main.c ioctl.c memory.c process.c

link.exe /SUBSYSTEM:NATIVE,10.0 /DRIVER /ENTRY:DriverEntry
         /NODEFAULTLIB /MACHINE:X64
         ntoskrnl.lib hal.lib BufferOverflowFastFailK.lib
```

---

## 5. 安装驱动 + 运行 (端到端)

### 5.1 准备工作

将以下文件拷贝到 Windows 目标机 (**同一目录**):

```
dmmdzz_injector.sys      ← Windows 编译的驱动
dmmdzz_ctl.exe           ← Linux 交叉编译的用户态控制器
```

### 5.2 启动测试目标进程

```cmd
:: 复制 notepad.exe 为 target.exe 作为演示目标
copy C:\Windows\notepad.exe C:\target.exe
start C:\target.exe
```

或直接使用任意进程名:
```cmd
:: dmmdzz_ctl.exe 可以接受任意进程名作为参数
dmmdzz_ctl.exe notepad.exe
```

### 5.3 首次运行: 开启测试签名

Windows 10/11 要求驱动签名。学习用途请开启测试签名 (仅需一次):

```cmd
:: 管理员 CMD
bcdedit /set testsigning on
shutdown /r /t 0
```

重启后桌面右下角会显示"测试模式"水印，这是正常的。

### 5.4 运行 (一键自动加载)

```cmd
:: 管理员 CMD — 一条命令搞定
dmmdzz_ctl.exe target.exe
```

**exe 会自动完成以下操作:**
1. 在同目录查找 `dmmdzz_injector.sys`
2. 通过 SCM (服务控制管理器) 创建并启动驱动服务
3. 打开 `\\.\dmmdzz_injector` 设备
4. 执行演示 (查找进程 → 读取模块基址 → 读内存 → 写内存 → 还原)
5. 退出时自动停止并删除驱动服务

> 不再需要手动执行 `sc create` / `sc start` / `sc stop` / `sc delete`。
> 如果驱动服务已存在且正在运行，exe 会直接复用。

### 5.5 关闭测试签名 (不再使用时)

```cmd
bcdedit /set testsigning off
shutdown /r /t 0
```

---

## 6. 预期输出

```
=== dmmdzz_injector - EDUCATIONAL kernel learning tool ===
Target image: target.exe
----------------------------------------------------------
[*] Creating driver service 'dmmdzz_injector' ...
    sys path: C:\tools\dmmdzz_injector.sys
[*] Starting driver service ...
[+] Driver service created and started.
[*] Opening driver device \.\dmmdzz_injector ...
[+] Driver version: 0.1.0
[*] Asking driver to find process 'target.exe' ...
[+] Driver reports PID=1234  EPROCESS VA=0xFFFFA80C12345000
[+] Toolhelp32  reports PID=1234 (should match)
[*] Asking driver for main module base ...
[+] Driver reports DllBase=0x00007FF6C0000000  Size=0x8000 (32768 bytes)
[+] Toolhelp enumerated 87 modules; first module:
    target.exe                       base=0x00007FF6C0000000 size=0x8000
[*] Reading 64 bytes of PE header at 0x00007FF6C0000000 via driver ...
  00007FF6C0000000  4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  |MZ.........|
  00007FF6C0000010  B8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@......|
  ...
[+] PE 'MZ' signature verified.
[*] Writing byte 0x6D at 0x00007FF6C0000000 via driver ...
[+] Verified after write: 0x6D ('m')
[*] Restoring original byte 0x4D ...
----------------------------------------------------------
[+] Educational demo complete.
[*] Driver service stopped.
[*] Driver service deleted.
```

用 DebugView (Sysinternals) 可以同时观察驱动侧的 `DbgPrint` 输出，
查看 IRP 流转过程。

---

## 7. 通信原理

```
用户态 dmmdzz_ctl.exe                内核态 dmmdzz_injector.sys
        |                                     |
        | CreateFileW("\\.\dmmdzz_injector")  |
        |------------------------------------->|
        |              HANDLE                 |  IoCreateDevice + IoCreateSymbolicLink
        |                                     |
        | DeviceIoControl(IOCTL_FIND_PROCESS) |
        |------------------------------------->|  IRP_MJ_DEVICE_CONTROL
        |                                     |  PsLookupProcessByProcessId
        |                                     |  PsGetProcessImageFileName
        |              PID + EPROCESS         |
        |<------------------------------------|  IoCompleteRequest
        |                                     |
        | DeviceIoControl(IOCTL_READ_MEMORY)  |
        |------------------------------------->|  KeStackAttachProcess
        |                                     |  MmCopyVirtualMemory (read)
        |              memory data            |  KeUnstackDetachProcess
        |<------------------------------------|
        |                                     |
        | DeviceIoControl(IOCTL_WRITE_MEMORY) |
        |------------------------------------->|  KeStackAttachProcess
        |                                     |  MmCopyVirtualMemory (write)
        |              status                 |  KeUnstackDetachProcess
        |<------------------------------------|
```

### IOCTL 列表

| 代码 | 功能 | 输入 | 输出 |
|------|------|------|------|
| `0x800` | GET_VERSION | 无 | 版本号 |
| `0x801` | FIND_PROCESS | 进程名 | PID + EPROCESS VA |
| `0x802` | ENUM_MODULE_BASE | PID + 模块名 | DllBase + SizeOfImage |
| `0x803` | READ_MEMORY | PID + 地址 + 大小 | 内存数据 |
| `0x804` | WRITE_MEMORY | PID + 地址 + 数据 | 写入字节数 |
| `0x805` | QUERY_BASE | PID | 主模块基址 + 大小 |

---

## 8. 学习要点

| 文件 | 教学内容 |
|------|----------|
| `driver/main.c` | `DriverEntry`、`IoCreateDevice`、`IoCreateSymbolicLink`、派发表、`DO_BUFFERED_IO` |
| `driver/ioctl.c` | `IRP_MJ_DEVICE_CONTROL`、METHOD_BUFFERED 缓冲区处理、IRP 完成 |
| `driver/process.c` | `PsLookupProcessByProcessId`、`KeStackAttachProcess`、PEB→Ldr 遍历、`__try/__except` |
| `driver/memory.c` | `MmCopyVirtualMemory` 跨地址空间读写、`MmGetSystemRoutineAddress` |
| `usermode/driver_ctl.cpp` | `CreateFileW`、`DeviceIoControl`、载荷打包 |
| `usermode/process.cpp` | `CreateToolhelp32Snapshot` 对照实现 |
| `asm/syscall_demo.asm` | `syscall` 指令、x64 ABI (RCX→R10) |

### IRQL 规则

- 所有 IOCTL 处理运行在 **PASSIVE_LEVEL**
- `KeStackAttachProcess` 将 IRQL 提升到 **APC_LEVEL**
- `IoCompleteRequest` 可能降低 IRQL，不可对同一 IRP 调用两次

---

## 9. 故障排除

| 问题 | 原因 | 解决 |
|------|------|------|
| `cl.exe` 找不到 | 未安装 MSVC | VS Installer 勾选 "使用 C++ 的桌面开发" |
| `ntddk.h` 找不到 | 未安装 WDK | 下载 wdksetup.exe 安装 |
| `um\winnt.h` 与 `km\wdm.h` 冲突 | include 路径含 `um\` | 脚本已自动清除 `INCLUDE` 环境变量 |
| `WindowsKernelModeDriver10.0` 工具集缺失 | VS 预览版不支持 WDK 集成 | 脚本已用 raw `cl.exe` 绕过 |
| `sc start` 报错 577 | 驱动未签名 | `bcdedit /set testsigning on` 并重启 |
| `CreateFile` 报错 5 | 权限不足 | 以管理员身份运行 |
| 找不到目标进程 | 进程未运行 | 先启动 `target.exe` 或指定其他进程名 |

---

## 10. 安全与法律声明

* 本项目仅供学习 Windows 内核编程
* 64 位 Windows 10/11 要求驱动签名，学习用途请开启测试签名
* 商业用途需要 EV 证书并提交微软硬件仪表板
* 请勿对非自有进程或非自有系统使用
