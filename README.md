# Mirage 🏜️

**Mirage** 是一款集成了多种规避技术的高级 Shellcode 加载框架，旨在绕过现代 EDR 的行为监测、栈回溯分析及内存扫描。

## 🛠️ 核心技术

* **间接系统调用 (Indirect Syscalls)** ：基于 **SysWhispers3** 逻辑重构，强制通过 `ntdll` 中的 `syscall; ret` 指令跳转执行，绕过 RIP 完整性校验 。
* **栈欺骗 (Stack Spoofing)** ：集成 **SilentMoonwalk** 的 Desync 栈伪造技术，通过 `SpoofCall` 构造合法的调用链（如 `BaseThreadInitThunk` -> `RtlUserThreadStart`），规避栈回溯分析。
* **模块踩踏 (Module Stomping)** ：利用 `NtMapViewOfSection` 映射合法系统 DLL（如 `xpsservices.dll`），并将 Payload 注入其 `.text` 段，使 Shellcode 运行在 Image-Backed 内存中，绕过私有内存扫描 。
* **RX 内存策略 (RX Strategy)** ：针对只读执行（Read-Execute）内存环境设计。利用 **shtools** 生成不含自解压逻辑、完全基于栈字符串和 API 哈希的纯净 Shellcode，完美兼容无写权限的代码段。

## 📁 项目结构

* `src/asm/gate.asm`：核心汇编代码，负责栈伪造与系统调用分发 。
* `src/loader.c`：实现模块加载、踩踏与权限切换逻辑 。
* `src/main.c`：动态扫描合适的栈帧（Suitable Frame）并初始化环境 。
* `shtools/`：用于生成符合 RX 策略的 C 语言 Shellcode 模板及提取工具 。

## 🚀 简易流程

1. **准备 Payload** ：在 `shtools/shellcode.c` 编写代码，运行 `build_shellcode.bat` 提取数组。
2. **配置 Loader** ：将提取的数组放入 `src/loader.c` 的 `shellcode[]` 变量 。
3. **编译运行** ：执行 `build.bat` 生成最小化的隐蔽加载器。

## ⚠️ 免责声明

本项目仅供网络安全研究与红队测试（Red Teaming）使用。请勿用于任何非法用途。开发者对使用本项目造成的任何后果不承担责任。

## 🙏 致谢

- **SilentMoonwalk** by [klezVirus](https://github.com/klezVirus) - Stack Spoofing
- **SysWhispers3** by [klezVirus](https://github.com/klezVirus) - Syscall
