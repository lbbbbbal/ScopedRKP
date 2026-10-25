# ScopedRKP

按应用名单调整 Keystore 的 `ro.boot.hwc` 读取视图，让受影响的 CN 环境能够继续使用系统原有的远程密钥配置（RKP）路径。

仅在 Keystore 处理名单内 UID、读取值为 `CN` 时返回 `GLOBAL`。全局属性保持原值，密钥生成、证书签发和认证结果仍由系统服务处理。

## 下载

从 [Releases](https://github.com/lbbbbbal/ScopedRKP/releases) 下载 KernelSU 安装包。首次公开版本为 **0.4.0 预发布版**，跨设备兼容性仍需实测。

## 兼容条件

- ARM64、Android 12 或更新版本、KernelSU。
- 系统使用 `/system/bin/keystore2`，并通过可解析的 ELF PLT 导入 `__system_property_read_callback`。
- Keystore 能使用 `AIBinder_getCallingUid` 获取当前请求 UID，root 环境允许完成用户态库加载。
- 实际问题与 Keystore 对 `ro.boot.hwc=CN` 的处理有关。其他原因导致的认证失败不在本模块范围内。

没有机型、系统版本哈希、Build ID 或固定指令偏移白名单，接口和重定位槽在运行时解析。移除机型绑定不等于所有设备均已验证：前身在 Xiaomi 17（pandora）验证过 TEE 恢复及 Play Integrity 三项通过；本版本的验证范围见 [VALIDATION.md](VALIDATION.md)。

## 使用

安装后用系统电源菜单完整重启。开机完成、首次解锁后自动启用，无到期时间；启动进程随后退出。

名单位于：

```text
/data/adb/modules/scoped_rkp/config/scope.txt
```

每行一个包名，第二列可选 Android 用户编号，默认是用户 0：

```text
com.google.android.gms
com.android.vending
com.example.app
com.example.workapp 10
```

包名在每次启用或重载时解析为当前 UID。共享 UID 的包共用作用范围；最多 256 个唯一 UID。空名单会关闭当前策略。升级保留已有名单；旧版第三列 UID 快照会被忽略。

root 控制命令：

```sh
/data/adb/modules/scoped_rkp/bin/scoped-rkpctl status
/data/adb/modules/scoped_rkp/bin/scoped-rkpctl reload
/data/adb/modules/scoped_rkp/bin/scoped-rkpctl off
/data/adb/modules/scoped_rkp/bin/scoped-rkpctl disable
/data/adb/modules/scoped_rkp/bin/scoped-rkpctl enable
```

`reload` 应用当前名单；`off` 关闭本次策略；`disable` 同时关闭开机启用；`enable` 恢复开机启用并立即应用名单。KernelSU 的 Action 按钮只显示状态。错误配置不会覆盖上一次有效名单。

更换库版本需要完整重启，让旧 Keystore 进程退出。KernelSU 的软重启可能只应用模块文件。Keystore 自行重启后，本模块不会循环重注入，可手动执行 `reload`。

## 精简内容

安装包只包含一个控制程序、一个属性视图库和启动/配置脚本。没有观察模式、120 秒窗口、测试命令、逐请求日志、逐 UID 计数、固件提取器、设备配置表或取证记录。源码和开发测试留在仓库，不放进手机安装包。

仍保留目标进程身份、ELF 边界、映像冲突检查以及寄存器、errno、句柄恢复。这些用于正常完成核心服务加载。加载中断会阻止之后的自动重试；确认原因后可用 `enable` 手动重试。

模块不依赖 Zygisk；现有其他 Zygisk 模块是否保留，应按它们自己的依赖决定。它不安装内核驱动，不改全局属性、SELinux、启动分区、Keybox 或认证 ID，也不清理应用或系统密钥。正常系统 RKP 业务仍可能创建密钥和证书。

## 构建

需要 Python 3.10+ 和 Android NDK r29 或更新版本：

```sh
python scripts/build.py --ndk /path/to/android-ndk-r29
python scripts/verify_package.py
```

产物位于 `dist/`。也可使用 CMake 和 NDK toolchain，指定 `ANDROID_ABI=arm64-v8a`、`ANDROID_PLATFORM=android-31`、`ANDROID_STL=c++_static`。

开发测试见 [tests/README.md](tests/README.md)。GitHub Actions 自动构建、验证安装包，并在版本尚未发布时生成预发布附件。

## 许可证

GPL-3.0。加载基础设施派生自 [JingMatrix/TEESimulator](https://github.com/JingMatrix/TEESimulator)，具体来源与修改见 [NOTICE](NOTICE)。本仓库提供安装包的对应源码。

---

ScopedRKP provides a per-UID `CN` → `GLOBAL` property view inside Keystore. It discovers the ARM64 ELF import at runtime instead of pinning a device hash or instruction address. It leaves key generation and attestation to the real system services. Other-device compatibility is conditional on the interfaces listed above; the first public build is a prerelease.
