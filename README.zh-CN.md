# SKey Software Encryption

[English](README.md) | 中文

SKey Software Encryption 是一个面向 Windows 交付场景的软件加密与授权工具。它可以保护 Python 项目、JAR、EXE 以及其他单文件编译产物，并提供图形化操作台、命令行工具、运行时解密组件和可选授权服务器。

这个公开仓库只保留产品源码、打包脚本和必要说明；内部规划文档、测试工具、构建产物、虚拟环境、本地数据库和缓存不会进入公开代码树。

## 主要能力

- Python 文件夹加密：输入一个 Python 项目文件夹，输出结构一致的受保护发行包，源代码会被加密并生成对应的 `*_r.py` 侧车文件。
- 单文件套壳：输入 JAR、EXE 或其他已编译文件，输出同名启动文件、`.secure` 运行时目录和客户授权文件。
- `skey.key` 客户授权：构建时生成客户 key，客户首次运行时自动绑定当前机器码，后续运行同时校验 key 文件和机器码。
- 永久授权：配置中可设置永久授权，也可设置有限授权时长和离线宽限时间。
- 图形化操作台：提供项目扫描、配置助手、构建、激活、诊断、帮助页和中英文切换。
- 可选授权服务器：支持在线激活、租约续期、离线激活和吊销，适合需要集中管控的部署。

## 快速使用

### 1. 启动图形化工具

构建后的桌面工具为：

```powershell
dist\skey-studio.exe
```

在源码环境中也可以运行：

```powershell
.\.venv\Scripts\python.exe -m skeystudio
```

### 2. 加密 Python 项目

1. 打开 `skey-studio.exe`。
2. 在“项目”页选择 Python 项目文件夹，也可以直接粘贴路径。
3. 点击“扫描项目”。
4. 在配置助手中确认产品信息、启动入口、加密范围和授权时间。
5. 点击“保存配置”，默认会在项目根目录生成 `skey.yaml`。
6. 在“构建”页选择源文件夹、配置文件和发行包输出目录。
7. 点击“构建发行包”。
8. 将完整输出目录交给客户，确保根目录包含 `skey.key`。

客户第一次运行时，`skey.key` 会绑定当前机器码。后续复制到其他机器运行会因为机器码不匹配而拒绝解密。

### 3. 加密单个 JAR/EXE/编译产物

图形界面中，在“构建”页选择单个文件作为源路径，配置文件可以留空，输出目录默认是源文件旁边的 `-p` 目录。

命令行示例：

```powershell
.\dist\skey-protect.exe wrap-file --input "<待加密单文件路径>" --out "<受保护输出目录>"
```

如果发行包必须同时包含 Windows DLL 和 Linux SO，请加上
`--require-windows-linux-runtime`。缺少任一平台必要文件时，命令会失败并提示缺失文件。

运行受保护 JAR：

```powershell
java -jar "<受保护输出目录>\<原始文件名>.jar"
```

Docker 部署时，把受保护启动文件、`.secure` 文件夹和 `skey.key` 一起复制到
backend 容器挂载的目录，例如 `runtime/app`。容器必须启动受保护 JAR。
Windows `.dll` 和 Linux `.so` 运行时可以同时放在 `.secure/rt`，加载器会按
当前操作系统选择。Linux 容器需要 `libskey_jni.so`，如果涉及 Python/通用运行时，
还需要 `libskey_rt.so`。

## 命令行工具

生成配置模板：

```powershell
.\dist\skey-protect.exe init-config --path "C:\path\to\project\skey.yaml"
```

构建 Python 项目发行包：

```powershell
.\dist\skey-protect.exe build --config "C:\path\to\project\skey.yaml" --project "C:\path\to\project" --out "C:\path\to\project-p"
```

检查受保护包：

```powershell
.\dist\skey-protect.exe inspect "C:\path\to\project-p\.secure\payload.skp"
```

验证运行时清单：

```powershell
.\dist\skey-protect.exe verify-runtime "C:\path\to\project-p"
```

## 授权方式

### 离线客户 key 流程

这是默认推荐流程，不需要提前注册授权服务器：

1. 构建发行包时自动生成 `skey.key`。
2. 将发行包和 `skey.key` 一起交付客户。
3. 客户第一次运行时，运行时读取 `skey.key` 并绑定当前机器码。
4. 后续运行校验签名、授权时间、包信息和机器码。

注意：如果 `skey.key` 在首次运行前被转发给其他机器，谁先运行就会绑定谁的机器。需要更严格管控时，应使用预绑定机器码或授权服务器模式。

### 授权服务器模式

授权服务器是可选组件，用于：

- 创建产品、软件包和授权码。
- 在线激活客户机器。
- 定期续租，控制授权过期。
- 吊销授权、机器或软件包。
- 支持离线请求和离线响应文件。

如果只使用 `skey.key` 首次绑定流程，不需要提前在授权服务器注册客户。

## 项目结构

```text
python/
  skeyprotect/      加密构建 CLI、配置、发行包生成
  skeystudio/       PySide6 图形化操作台
  skeyserver/       可选授权服务器
rust/
  crates/           运行时核心、FFI、JAR/EXE 套壳组件
java/
  skey-loader/      JAR 启动加载器
scripts/            打包与辅助脚本
packaging/          PyInstaller 打包配置
```

## 开发环境

创建虚拟环境并安装依赖：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
```

运行静态检查和 Rust 运行时验证：

```powershell
.\.venv\Scripts\python.exe -m ruff check python
.\.venv\Scripts\python.exe -m mypy python
cargo test --manifest-path rust\Cargo.toml
```

构建 Windows 工具：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-release-tools.ps1 -VendorPublicKeySha256 <runtime-public-key-sha256>
```

如果 `rust/target/release` 或 `rust/target/x86_64-unknown-linux-gnu/release`
中已经存在 Linux 运行时产物，打包脚本会同时把 `libskey_ffi.so` 和
`libskey_jni.so` 复制到 `dist/`。之后从该 `dist/` 构建出的受保护发行包会同时包含
Linux `.so` 和 Windows DLL。

## 安全说明

- 不要把生产私钥、服务器密钥、管理员令牌或 GitHub token 提交到仓库。
- `allow_unsafe_dev_signing_key` 只适合本地测试，正式交付前应替换为生产签名密钥。
- `dist/`、`build/`、`.venv/`、数据库文件和二进制发行产物默认不会上传到 Git。
- 正式商用前建议为客户授权增加预绑定机器码或授权服务器审批流程。

## 许可证

本项目使用 [MIT License](LICENSE) 开源。
