# UOS 远程助手

一个面向 UOS / Debian 系主机的图形化远程管理工具。单文件 Python 实现，内置 SSH/SFTP，打包成 exe 后拷到任意 Windows 双击即用，**目标机器无需安装任何客户端**。

典型场景：管理信创终端（UOS、Deepin、麒麟等），远程装软件、查硬件、修输入法，不用跑到工位前。

**当前版本：v1.1.0**

## 更新日志

- **v1.1.0** — 新增「升级修复」模块：诊断 / 一键修复 UOS 控制中心升级按钮失效（lastore 源配置缺失），带安全阀
- **v1.0.1** — 连接支持编辑（改 IP / 密码 / 提权方式后原地保存，改完自动重置提权检测结果）；修复删除当前连接后选中态错乱
- **v1.0.0** — 首个正式版：连接管理、系统信息、软件管理、上传安装、加入 sudoers、输入法；去掉启动黑窗

---

## 功能

| 模块 | 说明 |
| --- | --- |
| **连接管理** | 保存主机 / 账号 / 密码 / root 密码，多个连接切换，一键测试连通性，**已保存的连接可直接编辑** |
| **系统信息** | CPU、内存、内核、主机名、产品型号、主板序列号、硬盘序列号、网卡 MAC / IP / 速率、分区使用，支持导出 JSON |
| **软件管理** | 读取已安装软件列表、关键词模糊搜索、卸载（remove / purge），带系统关键包黑名单保护 |
| **上传安装** | 本地选 `.deb` 等包 → SFTP 传到远程 → `dpkg -i` 安装，带进度条 |
| **加入 sudoers** | 一键把登录账号加入 `sudo` 组，之后可用登录密码提权 |
| **输入法** | 远程把搜狗拼音写进 fcitx 启用列表并重载，自动探测真实输入法 ID |
| **升级修复** | 诊断并修复「系统升级按钮失效」：补齐 lastore 源配置、修 `config.json`、重启 lastore。**只改配置，不跑 apt upgrade** |

---

## 快速开始

### 直接用（Windows）

到 [Releases](https://github.com/lmzj/uos-remote-tool/releases) 下载最新版 `UOSRemoteTool.exe`（约 19 MB），双击运行。

- 会弹出一个原生窗口（内嵌 Web 界面），**关掉窗口即停止服务**
- 界面实际访问 `http://127.0.0.1:8765`，仅监听本机，外部不可访问
- 历史版本可在 [Releases 列表](https://github.com/lmzj/uos-remote-tool/releases) 里找

### 从源码运行

```bash
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple paramiko pywebview
python uos_remote_tool.py
```

- `pywebview` 可选：装了走原生窗口，没装自动回退到系统浏览器
- 强制浏览器模式：`UOS_TOOL_GUI=0 python uos_remote_tool.py`
- 换端口：`UOS_TOOL_PORT=9000 python uos_remote_tool.py`

---

## 提权方式

安装 / 卸载软件需要 root 权限。新建连接时可选四种方式：

| 方式 | 说明 |
| --- | --- |
| **自动探测（推荐）** | 依次尝试 sudo 免密 → sudo + 登录密码 → su + root 密码，哪个能用用哪个 |
| **sudo** | 用**登录密码**执行 `sudo`，要求账号在 sudoers 列表里 |
| **su 切换到 root** | 用 **root 密码**切 root。UOS 桌面版最常用、最可靠 |
| **不提权** | 仅普通用户权限，能看信息但不能装 / 卸软件 |

主界面顶部有「权限状态」卡片，点「检测提权」可实测当前账号能拿到哪种权限。

> **UOS 注意**：很多 UOS 桌面版账号虽然不在 sudoers，`sudo` 会直接失败，此时用 `su` + root 密码是唯一可行路径。

---

## 打包

```bash
pyinstaller --noconfirm --clean UOSRemoteTool.spec
```

`UOSRemoteTool.spec` 里已包含必需的 `--collect-all`：

```
paramiko  cryptography  bcrypt  nacl  webview  clr_loader  pythonnet
```

漏掉的话运行时会缺动态加载模块。产物约 19 MB。

---

## 安全提示

- **连接配置以明文存于程序同目录的 `connections.json`**，含登录密码和 root 密码。请勿把该文件传到公开仓库、网盘或发给他人。仓库已配 `.gitignore` 默认排除它。
- 服务只监听 `127.0.0.1`，局域网其他机器访问不到。
- 卸载功能内置了 `dpkg` / `apt` / `bash` / `libc6` 等关键包黑名单，但仍建议在测试机上先行验证。
- 修改 fcitx 配置前会自动备份为 `profile.uostool.bak`。

---

## 目标机器要求

- Debian 系（UOS / Deepin / Ubuntu 等），使用 `dpkg` / `apt`
- 开启 SSH 服务端，且防火墙 / 安全中心放行 22 端口
- 输入法功能需要 fcitx4 或 fcitx5

---

## 已知问题与处理经验

**1. UOS 上 `sudo` 不能用**
账号不在 sudoers 时 `sudo` 直接失败。用 `su` + root 密码，或先用本工具的「加入 sudoers」功能。注意：加入用户组后需**重新登录 SSH** 才生效。

**2. `su` 输出被 PAM 提示污染**
UOS 的 `su` / `sudo` 会在正常输出前插入「验证成功」等提示行，导致基于 `out.strip() == "0"` 的 root 判定失效。代码里用 `out_is_root()` 逐行判断，并用 `clean_out()` 剔除噪声行。

**3. SSH 会话里 `DISPLAY` 为空**
图形相关操作（如重载 fcitx）在 SSH 下拿不到 `DISPLAY`。工具会自动从 `/tmp/.X11-unix/` 探测并显式指定（通常是 `:0`）。

**4. 搜狗输入法 ID 因版本而异**
不能想当然写成 `sogou-pinyin`。实测 UOS 上搜狗拼音注册 ID 是 **`sogoupinyinuos`**。工具会从 `/usr/share/fcitx*/inputmethod/` 自动探测真实 ID。

**5. 别用 sed 改 fcitx profile**
`EnabledIMList` 是单行几万字符（含大量 `fcitx-keyboard-*:False`），sed 整行替换极易出错。本工具是**读回本机 → Python 精确解析 → 写回**，不依赖远程有没有 Python。

**6. faillock 锁定**
SSH 连续失败会触发账户锁定，需在目标机执行 `faillock --user <用户名> --reset` 解锁。

**7. lastore 用的是自己的源目录**
UOS 升级由 `lastore-daemon` 驱动，它读 `/var/lib/lastore/` 而**不是** `/etc/apt`。该目录下源配置缺失时，
`lastore` 认为没有可更新内容 → 控制中心升级按钮失效。`apt` 层面完全正常，所以很容易误判。

**8. `UpdatablePackages` 不是一个可靠的值**
lastore 5.6.x 上：`busctl` 取该属性报 `Input/output error`，`dbus-send ... Properties.Get` 报
`PropertyNotFound`，`GetAll` 的返回里也**没有**这一项（introspection 里却有）。
本工具改为三级回退：D-Bus → 解析 `update_infos.json` 里 `"Package"` 条目数 → 标记「读不到」。

**9. 修复前务必先诊断**
「升级修复」内置安全阀：诊断显示 lastore 正常（可升级包数 > 0）时**不修改任何配置**，
避免把好机器改坏。确需重建源配置时，勾选「忽略诊断结果，强制执行修复」。

**10. 源地址必须取自本机**
生成 `/var/lib/lastore/sources.list` 时从该机 `/etc/apt/sources.list` 提取 `deb` 行，
**绝不照抄其它机器**——专业版源、内网镜像、社区版源各不相同。

---

## 文件结构

```
uos_remote_tool.py      # 主程序（后端 + 内嵌前端页面，单文件）
UOSRemoteTool.spec      # PyInstaller 打包配置
connections.json        # 连接配置（明文，运行后生成，已 gitignore）
_uploads/               # 上传文件暂存目录
```

---

## 许可

MIT
