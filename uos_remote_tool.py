#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UOS 远程助手 —— 远程 Debian/UOS 主机管理工具

特性:
  * 内置 paramiko 实现 SSH/SFTP, 不依赖系统 ssh.exe, 拷贝到任意 Windows 均可使用
  * 提权支持 auto / sudo / su / none 四种模式, 连接时自动探测
  * 明文配置文件 connections.json, 存放于程序同目录
  * 本地 Web 界面, 仅监听 127.0.0.1
"""

import os
import sys
import io
import re
import json
import time
import uuid
import shutil
import threading
import webbrowser
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

try:
    import paramiko
except ImportError:
    sys.stderr.write("缺少 paramiko, 请先执行: pip install paramiko\n")
    sys.exit(1)

PORT = int(os.environ.get("UOS_TOOL_PORT", "8765"))
HOST = "127.0.0.1"


def base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


BASE = base_dir()
CONFIG_PATH = os.path.join(BASE, "connections.json")
UPLOAD_DIR = os.path.join(BASE, "_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 卸载黑名单: 卸载这些包会导致系统损坏
DANGER_PACKAGES = {
    "dpkg", "apt", "apt-utils", "bash", "coreutils", "python3", "python3-minimal",
    "libc6", "systemd", "sudo", "openssh-server", "openssh-client", "init",
    "login", "passwd", "util-linux", "debianutils", "perl-base", "tar", "gzip",
    "u-boot-tools", "grub-common", "grub2-common", "linux-kernel", "uos-desktop",
}


# --------------------------------------------------------------------------
# 配置读写
# --------------------------------------------------------------------------
def load_conns():
    if not os.path.exists(CONFIG_PATH):
        return []
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_conns(conns):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(conns, f, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# SSH 主机封装
# --------------------------------------------------------------------------
AUTH_FAIL_HINTS = (
    "not in the sudoers", "不在 sudoers", "鉴定故障", "authentication failure",
    "incorrect password", "su: 密码不正确", "permission denied", "sorry, try again",
)


def shell_quote(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


# UOS 的 su / sudo 会在正常输出前插入 PAM 提示行（如"验证成功"），需剔除
PAM_NOISE = ("验证成功", "密码正确", "Password:", "密码：")


def clean_out(s):
    if not s:
        return s
    keep = []
    for ln in s.splitlines():
        if ln.strip() in PAM_NOISE:
            continue
        keep.append(ln)
    return "\n".join(keep)


def out_is_root(s):
    """判断远端 id -u 的输出里是否含 root(0)。输出可能被 PAM 提示污染，逐行判断。"""
    for ln in (s or "").splitlines():
        if ln.strip() == "0":
            return True
    return False


class Host(object):
    def __init__(self, cfg, log=None):
        self.cfg = cfg
        self.log = log or (lambda m: None)
        self.cli = None
        self.priv_mode = None

    # ---------- 连接 ----------
    def connect(self):
        cfg = self.cfg
        self.cli = paramiko.SSHClient()
        self.cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.cli.connect(
            hostname=cfg.get("host", ""),
            port=int(cfg.get("port", 22) or 22),
            username=cfg.get("username", ""),
            password=cfg.get("password", "") or None,
            timeout=15,
            banner_timeout=20,
            auth_timeout=20,
            allow_agent=False,
            look_for_keys=False,
        )
        return True

    def close(self):
        try:
            if self.cli:
                self.cli.close()
        except Exception:
            pass

    # ---------- 底层执行 ----------
    def _raw(self, cmd, timeout=60, stdin_pw=None):
        stdin, stdout, stderr = self.cli.exec_command(cmd, timeout=timeout)
        if stdin_pw is not None:
            try:
                stdin.write(stdin_pw + "\n")
                stdin.flush()
            except Exception:
                pass
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        try:
            code = stdout.channel.recv_exit_status()
        except Exception:
            code = -1
        return code, out, err

    def exec_cmd(self, cmd, timeout=60):
        return self._raw(cmd, timeout=timeout)

    # ---------- 提权执行 ----------
    def _mk_cand(self, name, path):
        pw = self.cfg.get("password", "")
        rp = self.cfg.get("root_password") or pw
        if name == "sudo-nopass":
            return ("sudo-nopass", "sudo -n -p '' bash %s" % path, None)
        if name == "sudo":
            return ("sudo", "sudo -S -p '' bash %s" % path, pw)
        if name == "su":
            return ("su", "su -c %s" % shell_quote("bash " + path), rp)
        return ("none", "bash %s" % path, None)

    def exec_root(self, cmd, timeout=600):
        mode = (self.cfg.get("privilege") or "auto").lower()
        path = "/tmp/.uostool_%s.sh" % uuid.uuid4().hex[:8]
        script = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" + cmd + "\n"
        self.put_bytes(path, script.encode("utf-8"))
        self._raw("chmod 700 %s" % path, 20)

        cands = []
        seen = set()

        def add(name):
            if name not in seen:
                seen.add(name)
                cands.append(self._mk_cand(name, path))

        if mode == "auto":
            if self.priv_mode:
                add(self.priv_mode)
            add("sudo-nopass")
            add("sudo")
            add("su")
        elif mode in ("sudo", "su", "none"):
            add(mode)
        else:
            add("none")

        last = ""
        for name, c, password in cands:
            code, out, err = self._raw(c, timeout=timeout, stdin_pw=password)
            blob = (out or "") + (err or "")
            auth_fail = any(h in blob.lower() for h in AUTH_FAIL_HINTS)
            if code == 0 and not auth_fail:
                self.priv_mode = name
                self._raw("rm -f %s" % path, 10)
                return code, clean_out(out), clean_out(err)
            last = blob.strip() or ("exit=%s" % code)
            self.log("  提权方式 %s 不可用: %s" % (name, last[:160]))
        self._raw("rm -f %s" % path, 10)
        return 1, "", clean_out(last) or "提权失败"

    # ---------- 文件 ----------
    def put_bytes(self, remote, data):
        sftp = self.cli.open_sftp()
        try:
            with sftp.open(remote, "wb") as f:
                f.write(data)
        finally:
            sftp.close()

    def put_file(self, local, remote, callback=None):
        sftp = self.cli.open_sftp()
        try:
            sftp.put(local, remote, callback=callback)
        finally:
            sftp.close()

    def get_bytes(self, remote):
        """读取远程文件为 bytes；不存在返回 None。"""
        sftp = self.cli.open_sftp()
        try:
            with sftp.open(remote, "rb") as f:
                return f.read()
        except IOError:
            return None
        finally:
            sftp.close()

    # ---------- 提权探测 ----------
    def probe(self):
        code, out, err = self._raw("id -u", 15)
        if code == 0 and out_is_root(out):
            self.priv_mode = "none"
            return "root 直接登录", True
        code, out, err = self._raw("sudo -n -p '' id -u", 15)
        if code == 0 and out_is_root(out):
            self.priv_mode = "sudo-nopass"
            return "sudo 免密", True
        pw = self.cfg.get("password", "")
        code, out, err = self._raw("sudo -S -p '' id -u", 25, stdin_pw=pw)
        if code == 0 and out_is_root(out):
            self.priv_mode = "sudo"
            return "sudo 用户密码", True
        rp = self.cfg.get("root_password") or pw
        code, out, err = self._raw("su -c 'id -u'", 25, stdin_pw=rp)
        if code == 0 and out_is_root(out):
            self.priv_mode = "su"
            return "su root 密码", True
        return "未取得 root（仅普通用户权限）", False


# --------------------------------------------------------------------------
# 采集脚本
# --------------------------------------------------------------------------
COLLECT_SCRIPT = r'''
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "##INFO##"
echo "hostname=$(hostname 2>/dev/null)"
echo "os_name=$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
echo "kernel=$(uname -r 2>/dev/null)"
echo "arch=$(uname -m 2>/dev/null)"
echo "uptime=$(uptime -p 2>/dev/null || uptime 2>/dev/null)"
echo "cpu_model=$(grep -m1 -E 'model name|Hardware' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')"
echo "cpu_cores=$(nproc 2>/dev/null)"
echo "mem_total=$(free -h 2>/dev/null | awk '/^Mem:/{print $2}')"
echo "mem_used=$(free -h 2>/dev/null | awk '/^Mem:/{print $3}')"
echo "board_name=$(cat /sys/class/dmi/id/board_name 2>/dev/null)"
echo "board_serial=$(cat /sys/class/dmi/id/board_serial 2>/dev/null)"
echo "product_name=$(cat /sys/class/dmi/id/product_name 2>/dev/null)"
echo "bios_serial=$(cat /sys/class/dmi/id/product_serial 2>/dev/null)"
echo "##LSBLK##"
lsblk -J -o NAME,SIZE,TYPE,MODEL,SERIAL,VENDOR 2>/dev/null || echo "{}"
echo "##NETIF##"
for f in /sys/class/net/*; do
  n=$(basename "$f")
  [ "$n" = "lo" ] && continue
  mac=$(cat "$f/address" 2>/dev/null)
  ip=$(ip -o -4 addr show dev "$n" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
  st=$(cat "$f/operstate" 2>/dev/null)
  sp=$(cat "$f/speed" 2>/dev/null)
  echo "netif=${n}|${mac}|${ip}|${st}|${sp}"
done
echo "##DISKSERIAL##"
for d in $(lsblk -d -o NAME -n 2>/dev/null); do
  s=$(cat /sys/block/$d/serial 2>/dev/null | tr -d ' \t')
  m=$(cat /sys/block/$d/device/model 2>/dev/null | tr -d ' \t')
  echo "serial=${d}|${s}|${m}"
done
echo "##DF##"
df -h -x tmpfs -x devtmpfs 2>/dev/null | tail -n +1
echo "##END##"
'''


def parse_sysinfo(text):
    info = {}
    disks = []
    nets = []
    serials = {}
    df = []

    def section(name, nxt):
        try:
            s = text.index("##%s##" % name)
        except ValueError:
            return ""
        try:
            e = text.index("##%s##" % nxt)
        except ValueError:
            e = len(text)
        return text[s + len(name) + 4:e]

    # INFO
    for line in section("INFO", "LSBLK").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()

    # LSBLK json
    raw = section("LSBLK", "NETIF")
    m = re.search(r"\{.*\}", raw, re.S)
    if m:
        try:
            data = json.loads(m.group(0))
            for dev in data.get("blockdevices", []):
                if dev.get("type") == "disk":
                    disks.append({
                        "name": dev.get("name", ""),
                        "size": dev.get("size", ""),
                        "model": (dev.get("model") or "").strip(),
                        "serial": (dev.get("serial") or "").strip(),
                    })
        except Exception:
            pass

    # 序列号补全
    for line in section("DISKSERIAL", "DF").splitlines():
        if line.startswith("serial="):
            parts = line[len("serial="):].split("|")
            if len(parts) >= 2 and parts[1]:
                serials[parts[0]] = parts[1]
    for d in disks:
        if not d.get("serial"):
            d["serial"] = serials.get(d["name"], "")
        if not d.get("model") and len(serials.get(d["name"], "")) > 0:
            pass

    # NETIF
    for line in section("NETIF", "DISKSERIAL").splitlines():
        if line.startswith("netif="):
            p = line[len("netif="):].split("|")
            p += [""] * (5 - len(p))
            nets.append({"name": p[0], "mac": p[1], "ip": p[2], "state": p[3], "speed": p[4]})

    # DF
    for i, line in enumerate(section("DF", "END").splitlines()):
        if i == 0:
            continue
        parts = line.split()
        if len(parts) >= 6:
            df.append({"fs": parts[0], "size": parts[1], "used": parts[2],
                       "avail": parts[3], "use": parts[4], "mount": parts[5]})

    return {"info": info, "disks": disks, "nets": nets, "df": df}


# --------------------------------------------------------------------------
# 任务系统
# --------------------------------------------------------------------------
TASKS = {}
TASKS_LOCK = threading.Lock()


def new_task():
    tid = uuid.uuid4().hex[:12]
    with TASKS_LOCK:
        TASKS[tid] = {"id": tid, "status": "running", "log": [], "result": None,
                      "progress": 0, "started": time.time()}
    return tid


def task_log(tid, msg):
    with TASKS_LOCK:
        t = TASKS.get(tid)
        if t is not None:
            t["log"].append(str(msg))
            if len(t["log"]) > 4000:
                t["log"] = t["log"][-2000:]


def task_done(tid, result=None, status="done"):
    with TASKS_LOCK:
        t = TASKS.get(tid)
        if t is not None:
            t["status"] = status
            t["result"] = result
            t["progress"] = 100


def run_async(tid, fn):
    def wrap():
        try:
            fn(tid)
        except Exception as e:
            task_log(tid, "异常: %s" % e)
            task_log(tid, traceback.format_exc()[-1500:])
            task_done(tid, status="error")
    th = threading.Thread(target=wrap, daemon=True)
    th.start()


# --------------------------------------------------------------------------
# 业务动作
# --------------------------------------------------------------------------
def action_test(tid, cfg):
    h = Host(cfg, log=lambda m: task_log(tid, m))
    try:
        task_log(tid, "连接 %s@%s ..." % (cfg.get("username"), cfg.get("host")))
        h.connect()
        task_log(tid, "SSH 登录成功")
        mode, ok = h.probe()
        task_log(tid, "提权探测: %s" % mode)
        code, out, err = h.exec_cmd("uname -a; cat /etc/os-release 2>/dev/null | head -n 3", 30)
        task_log(tid, (out or err).strip()[:500])
        h.close()
        task_done(tid, {"ok": True, "privilege": mode, "root": ok})
    except Exception as e:
        task_log(tid, "连接失败: %s" % e)
        task_done(tid, {"ok": False, "error": str(e)}, status="error")


def action_elevate(tid, cfg):
    """按指定方式尝试提权，返回是否拿到 root。"""
    h = Host(cfg, log=lambda m: task_log(tid, m))
    try:
        task_log(tid, "连接 %s@%s ..." % (cfg.get("username"), cfg.get("host")))
        h.connect()
        task_log(tid, "SSH 登录成功，尝试提权 …")
        mode = (cfg.get("privilege") or "auto").lower()
        pw = cfg.get("password", "")
        rp = cfg.get("root_password") or pw
        found = None

        if mode in ("auto", "sudo-nopass", "sudo"):
            code, out, err = h._raw("sudo -n -p '' id -u", 15)
            if code == 0 and out_is_root(out):
                found = ("sudo-nopass", "sudo 免密（账号已在 sudoers 且无需密码）")
            else:
                task_log(tid, "  sudo 免密不可用")

        if not found and mode in ("auto", "sudo"):
            task_log(tid, "  尝试 sudo + 登录密码 …")
            code, out, err = h._raw("sudo -S -p '' id -u", 25, stdin_pw=pw)
            if code == 0 and out_is_root(out):
                found = ("sudo", "sudo（使用登录密码）")
            else:
                task_log(tid, "  sudo + 登录密码失败：账号可能不在 sudoers 中")

        if not found and mode in ("auto", "su"):
            task_log(tid, "  尝试 su + root 密码 …")
            code, out, err = h._raw("su -c 'id -u'", 25, stdin_pw=rp)
            if code == 0 and out_is_root(out):
                found = ("su", "su 切换 root（使用 root 密码）")
            else:
                task_log(tid, "  su 失败：root 密码可能不对")

        h.close()
        if found:
            task_log(tid, "提权成功：%s" % found[1])
            task_done(tid, {"ok": True, "mode": found[0], "privilege": found[1], "root": True})
        else:
            task_log(tid, "未能取得 root 权限")
            task_done(tid, {"ok": False, "root": False,
                            "error": "提权失败：请确认密码正确，或改用其它提权方式"},
                      status="error")
    except Exception as e:
        task_log(tid, "提权出错: %s" % e)
        task_done(tid, {"ok": False, "root": False, "error": str(e)}, status="error")


def action_addsudo(tid, cfg):
    """一键把当前登录用户加入 sudo 组（sudoers），需 root 密码（su 提权）。"""
    h = Host(cfg, log=lambda m: task_log(tid, m))
    try:
        user = cfg.get("username", "").strip()
        if not user:
            task_log(tid, "用户名为空，无法操作")
            task_done(tid, {"ok": False, "error": "用户名为空"}, status="error")
            return
        if user == "root":
            task_done(tid, {"ok": True, "already": True,
                            "msg": "当前账号就是 root，无需加入 sudo 组"})
            task_log(tid, "当前账号是 root，无需操作")
            return

        rp = cfg.get("root_password") or ""
        if not rp:
            task_log(tid, "需要 root 密码：请在「编辑连接」中填写 root 密码后重试")
            task_done(tid, {"ok": False, "error": "缺少 root 密码"},
                      status="error")
            return

        task_log(tid, "连接 %s@%s ..." % (user, cfg.get("host")))
        h.connect()
        task_log(tid, "SSH 登录成功")

        # 先看是否已在 sudo 组
        code, out, err = h._raw("id -nG %s 2>/dev/null" % shell_quote(user), 20)
        groups = (out or "").strip()
        task_log(tid, "当前所属用户组: %s" % (groups or "未知"))
        in_sudo = any(g == "sudo" for g in groups.split())

        if in_sudo:
            task_log(tid, "账号 %s 已在 sudo 组，无需重复添加" % user)
            # 验证 sudo 是否真可用
            code2, out2, err2 = h._raw("sudo -S -p '' id -u", 25,
                                       stdin_pw=cfg.get("password", ""))
            ok_sudo = (code2 == 0 and out_is_root(out2))
            h.close()
            msg = ("账号已在 sudo 组。" + ("sudo 已可用。" if ok_sudo
                   else "但 sudo 命令仍不可用，可能需要重新登录 SSH 后生效。"))
            task_done(tid, {"ok": True, "already": True, "sudo_ok": ok_sudo,
                            "msg": msg})
            return

        # 用 su root 密码执行 usermod
        task_log(tid, "执行: usermod -aG sudo %s （su 提权）" % user)
        inner = ("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; "
                 "usermod -aG sudo %s" % shell_quote(user))
        code, out, err = h._raw("su -c %s" % shell_quote(inner), 40, stdin_pw=rp)
        blob = clean_out((out or "") + "\n" + (err or "")).strip()
        if code != 0:
            task_log(tid, "usermod 失败: %s" % blob[:300])
            task_done(tid, {"ok": False, "error": blob[:200] or "usermod 执行失败"},
                      status="error")
            return
        task_log(tid, "usermod 执行成功")

        # 复核
        code, out, err = h._raw("id -nG %s 2>/dev/null" % shell_quote(user), 20)
        groups2 = (out or "").strip()
        ok_add = any(g == "sudo" for g in groups2.split())
        task_log(tid, "复核所属用户组: %s" % groups2)
        h.close()

        if ok_add:
            msg = ("账号 %s 已加入 sudo 组。\n"
                   "注意：需重新登录（重新建立 SSH 连接）后 sudo 才生效。\n"
                   "生效后可用「登录密码」通过 sudo 提权。" % user)
            task_log(tid, msg.replace("\n", " "))
            task_done(tid, {"ok": True, "already": False, "msg": msg})
        else:
            task_done(tid, {"ok": False,
                            "error": "usermod 执行后仍未检测到 sudo 组"},
                      status="error")
    except Exception as e:
        task_log(tid, "加入 sudoers 出错: %s" % e)
        task_done(tid, {"ok": False, "error": str(e)}, status="error")


# --------------------------------------------------------------------------
# 输入法（fcitx）相关
# --------------------------------------------------------------------------
def ime_detect(h, log):
    """探测 fcitx 版本、搜狗注册 ID、profile 路径。返回 dict。"""
    info = {"fcitx": None, "sogou_id": None, "profile": None,
            "installed": False, "running": False}

    code, out, _ = h.exec_cmd("which fcitx 2>/dev/null; which fcitx5 2>/dev/null", 20)
    which = (out or "").strip()
    if "fcitx5" in which:
        info["fcitx"] = "fcitx5"
    elif "fcitx" in which:
        info["fcitx"] = "fcitx4"
    log("输入法框架: %s" % (info["fcitx"] or "未检测到 fcitx"))

    # fcitx 是否在运行
    code, out, _ = h.exec_cmd("pgrep -x fcitx >/dev/null && echo yes || "
                              "(pgrep -x fcitx5 >/dev/null && echo yes || echo no)", 20)
    info["running"] = (out or "").strip().endswith("yes")
    log("fcitx 运行中: %s" % info["running"])

    if not info["fcitx"]:
        return info

    # 搜狗是否安装
    code, out, _ = h.exec_cmd(
        "dpkg -l 2>/dev/null | grep -iE 'sogou|sogoupinyin' | awk '{print $2}'", 30)
    pkgs = [l.strip() for l in (out or "").splitlines() if l.strip()]
    info["packages"] = pkgs
    info["installed"] = bool(pkgs)
    log("搜狗相关包: %s" % (", ".join(pkgs) if pkgs else "未安装"))

    # 关键：从 inputmethod 目录里找出搜狗注册的实际 ID（不同版本差异大）
    base = "/usr/share/fcitx5" if info["fcitx"] == "fcitx5" else "/usr/share/fcitx"
    code, out, _ = h.exec_cmd(
        "ls %s/inputmethod/ 2>/dev/null | grep -i sogou" % base, 20)
    cands = [l.strip() for l in (out or "").splitlines() if l.strip()]
    ids = []
    for c in cands:
        if c.endswith(".conf"):
            ids.append(c[:-5])
        else:
            ids.append(c)
    if ids:
        info["sogou_id"] = ids[0]
        info["sogou_ids"] = ids
        log("搜狗注册 ID: %s（候选项: %s）" % (ids[0], ", ".join(ids)))
    else:
        log("未在 %s/inputmethod/ 找到搜狗条目" % base)

    # profile 路径
    pf = "~/.config/fcitx5/profile" if info["fcitx"] == "fcitx5" else "~/.config/fcitx/profile"
    code, out, _ = h.exec_cmd("echo %s" % pf, 15)
    info["profile"] = (out or "").strip()
    return info


def ime_parse_profile(text):
    """解析 fcitx profile，返回 (行列表, 元数据字典)。"""
    lines = text.splitlines()
    meta = {}
    for i, l in enumerate(lines):
        s = l.strip()
        if s.startswith("EnabledIMList="):
            meta["enabled_idx"] = i
            meta["enabled"] = s[len("EnabledIMList="):]
        elif s.startswith("IMName="):
            meta["imname_idx"] = i
            meta["imname"] = s[len("IMName="):]
    return lines, meta


def ime_ensure_id(enabled_str, target_id):
    """确保 target_id 在启用列表里且为 True。返回 (新字符串, 是否改动, 已在列表)。"""
    items = [x for x in enabled_str.split(",") if x]
    parsed = []
    for it in items:
        if ":" in it:
            n, v = it.rsplit(":", 1)
            parsed.append([n, v])
        else:
            parsed.append([it, "True"])

    found = False
    changed = False
    for p in parsed:
        if p[0] == target_id:
            found = True
            if p[1] != "True":
                p[1] = "True"
                changed = True
            break
    if not found:
        # 插到最前面，保证它排在首位
        parsed.insert(0, [target_id, "True"])
        changed = True

    return ",".join(n + ":" + v for n, v in parsed), changed, found


def action_addime(tid, cfg, set_default=True):
    """把搜狗输入法加入 fcitx 启用列表并重启 fcitx。"""
    h = Host(cfg, log=lambda m: task_log(tid, m))
    try:
        task_log(tid, "连接 %s@%s ..." % (cfg.get("username"), cfg.get("host")))
        h.connect()
        task_log(tid, "SSH 登录成功（注意：操作的是登录用户自己的输入法配置）")

        info = ime_detect(h, lambda m: task_log(tid, m))
        if not info.get("fcitx"):
            task_done(tid, {"ok": False, "error": "未检测到 fcitx，无法操作"},
                      status="error")
            return
        if not info.get("installed"):
            task_done(tid, {"ok": False,
                            "error": "未检测到搜狗输入法已安装（请先安装搜狗拼音）"},
                      status="error")
            return
        sid = info.get("sogou_id")
        if not sid:
            task_done(tid, {"ok": False,
                            "error": "搜狗已安装，但在 fcitx 的 inputmethod 目录里"
                                     "找不到注册条目，无法自动添加"},
                      status="error")
            return

        # 读 profile
        pf = info.get("profile")
        raw = h.get_bytes(pf)
        if raw is None:
            task_done(tid, {"ok": False,
                            "error": "找不到配置文件 %s\n"
                                     "请先在图形界面登录一次并打开输入法设置，生成配置后再操作。" % pf},
                      status="error")
            return
        text = raw.decode("utf-8", "replace")
        lines, meta = ime_parse_profile(text)

        if "enabled_idx" not in meta:
            task_done(tid, {"ok": False,
                            "error": "配置文件里没有 EnabledIMList 项，格式不符，已放弃修改"},
                      status="error")
            return

        enabled = meta["enabled"]
        task_log(tid, "当前 IMName = %s" % meta.get("imname", "(无)"))
        active = [x.split(":")[0] for x in enabled.split(",")
                  if x and x.endswith(":True")]
        task_log(tid, "当前已启用输入法(%d): %s" % (len(active), ", ".join(active[:10])))

        new_enabled, changed, already = ime_ensure_id(enabled, sid)
        if already and not changed:
            task_log(tid, "搜狗（%s）已在启用列表中且为启用状态" % sid)
        elif already and changed:
            task_log(tid, "搜狗（%s）在列表中但为禁用，已改为启用" % sid)
        else:
            task_log(tid, "搜狗（%s）不在列表中，已添加到首位" % sid)

        # 备份
        bak = pf + ".uostool.bak"
        h.exec_cmd("cp -f %s %s" % (shell_quote(pf), shell_quote(bak)), 20)
        task_log(tid, "已备份原配置 → %s" % bak)

        if changed:
            lines[meta["enabled_idx"]] = "EnabledIMList=" + new_enabled
            if set_default and "imname_idx" in meta:
                lines[meta["imname_idx"]] = "IMName=" + sid
                task_log(tid, "已设为当前默认输入法")
            h.put_bytes(pf, ("\n".join(lines) + "\n").encode("utf-8"))
            task_log(tid, "配置文件已更新")
        else:
            task_log(tid, "配置无需修改，跳过写入")

        # 重启 fcitx —— SSH 会话里 DISPLAY 通常为空，必须显式指定
        code_d, out_d, _ = h.exec_cmd(
            "ls /tmp/.X11-unix/ 2>/dev/null | head -5", 15)
        socks = [x for x in (out_d or "").split() if x.startswith("X")]
        disp = (":" + socks[0][1:]) if socks else ":0"
        task_log(tid, "探测到 DISPLAY = %s" % disp)

        restart_cmd = ("export DISPLAY=%s; "
                       "(fcitx-remote -r 2>/dev/null || fcitx5-remote -r 2>/dev/null "
                       "|| true)" % disp)
        code, out, err = h.exec_cmd(restart_cmd, 40)
        task_log(tid, "已发送重载配置指令 (exit=%s)%s" %
                 (code, (" 输出: " + (out or "").strip()) if (out or "").strip() else ""))

        # 复核
        raw2 = h.get_bytes(pf)
        ok = False
        if raw2 is not None:
            _, meta2 = ime_parse_profile(raw2.decode("utf-8", "replace"))
            en2 = meta2.get("enabled", "")
            for x in en2.split(","):
                if x.split(":")[0] == sid and x.endswith(":True"):
                    ok = True
                    break
        h.close()

        msg = []
        msg.append("搜狗输入法条目: %s" % sid)
        msg.append("配置中状态: %s" % ("已启用 ✓" if ok else "未能确认"))
        if set_default:
            msg.append("已设为默认输入法。")
        msg.append("fcitx 已重载配置。")
        msg.append("若桌面右下角仍看不到，请注销并重新登录图形界面。")
        task_done(tid, {"ok": ok, "sogou_id": sid, "already": already,
                        "changed": changed, "fcitx": info.get("fcitx"),
                        "display": disp,
                        "msg": "\n".join(msg)})
    except Exception as e:
        task_log(tid, "加入输入法出错: %s" % e)
        task_done(tid, {"ok": False, "error": str(e)}, status="error")


def action_sysinfo(tid, cfg):
    h = Host(cfg, log=lambda m: task_log(tid, m))
    try:
        task_log(tid, "连接并采集硬件信息 ...")
        h.connect()
        code, out, err = h.exec_root(COLLECT_SCRIPT, timeout=180)
        if code != 0 and not out:
            task_log(tid, "采集失败: %s" % (err or out)[:500])
            task_done(tid, status="error")
            return
        parsed = parse_sysinfo(out)
        task_log(tid, "采集完成")
        h.close()
        task_done(tid, parsed)
    except Exception as e:
        task_log(tid, "失败: %s" % e)
        task_done(tid, status="error")


def action_packages(tid, cfg, keyword=""):
    h = Host(cfg, log=lambda m: task_log(tid, m))
    try:
        task_log(tid, "读取已安装软件列表 ...")
        h.connect()
        cmd = "dpkg-query -W -f='${Package}\\t${Version}\\t${Status}\\n' 2>/dev/null"
        if keyword:
            cmd += " | grep -i %s" % shell_quote(keyword)
        code, out, err = h.exec_cmd(cmd, timeout=120)
        pkgs = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                if "install ok installed" in parts[2] or parts[2].startswith("ii"):
                    pkgs.append({"name": parts[0], "version": parts[1]})
        task_log(tid, "共 %d 个软件包" % len(pkgs))
        h.close()
        task_done(tid, {"packages": pkgs})
    except Exception as e:
        task_log(tid, "失败: %s" % e)
        task_done(tid, status="error")


def action_uninstall(tid, cfg, package, purge=False):
    h = Host(cfg, log=lambda m: task_log(tid, m))
    try:
        if package.lower() in DANGER_PACKAGES:
            task_log(tid, "拒绝卸载: %s 属于系统关键包" % package)
            task_done(tid, status="error")
            return
        task_log(tid, "开始卸载 %s ..." % package)
        h.connect()
        act = "purge" if purge else "remove"
        cmd = "DEBIAN_FRONTEND=noninteractive apt-get %s -y %s 2>&1" % (act, shell_quote(package))
        code, out, err = h.exec_root(cmd, timeout=600)
        for line in (out or "").splitlines():
            task_log(tid, line)
        if err:
            task_log(tid, err)
        task_log(tid, "退出码 %s" % code)
        h.close()
        task_done(tid, {"code": code})
    except Exception as e:
        task_log(tid, "失败: %s" % e)
        task_done(tid, status="error")


def action_install(tid, cfg, local_path, filename):
    h = Host(cfg, log=lambda m: task_log(tid, m))
    try:
        task_log(tid, "连接主机 ...")
        h.connect()
        remote_dir = "~/Downloads"
        remote_path = "/home/%s/Downloads/%s" % (cfg.get("username", "root"), filename)
        # 确认目录存在
        h.exec_cmd("mkdir -p %s" % remote_dir, 20)
        size = os.path.getsize(local_path)
        task_log(tid, "上传 %s (%.1f MB) ..." % (filename, size / 1048576.0))
        last = [0]

        def cb(done, total):
            pct = int(done * 100 / total) if total else 0
            if pct - last[0] >= 5 or done == total:
                last[0] = pct
                task_log(tid, "上传进度 %d%%" % pct)
                with TASKS_LOCK:
                    if tid in TASKS:
                        TASKS[tid]["progress"] = pct

        h.put_file(local_path, remote_path, callback=cb)
        task_log(tid, "上传完成: %s" % remote_path)
        task_log(tid, "开始安装 (dpkg -i) ...")
        cmd = "DEBIAN_FRONTEND=noninteractive dpkg -i %s 2>&1" % shell_quote(remote_path)
        code, out, err = h.exec_root(cmd, timeout=900)
        for line in (out or "").splitlines():
            task_log(tid, line)
        if err:
            task_log(tid, err)
        if code != 0:
            task_log(tid, "dpkg 返回 %s, 尝试修复依赖 ..." % code)
            c2, o2, e2 = h.exec_root(
                "DEBIAN_FRONTEND=noninteractive apt-get -f install -y 2>&1", timeout=900)
            for line in (o2 or "").splitlines():
                task_log(tid, line)
            code = c2
        task_log(tid, "安装结束, 退出码 %s" % code)
        h.close()
        task_done(tid, {"code": code})
    except Exception as e:
        task_log(tid, "失败: %s" % e)
        task_log(tid, traceback.format_exc()[-800:])
        task_done(tid, status="error")


# --------------------------------------------------------------------------
# 前端页面
# --------------------------------------------------------------------------
PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UOS 远程助手</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;font-size:13px;
 background:#f5f6f8;color:#1f2328;line-height:1.6}
button{font-family:inherit;font-size:13px;padding:6px 14px;border:1px solid #d0d7de;
 background:#fff;border-radius:6px;cursor:pointer;color:#1f2328}
button:hover{background:#f3f4f6}
button:disabled{opacity:.5;cursor:not-allowed}
button.primary{background:#1f6feb;color:#fff;border-color:#1f6feb}
button.primary:hover{background:#1a5fd0}
button.danger{color:#cf222e;border-color:#ffcecb}
button.danger:hover{background:#fff5f5}
input,select{font-family:inherit;font-size:13px;padding:6px 10px;border:1px solid #d0d7de;
 border-radius:6px;background:#fff;color:#1f2328;width:100%}
label{font-size:12px;color:#57606a;display:block;margin-bottom:4px}
.top{display:flex;align-items:center;justify-content:space-between;padding:12px 20px;
 background:#fff;border-bottom:1px solid #e5e7eb}
.top h1{font-size:15px;font-weight:500}
.status{display:flex;align-items:center;gap:8px;font-size:12px;color:#57606a}
.dot{width:8px;height:8px;border-radius:50%;background:#d0d7de;display:inline-block}
.dot.on{background:#1a7f37}.dot.err{background:#cf222e}
.wrap{display:grid;grid-template-columns:220px minmax(0,1fr);height:calc(100vh - 49px)}
.side{background:#fff;border-right:1px solid #e5e7eb;padding:14px;overflow-y:auto}
.side h3{font-size:12px;color:#57606a;font-weight:500;margin:14px 0 8px}
.side h3:first-child{margin-top:0}
.conn{padding:8px 10px;border-radius:6px;cursor:pointer;font-size:13px;
 display:flex;justify-content:space-between;align-items:center;gap:6px}
.conn:hover{background:#f3f4f6}
.conn.active{background:#ddf4ff}
.conn .del{color:#cf222e;font-size:12px;padding:0 4px}
.navitem{padding:8px 10px;border-radius:6px;cursor:pointer;font-size:13px;color:#1f2328}
.navitem:hover{background:#f3f4f6}
.navitem.active{background:#f0f3f6;font-weight:500}
.main{padding:18px 22px;overflow-y:auto}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:14px 16px;margin-bottom:14px}
.card h2{font-size:14px;font-weight:500;margin-bottom:10px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}
.kv{background:#f6f8fa;border-radius:6px;padding:10px 12px}
.kv .k{font-size:12px;color:#57606a}
.kv .v{font-size:13px;margin-top:2px;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:12px;color:#57606a;font-weight:500;padding:8px 10px;
 border-bottom:1px solid #e5e7eb}
td{padding:8px 10px;border-bottom:1px solid #f0f1f3;word-break:break-all}
tr:hover td{background:#fafbfc}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.empty{color:#57606a;font-size:13px;padding:16px;text-align:center}
.log{background:#0d1117;color:#c9d1d9;font-family:ui-monospace,Consolas,monospace;
 font-size:12px;padding:10px 14px;border-radius:6px;height:170px;overflow-y:auto;
 white-space:pre-wrap;line-height:1.5}
.modal{position:absolute;inset:0;background:rgba(0,0,0,.35);display:flex;
 align-items:center;justify-content:center;padding:20px}
.modal .box{background:#fff;border-radius:10px;padding:20px;width:500px;max-height:90vh;overflow-y:auto}
.modal h2{font-size:15px;font-weight:500;margin-bottom:14px}
.field{margin-bottom:12px}
.modal .btns{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
.drop{border:1px dashed #d0d7de;border-radius:8px;padding:26px;text-align:center;
 color:#57606a;cursor:pointer}
.drop.over{background:#ddf4ff;border-color:#1f6feb}
.bar{height:6px;background:#e5e7eb;border-radius:3px;overflow:hidden;margin-top:8px}
.bar i{display:block;height:100%;background:#1f6feb;width:0}
.tag{display:inline-block;font-size:12px;padding:1px 8px;border-radius:10px;
 background:#ddf4ff;color:#0969da}
.tag.warn{background:#fff8c5;color:#9a6700}
.tag.err{background:#ffebe9;color:#cf222e}
.spin{color:#57606a;font-size:12px}
.hint{font-size:12px;color:#6b7280;margin-top:5px;line-height:1.5}
.radios{display:flex;flex-wrap:wrap;gap:8px}
.radio{display:inline-flex;align-items:center;gap:6px;border:1px solid #d0d7de;
 border-radius:7px;padding:7px 12px;cursor:pointer;background:#fff;
 font-size:13px;color:#1f2328;margin-bottom:0}
.radio.on{border-color:#1f6feb;background:#f0f7ff;color:#0969da;font-weight:500}
.radio input{margin:0;flex-shrink:0;width:auto}
.priv-desc{margin-top:9px;font-size:12px;color:#57606a;line-height:1.6;
 background:#f6f8fa;border:1px solid #e5e7eb;border-radius:7px;padding:9px 12px}
.privcard{display:flex;align-items:center;justify-content:space-between;gap:14px;
 border:1px solid #d0d7de;border-radius:9px;padding:13px 16px;margin-bottom:16px;background:#fafbfc}
.privcard.ok{border-color:#a7f3d0;background:#f0fdf4}
.privcard.no{border-color:#ffc9c9;background:#fef2f2}
.privcard.un{border-color:#d0d7de;background:#fafbfc}
.pleft{display:flex;flex-direction:column;gap:3px;min-width:0}
.pleft .t{font-size:13px;font-weight:500;display:flex;align-items:center;gap:7px}
.pleft .d{font-size:12px;color:#6b7280;line-height:1.5}
.pdot{width:9px;height:9px;border-radius:50%;background:#9ca3af;flex-shrink:0}
.pdot.ok{background:#16a34a}
.pdot.no{background:#dc2626}
.pbtns{display:flex;gap:8px;flex-shrink:0}
</style>
</head>
<body>
<div class="top">
  <h1>UOS 远程助手</h1>
  <div class="status"><span class="dot" id="dot"></span><span id="statusText">未连接</span></div>
</div>
<div class="wrap">
  <div class="side">
    <h3>已保存连接</h3>
    <div id="connList"></div>
    <div class="navitem" id="btnNew" style="color:#0969da">+ 新建连接</div>
    <h3>功能</h3>
    <div class="navitem active" data-tab="info">系统信息</div>
    <div class="navitem" data-tab="soft">软件管理</div>
    <div class="navitem" data-tab="install">上传安装</div>
    <div class="navitem" data-tab="sudo">加入 sudoers</div>
    <div class="navitem" data-tab="ime">输入法</div>
  </div>
  <div class="main">
    <div class="privcard un" id="privCard">
      <div class="pleft">
        <div class="t"><span class="pdot" id="pdot"></span>权限状态</div>
        <div class="d" id="privDesc">尚未检测。安装/卸载软件需要 root 权限，请先检测提权方式。</div>
      </div>
      <div class="pbtns">
        <button id="btnElevate">检测提权</button>
      </div>
    </div>

    <div id="tab-info">
      <div class="card">
        <div class="row" style="justify-content:space-between">
          <h2 style="margin:0">硬件与系统信息</h2>
          <div style="display:flex;gap:8px">
            <button id="btnSysinfo">采集信息</button>
            <button id="btnExport">导出 JSON</button>
          </div>
        </div>
        <div id="sysinfoBox"><div class="empty">点击「采集信息」获取远程主机硬件信息</div></div>
      </div>
    </div>

    <div id="tab-soft" style="display:none">
      <div class="card">
        <h2>已安装软件</h2>
        <div class="row">
          <input id="kw" placeholder="模糊搜索软件包名…" style="flex:1;min-width:220px">
          <button id="btnPkgs" class="primary">读取列表</button>
          <span class="spin" id="pkgCount"></span>
        </div>
        <div id="pkgBox"><div class="empty">点击「读取列表」加载已安装软件</div></div>
      </div>
    </div>

    <div id="tab-install" style="display:none">
      <div class="card">
        <h2>上传并安装软件包</h2>
        <div class="drop" id="drop">拖拽 .deb 文件到此处，或点击选择</div>
        <input type="file" id="file" accept=".deb,.rpm,.AppImage,.run,.sh,.tar.gz" style="display:none">
        <div id="fileInfo" style="margin-top:10px"></div>
        <div class="bar"><i id="upbar"></i></div>
        <div class="row" style="margin-top:12px">
          <button id="btnInstall" class="primary" disabled>上传并安装</button>
        </div>
      </div>
    </div>

    <div id="tab-sudo" style="display:none">
      <div class="card">
        <h2>一键加入 sudoers（sudo 用户组）</h2>
        <div class="hint" style="margin-bottom:12px">
          UOS 上安装/卸载软件需要提权。把当前登录账号加入 <b>sudo</b> 组后，
          就可以用「登录密码」通过 <b>sudo</b> 提权，不必再输 root 密码。<br>
          <b>原理：</b>以 root 身份执行 <code>usermod -aG sudo 用户名</code>，因此需要先在「编辑连接」中填写 root 密码。<br>
          <b>注意：</b>加入后需<b>重新登录 SSH</b>（重新检测/重连）sudo 才生效。
        </div>
        <div class="row">
          <button id="btnAddSudo" class="primary">一键加入 sudoers</button>
          <span class="spin" id="sudoStatus"></span>
        </div>
        <div id="sudoBox" style="margin-top:6px"></div>
      </div>
    </div>

    <div id="tab-ime" style="display:none">
      <div class="card">
        <h2>把搜狗输入法加入 fcitx 列表</h2>
        <div class="hint" style="margin-bottom:12px">
          远程把搜狗拼音写进 fcitx 的启用列表并重载配置，不用跑到机器前手动添加。<br>
          <b>原理：</b>fcitx 的输入法列表来自配置文件
          <code>~/.config/fcitx/profile</code>（键 <code>EnabledIMList</code>）。
          程序会自动探测搜狗在 fcitx 里注册的真实 ID（不同版本可能是
          <code>sogoupinyinuos</code>、<code>sogou-pinyin</code> 等），再精确写入并重载 fcitx。<br>
          <b>注意：</b>操作的是<b>当前登录用户</b>的配置；若桌面仍看不到，注销重登图形界面即可。
        </div>
        <div class="row">
          <label style="display:flex;align-items:center;gap:6px;margin:0;font-size:13px;color:#1f2328">
            <input type="checkbox" id="imeDefault" checked style="width:auto"> 同时设为默认输入法
          </label>
          <button id="btnAddIme" class="primary">一键加入搜狗输入法</button>
          <span class="spin" id="imeStatus"></span>
        </div>
        <div id="imeBox" style="margin-top:6px"></div>
      </div>
    </div>

    <div class="card">
      <h2>执行日志</h2>
      <div class="log" id="log">等待操作…</div>
    </div>
  </div>
</div>

<div id="modal" style="display:none"></div>

<script>
let conns = [];
let cur = -1;
let lastSysinfo = null;
let pendingFile = null;
let pendingServerPath = null;

const $ = id => document.getElementById(id);
const logEl = $('log');

function log(msg){
  const t = new Date().toLocaleTimeString('zh-CN',{hour12:false});
  logEl.textContent += '[' + t + '] ' + msg + '\n';
  logEl.scrollTop = logEl.scrollHeight;
}
function setStatus(text, cls){
  $('statusText').textContent = text;
  $('dot').className = 'dot ' + (cls || '');
}
function esc(s){
  return String(s==null?'':s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

async function api(path, opts){
  const r = await fetch(path, opts);
  return await r.json();
}

function renderConns(){
  const box = $('connList');
  if(!conns.length){ box.innerHTML = '<div class="empty" style="padding:8px">暂无连接</div>'; return; }
  box.innerHTML = conns.map((c,i) =>
    '<div class="conn' + (i===cur?' active':'') + '" data-i="' + i + '">' +
      '<span>' + esc(c.name) + '<br><span style="font-size:11px;color:#57606a">' + esc(c.username) + '@' + esc(c.host) + '</span></span>' +
      '<span class="del" data-del="' + i + '">×</span>' +
    '</div>').join('');
  box.querySelectorAll('.conn').forEach(el => {
    el.onclick = e => {
      if(e.target.dataset.del !== undefined){
        const i = +e.target.dataset.del;
        if(confirm('删除连接 ' + conns[i].name + ' ?')){
          api('/api/conns?idx=' + i, {method:'DELETE'}).then(loadConns);
        }
        return;
      }
      cur = +el.dataset.i; renderConns(); setStatus('已选择 ' + conns[cur].name, 'on');
      setPriv('un', '尚未检测。安装/卸载软件需要 root 权限，请先检测提权方式。');
    };
  });
}

async function loadConns(){
  conns = await api('/api/conns');
  renderConns();
}

const PRIV_DESCS = {
  auto:  '自动探测：依次尝试 sudo 免密 → sudo + 登录密码 → su + root 密码，哪个能用就用哪个。',
  sudo:  'sudo：用「登录密码」执行 sudo。要求该账号在 sudoers 列表里。',
  su:    'su 切换到 root：用「root 密码」切到 root。UOS 桌面版上最常用、最可靠。',
  none:  '不提权：仅普通用户权限，能看信息但不能安装/卸载软件。'
};
function privOptions(sel){
  const opts = [
    ['auto','自动探测（推荐）'],
    ['sudo','sudo'],
    ['su','su 切换到 root'],
    ['none','不提权']
  ];
  return '<div class="radios">' + opts.map(function(o){
    return '<label class="radio' + (sel===o[0]?' on':'') + '">' +
      '<input type="radio" name="f_priv" value="' + o[0] + '"' + (sel===o[0]?' checked':'') + '>' +
      '<span>' + o[1] + '</span></label>';
  }).join('') + '</div>' +
  '<div class="priv-desc" id="privDescBox">' + esc(PRIV_DESCS[sel] || PRIV_DESCS.auto) + '</div>';
}

function connForm(idx){
  const c = idx >= 0 ? conns[idx] : {name:'',host:'',port:22,username:'',password:'',root_password:'',privilege:'auto'};
  const isNew = idx < 0;
  $('modal').innerHTML =
    '<div class="modal"><div class="box">' +
    '<h2>' + (isNew?'新建连接':'编辑连接') + '</h2>' +
    '<div class="field"><label>名称</label><input id="f_name" value="' + esc(c.name) + '" placeholder="可留空，留空则显示为 用户名@主机"></div>' +
    '<div class="field"><label>主机地址</label><input id="f_host" value="' + esc(c.host) + '" placeholder="必填，IP 或域名"></div>' +
    '<div class="field"><label>端口</label><input id="f_port" value="' + esc(c.port||22) + '" placeholder="22"></div>' +
    '<div class="field"><label>用户名</label><input id="f_user" value="' + esc(c.username) + '" placeholder="必填"></div>' +
    '<div class="field"><label>登录密码</label><input id="f_pwd" type="password" value="' + esc(c.password) + '"></div>' +
    '<div class="field"><label>root 密码</label><input id="f_root" type="password" value="' + esc(c.root_password||'') + '" placeholder="su 提权时需要，可留空">' +
      '<div class="hint">普通用户装软件需要更高权限。若用 sudo，填登录密码即可；若用 su 切 root，需填 root 密码。</div></div>' +
    '<div class="field"><label>提权方式</label>' +
      privOptions(c.privilege) +
    '</div>' +
    '<div class="btns">' +
      '<button id="f_cancel">取消</button>' +
      '<button id="f_test">测试连接</button>' +
      '<button id="f_save" class="primary">保存</button>' +
    '</div></div></div>';
  $('modal').style.display = 'block';

  // 选中某个提权方式时，更新下方说明框 + 高亮选中的选项
  document.querySelectorAll('input[name=f_priv]').forEach(function(r){
    r.addEventListener('change', function(){
      document.querySelectorAll('.radio').forEach(function(l){
        l.classList.remove('on');
      });
      const lab = r.closest('.radio');
      if(lab) lab.classList.add('on');
      $('privDescBox').textContent = PRIV_DESCS[r.value] || PRIV_DESCS.auto;
    });
  });

  const privRadio = () => { const r = document.querySelector('input[name=f_priv]:checked'); return r ? r.value : 'auto'; };
  const collect = () => ({
    name: $('f_name').value.trim(), host: $('f_host').value.trim(),
    port: parseInt($('f_port').value) || 22, username: $('f_user').value.trim(),
    password: $('f_pwd').value, root_password: $('f_root').value,
    privilege: privRadio()
  });

  $('f_cancel').onclick = () => { $('modal').style.display='none'; $('modal').innerHTML=''; };
  $('f_save').onclick = async () => {
    const data = collect();
    if(!data.host || !data.username){ alert('主机和用户名必填'); return; }
    await api('/api/conns', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({idx: idx, conn: data})});
    $('modal').style.display='none'; $('modal').innerHTML='';
    await loadConns();
    cur = idx >= 0 ? idx : conns.length - 1;
    renderConns(); setStatus('已保存 ' + data.name, 'on');
    log('连接已保存: ' + data.name);
  };
  $('f_test').onclick = async () => {
    const data = collect();
    $('f_test').disabled = true; $('f_test').textContent = '测试中…';
    log('测试连接 ' + data.username + '@' + data.host);
    const tid = (await api('/api/test', {method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify({conn:data})})).task;
    const r = await poll(tid);
    $('f_test').disabled = false; $('f_test').textContent = '测试连接';
    if(r && r.ok) alert('连接成功\n提权方式: ' + r.privilege);
    else alert('连接失败，详见日志');
  };
}

async function poll(tid){
  while(true){
    await new Promise(r => setTimeout(r, 500));
    const t = await api('/api/task?id=' + tid);
    (t.log||[]).slice(-50).forEach(() => {});
    if(t.log && t.log.length){
      logEl.textContent = t.log.join('\n');
      logEl.scrollTop = logEl.scrollHeight;
    }
    if(t.status !== 'running') return t.result;
  }
}

function curConn(){
  if(cur < 0 || !conns[cur]){ alert('请先在左侧选择或新建连接'); return null; }
  return conns[cur];
}

let privState = 'un';
function setPriv(state, desc){
  privState = state;
  const card = $('privCard'), dot = $('pdot'), d = $('privDesc');
  card.className = 'privcard ' + (state === 'ok' ? 'ok' : state === 'no' ? 'no' : 'un');
  dot.className = 'pdot ' + (state === 'ok' ? 'ok' : state === 'no' ? 'no' : '');
  d.textContent = desc || '';
}

$('btnElevate').onclick = async () => {
  const c = curConn(); if(!c) return;
  $('btnElevate').disabled = true; $('btnElevate').textContent = '检测中…';
  setPriv('un', '正在连接并检测可用的提权方式…');
  log('开始检测提权方式（方式: ' + (c.privilege || 'auto') + '）');
  const tid = (await api('/api/elevate', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({conn:c})})).task;
  const r = await poll(tid);
  $('btnElevate').disabled = false; $('btnElevate').textContent = '检测提权';
  if(r && r.ok){
    setPriv('ok', '已取得 root 权限：' + r.privilege + '。可以正常安装/卸载软件。');
    log('提权成功：' + r.privilege);
  } else {
    setPriv('no', '未能取得 root 权限。请检查密码，或在「编辑连接」中更换提权方式后重试。');
    log('提权失败');
  }
};

function renderSysinfo(d){
  lastSysinfo = d;
  const i = d.info || {};
  const kv = (k,v) => v ? '<div class="kv"><div class="k">' + k + '</div><div class="v">' + esc(v) + '</div></div>' : '';
  let h = '<div class="grid">' +
    kv('主机名', i.hostname) + kv('系统', i.os_name) + kv('内核', i.kernel) + kv('架构', i.arch) +
    kv('CPU', i.cpu_model) + kv('CPU 核心', i.cpu_cores) + kv('内存总量', i.mem_total) + kv('已用内存', i.mem_used) +
    kv('运行时长', i.uptime) + kv('产品型号', i.product_name) + kv('主板', i.board_name) + kv('主板序列号', i.board_serial) +
    '</div>';

  if(d.disks && d.disks.length){
    h += '<h2 style="margin:16px 0 8px;font-size:14px">硬盘（含序列号）</h2><table><thead><tr>' +
      '<th>设备</th><th>容量</th><th>型号</th><th>序列号</th></tr></thead><tbody>' +
      d.disks.map(x => '<tr><td class="mono">' + esc(x.name) + '</td><td>' + esc(x.size) +
        '</td><td>' + esc(x.model) + '</td><td class="mono">' + esc(x.serial || '—') + '</td></tr>').join('') +
      '</tbody></table>';
  }
  if(d.nets && d.nets.length){
    h += '<h2 style="margin:16px 0 8px;font-size:14px">网卡</h2><table><thead><tr>' +
      '<th>接口</th><th>MAC 地址</th><th>IPv4</th><th>状态</th><th>速率</th></tr></thead><tbody>' +
      d.nets.map(x => '<tr><td class="mono">' + esc(x.name) + '</td><td class="mono">' + esc(x.mac) +
        '</td><td class="mono">' + esc(x.ip) + '</td><td>' + esc(x.state) +
        '</td><td>' + esc(x.speed ? x.speed + ' Mbps' : '—') + '</td></tr>').join('') +
      '</tbody></table>';
  }
  if(d.df && d.df.length){
    h += '<h2 style="margin:16px 0 8px;font-size:14px">分区使用</h2><table><thead><tr>' +
      '<th>分区</th><th>容量</th><th>已用</th><th>可用</th><th>使用率</th><th>挂载点</th></tr></thead><tbody>' +
      d.df.map(x => '<tr><td class="mono">' + esc(x.fs) + '</td><td>' + esc(x.size) + '</td><td>' + esc(x.used) +
        '</td><td>' + esc(x.avail) + '</td><td>' + esc(x.use) + '</td><td class="mono">' + esc(x.mount) + '</td></tr>').join('') +
      '</tbody></table>';
  }
  $('sysinfoBox').innerHTML = h;
}

let allPkgs = [];
function renderPkgs(list){
  allPkgs = list;
  paintPkgs(list);
}
function paintPkgs(list){
  if(!list.length){ $('pkgBox').innerHTML = '<div class="empty">没有匹配的软件包</div>'; return; }
  $('pkgBox').innerHTML = '<table><thead><tr><th>软件包</th><th style="width:150px">版本</th><th style="width:170px">操作</th></tr></thead><tbody>' +
    list.slice(0, 400).map(p =>
      '<tr><td>' + esc(p.name) + '</td><td class="mono">' + esc(p.version) + '</td><td>' +
      '<button class="danger" data-pkg="' + esc(p.name) + '">卸载</button></td></tr>').join('') +
    '</tbody></table>' + (list.length > 400 ? '<div class="empty">仅显示前 400 条，请用搜索缩小范围</div>' : '');
  $('pkgBox').querySelectorAll('button[data-pkg]').forEach(b => {
    b.onclick = async () => {
      const pkg = b.dataset.pkg;
      const c = curConn(); if(!c) return;
      if(!confirm('确定卸载 ' + pkg + ' ?\n（将执行 apt-get remove）')) return;
      const purge = confirm('是否同时清除配置文件（purge）？\n点「确定」= purge，点「取消」= 仅 remove');
      b.disabled = true; b.textContent = '执行中…';
      log('卸载 ' + pkg + (purge ? ' (purge)' : ''));
      const tid = (await api('/api/uninstall', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({conn:c, package:pkg, purge:purge})})).task;
      const r = await poll(tid);
      b.disabled = false; b.textContent = '卸载';
      if(r && r.code === 0) log('卸载完成: ' + pkg); else log('卸载结束，请查看日志');
    };
  });
}

$('btnNew').onclick = () => connForm(-1);

$('btnSysinfo').onclick = async () => {
  const c = curConn(); if(!c) return;
  $('btnSysinfo').disabled = true; $('sysinfoBox').innerHTML = '<div class="empty">采集中…</div>';
  log('开始采集系统信息');
  const tid = (await api('/api/sysinfo', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({conn:c})})).task;
  const r = await poll(tid);
  $('btnSysinfo').disabled = false;
  if(r) { renderSysinfo(r); log('采集完成'); } else { $('sysinfoBox').innerHTML = '<div class="empty">采集失败</div>'; }
};

$('btnExport').onclick = () => {
  if(!lastSysinfo){ alert('请先采集信息'); return; }
  const blob = new Blob([JSON.stringify(lastSysinfo, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'sysinfo_' + (lastSysinfo.info.hostname || 'host') + '.json';
  a.click();
  log('已导出 JSON');
};

$('btnPkgs').onclick = async () => {
  const c = curConn(); if(!c) return;
  $('btnPkgs').disabled = true; $('pkgBox').innerHTML = '<div class="empty">读取中…</div>';
  const kw = $('kw').value.trim();
  log('读取已安装软件列表' + (kw ? '，关键词: ' + kw : ''));
  const tid = (await api('/api/packages', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({conn:c, keyword:kw})})).task;
  const r = await poll(tid);
  $('btnPkgs').disabled = false;
  if(r && r.packages){ renderPkgs(r.packages); $('pkgCount').textContent = '共 ' + r.packages.length + ' 个'; log('列表读取完成'); }
  else $('pkgBox').innerHTML = '<div class="empty">读取失败</div>';
};

$('kw').oninput = () => {
  const k = $('kw').value.trim().toLowerCase();
  if(!k){ paintPkgs(allPkgs); return; }
  paintPkgs(allPkgs.filter(p => p.name.toLowerCase().includes(k)));
};

const drop = $('drop');
drop.onclick = () => $('file').click();
drop.ondragover = e => { e.preventDefault(); drop.classList.add('over'); };
drop.ondragleave = () => drop.classList.remove('over');
drop.ondrop = e => { e.preventDefault(); drop.classList.remove('over');
  if(e.dataTransfer.files.length) pick(e.dataTransfer.files[0]); };
$('file').onchange = e => { if(e.target.files.length) pick(e.target.files[0]); };

async function pick(f){
  pendingFile = f;
  $('fileInfo').innerHTML = '已选择: <b>' + esc(f.name) + '</b> (' + (f.size/1048576).toFixed(2) + ' MB)';
  $('upbar').style.width = '0';
  $('btnInstall').disabled = false;
  log('选择文件: ' + f.name);
}

$('btnInstall').onclick = async () => {
  const c = curConn(); if(!c || !pendingFile) return;
  $('btnInstall').disabled = true;
  log('上传 ' + pendingFile.name + ' 到服务器（本机）…');
  const r = await fetch('/api/upload?name=' + encodeURIComponent(pendingFile.name),
    {method:'POST', body: pendingFile});
  const j = await r.json();
  if(!j.path){ log('上传失败'); $('btnInstall').disabled = false; return; }
  log('开始传输到远程主机并安装');
  const tid = (await api('/api/install', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({conn:c, path:j.path, filename:pendingFile.name})})).task;
  while(true){
    await new Promise(r2 => setTimeout(r2, 600));
    const t = await api('/api/task?id=' + tid);
    if(t.log){ logEl.textContent = t.log.join('\n'); logEl.scrollTop = logEl.scrollHeight; }
    $('upbar').style.width = (t.progress || 0) + '%';
    if(t.status !== 'running') break;
  }
  $('btnInstall').disabled = false;
  log('安装流程结束');
};

document.querySelectorAll('.navitem[data-tab]').forEach(el => {
  el.onclick = () => {
    document.querySelectorAll('.navitem[data-tab]').forEach(x => x.classList.remove('active'));
    el.classList.add('active');
    ['info','soft','install','sudo','ime'].forEach(t => $('tab-' + t).style.display = (t === el.dataset.tab ? '' : 'none'));
  };
});

$('btnAddIme').onclick = async () => {
  const c = curConn(); if(!c) return;
  const setDefault = $('imeDefault').checked;
  $('btnAddIme').disabled = true; $('btnAddIme').textContent = '执行中…';
  $('imeStatus').textContent = ''; $('imeBox').innerHTML = '';
  log('开始加入搜狗输入法: ' + c.username + '@' + c.host);
  const tid = (await api('/api/addime', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({conn:c, set_default:setDefault})})).task;
  const r = await poll(tid);
  $('btnAddIme').disabled = false; $('btnAddIme').textContent = '一键加入搜狗输入法';
  if(r && r.ok){
    $('imeBox').innerHTML = '<div class="hint" style="color:#16a34a;font-weight:500;white-space:pre-line">' +
      esc(r.msg || ('已加入：' + r.sogou_id)) + '</div>';
    log('加入搜狗输入法完成（ID: ' + r.sogou_id + '）');
  } else {
    $('imeBox').innerHTML = '<div class="hint" style="color:#dc2626;font-weight:500;white-space:pre-line">' +
      esc((r && r.error) || '加入失败，详见日志') + '</div>';
    log('加入搜狗输入法失败');
  }
};

$('btnAddSudo').onclick = async () => {
  const c = curConn(); if(!c) return;
  if(!confirm('确定把账号「' + c.username + '」加入 sudo 用户组吗？\n\n此操作需要 root 密码（su 提权）。\n加入后需重新登录 SSH 才生效。')) return;
  $('btnAddSudo').disabled = true; $('btnAddSudo').textContent = '执行中…';
  $('sudoStatus').textContent = '';
  $('sudoBox').innerHTML = '';
  log('开始加入 sudoers: ' + c.username + '@' + c.host);
  const tid = (await api('/api/addsudo', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({conn:c})})).task;
  const r = await poll(tid);
  $('btnAddSudo').disabled = false; $('btnAddSudo').textContent = '一键加入 sudoers';
  if(r && r.ok){
    $('sudoBox').innerHTML = '<div class="hint" style="color:#16a34a;font-weight:500">' + esc(r.msg || '已加入 sudo 组') + '</div>';
    setPriv('ok', r.msg || '已加入 sudo 组');
    log('加入 sudoers 完成');
  } else {
    $('sudoBox').innerHTML = '<div class="hint" style="color:#dc2626;font-weight:500">' + esc((r && r.error) || '加入失败，详见日志') + '</div>';
    log('加入 sudoers 失败');
  }
};

loadConns().then(() => { if(conns.length){ cur = 0; renderConns(); setStatus('已选择 ' + conns[0].name, 'on'); } });
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# HTTP 服务
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    # ---------- GET ----------
    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        q = parse_qs(u.query)
        try:
            if p in ("/", "/index.html"):
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif p == "/api/conns":
                self._json(load_conns())
            elif p == "/api/task":
                tid = q.get("id", [""])[0]
                with TASKS_LOCK:
                    t = TASKS.get(tid)
                    data = dict(t) if t else {"status": "missing", "log": [], "result": None}
                self._json(data)
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": str(e)}, 500)

    # ---------- POST ----------
    def do_POST(self):
        u = urlparse(self.path)
        p = u.path
        q = parse_qs(u.query)
        try:
            if p == "/api/conns":
                data = json.loads(self._body().decode("utf-8"))
                conns = load_conns()
                idx = data.get("idx", -1)
                conn = data.get("conn", {})
                if isinstance(idx, int) and 0 <= idx < len(conns):
                    conns[idx] = conn
                else:
                    conns.append(conn)
                save_conns(conns)
                self._json({"ok": True, "conns": conns})

            elif p == "/api/test":
                data = json.loads(self._body().decode("utf-8"))
                tid = new_task()
                run_async(tid, lambda t: action_test(t, data["conn"]))
                self._json({"task": tid})

            elif p == "/api/elevate":
                data = json.loads(self._body().decode("utf-8"))
                tid = new_task()
                run_async(tid, lambda t: action_elevate(t, data["conn"]))
                self._json({"task": tid})

            elif p == "/api/addsudo":
                data = json.loads(self._body().decode("utf-8"))
                tid = new_task()
                run_async(tid, lambda t: action_addsudo(t, data["conn"]))
                self._json({"task": tid})

            elif p == "/api/addime":
                data = json.loads(self._body().decode("utf-8"))
                tid = new_task()
                run_async(tid, lambda t: action_addime(
                    t, data["conn"], bool(data.get("set_default", True))))
                self._json({"task": tid})

            elif p == "/api/sysinfo":
                data = json.loads(self._body().decode("utf-8"))
                tid = new_task()
                run_async(tid, lambda t: action_sysinfo(t, data["conn"]))
                self._json({"task": tid})

            elif p == "/api/packages":
                data = json.loads(self._body().decode("utf-8"))
                tid = new_task()
                run_async(tid, lambda t: action_packages(t, data["conn"], data.get("keyword", "")))
                self._json({"task": tid})

            elif p == "/api/uninstall":
                data = json.loads(self._body().decode("utf-8"))
                tid = new_task()
                run_async(tid, lambda t: action_uninstall(t, data["conn"],
                                                          data["package"], bool(data.get("purge"))))
                self._json({"task": tid})

            elif p == "/api/upload":
                name = unquote(q.get("name", ["upload.bin"])[0])
                safe = re.sub(r"[^\w.\-]", "_", os.path.basename(name))
                dest = os.path.join(UPLOAD_DIR, "%d_%s" % (int(time.time()), safe))
                length = int(self.headers.get("Content-Length") or 0)
                with open(dest, "wb") as f:
                    left = length
                    while left > 0:
                        chunk = self.rfile.read(min(65536, left))
                        if not chunk:
                            break
                        f.write(chunk)
                        left -= len(chunk)
                self._json({"path": dest, "name": safe})

            elif p == "/api/install":
                data = json.loads(self._body().decode("utf-8"))
                tid = new_task()
                run_async(tid, lambda t: action_install(t, data["conn"],
                                                        data["path"], data["filename"]))
                self._json({"task": tid})

            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": str(e), "trace": traceback.format_exc()[-800:]}, 500)

    # ---------- DELETE ----------
    def do_DELETE(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path == "/api/conns":
                idx = int(q.get("idx", ["-1"])[0])
                conns = load_conns()
                if 0 <= idx < len(conns):
                    conns.pop(idx)
                    save_conns(conns)
                self._json({"ok": True})
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": str(e)}, 500)


def start_server():
    """启动 HTTP 服务（后台线程），返回 (server, url)。"""
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "http://%s:%d" % (HOST, PORT)


def stop_server(srv):
    try:
        srv.shutdown()
    except Exception:
        pass
    try:
        srv.server_close()
    except Exception:
        pass


def run_native_window(url, srv):
    """用 pywebview 打开原生窗口承载界面。窗口关闭即返回，随后停服务退出。"""
    import webview

    title = "UOS 远程助手  —  %s" % url
    win = webview.create_window(
        title,
        url=url,
        width=1280,
        height=860,
        min_size=(1024, 700),
        background_color="#0f1115",
    )

    def on_closed():
        print("窗口已关闭，正在停止服务…")

    try:
        win.events.closed += on_closed
    except Exception:
        pass
    webview.start(debug=False)


def run_tk_window(url, srv):
    """回退方案：标准库 tkinter 状态窗口。关窗即停服务。"""
    import tkinter as tk
    from tkinter import scrolledtext, messagebox

    root = tk.Tk()
    root.title("UOS 远程助手")
    root.geometry("760x520")
    root.configure(bg="#0f1115")

    head = tk.Frame(root, bg="#0f1115")
    head.pack(fill="x", padx=18, pady=(16, 6))
    tk.Label(head, text="●", fg="#3ddc84", bg="#0f1115",
             font=("Segoe UI", 16)).pack(side="left")
    tk.Label(head, text=" 服务运行中", bg="#0f1115", fg="#e8ecf1",
             font=("Segoe UI", 14, "bold")).pack(side="left")
    tk.Label(root, text="界面地址：" + url, bg="#0f1115", fg="#8b95a5",
             font=("Segoe UI", 10)).pack(anchor="w", padx=18)

    tk.Label(root, text="关闭本窗口 = 停止服务并退出程序（无需再手动结束进程）",
             bg="#0f1115", fg="#c8d0da", font=("Segoe UI", 10)).pack(
        anchor="w", padx=18, pady=(10, 4))

    tk.Label(root, text="运行日志", bg="#0f1115", fg="#8b95a5",
             font=("Segoe UI", 9)).pack(anchor="w", padx=18, pady=(12, 2))
    box = scrolledtext.ScrolledText(root, height=14, bg="#151922", fg="#c8d0da",
                                    insertbackground="#c8d0da",
                                    font=("Consolas", 9), relief="flat")
    box.pack(fill="both", expand=True, padx=18, pady=(0, 10))
    box.insert("end", "服务已启动：%s\n" % url)
    try:
        for c in load_conns():
            box.insert("end", "已保存连接：%s  %s@%s\n" %
                       (c.get("name", ""), c.get("username", ""), c.get("host", "")))
    except Exception:
        pass
    box.configure(state="disabled")

    bar = tk.Frame(root, bg="#0f1115")
    bar.pack(fill="x", padx=18, pady=(0, 16))
    tk.Button(bar, text="在浏览器中打开界面", width=20,
              command=lambda: webbrowser.open(url)).pack(side="left")
    tk.Button(bar, text="停止服务并退出", width=16,
              command=lambda: root.destroy()).pack(side="right")

    def on_close():
        if messagebox.askokcancel("退出", "关闭窗口将停止服务并退出程序，确定吗？"):
            root.destroy()
        # 取消则什么也不做，窗口保持

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


def main():
    srv, url = start_server()
    print("=" * 52)
    print("  UOS 远程助手已启动")
    print("  访问地址: %s" % url)
    print("  配置文件: %s" % CONFIG_PATH)
    print("  关闭窗口即停止服务")
    print("=" * 52)

    mode = os.environ.get("UOS_TOOL_GUI", "1").strip().lower()
    try:
        if mode in ("0", "off", "browser"):
            webbrowser.open(url)
            srv.serve_forever()
        else:
            try:
                run_native_window(url, srv)
            except Exception as e:
                print("原生窗口不可用(%s)，回退到状态窗口" % e)
                run_tk_window(url, srv)
    except KeyboardInterrupt:
        pass
    finally:
        stop_server(srv)
        print("服务已停止，程序退出")


if __name__ == "__main__":
    main()
