# FloppyKey

将 3.5" 软盘作为物理密钥解锁 Linux 桌面的工具。

## 特性

- 插入软盘自动唤醒并解锁桌面（GNOME Wayland / X11）。
- 单向解锁：拔出软盘不自动锁屏。
- 两种运行模式：
  - **静态钥匙（默认）**：配对后钥匙 token 固定，软盘可全程开启物理写保护片，避免磨损与意外写入。
  - **动态滚动（`--rolling`）**：每次锁屏解锁后两阶段提交更换新 token；若出示历史作废 token 即判定为克隆盘并永久作废配对。
- 支持手动轮转：提供 `floppy-key rotate` 子命令在需要时随时更换 token。
- 仅使用 Python 3 标准库，无第三方依赖。
- 以用户权限运行（`systemd --user`），无需 root 权限。
- 读取 `/sys/block/<dev>/size` 状态检测物理介质，避开 Linux VFS 页面缓存。

## 安装与使用

### 安装

```bash
git clone https://github.com/2onic/floppy-key.git
cd floppy-key
./install.sh
```

### 配对软盘

插入 FAT 格式软盘后执行：

```bash
# 默认制作静态钥匙
floppy-key pair

# 或启用动态滚动钥匙
floppy-key pair --rolling
```

### 常用命令

```bash
floppy-key status      # 查看硬件、介质、配对模式与服务状态
floppy-key pair        # 制作钥匙软盘（-r / --rolling 启用动态轮转）
floppy-key rotate      # 手动更换软盘与主机的钥匙 token
floppy-key unlock      # 手动测试屏幕唤醒与解锁
floppy-key reset       # 重置会话失败尝试计数与锁定状态
floppy-key revoke      # 作废当前钥匙绑定（-w 可同时擦除软盘）
floppy-key daemon      # 前台运行守护进程（-t 接管后台服务）
```

### 卸载

```bash
./uninstall.sh
```

## 安全模型与说明

- **威胁模型**：仅针对坐在锁屏前、未持有合法钥匙盘的物理旁观者。任何以当前用户身份运行的本地进程本身即可直接调用桌面解锁接口，因此不提供针对本地恶意进程的防御。
- **克隆检测**：在滚动模式下，若检测到出示历史已作废的 token（说明软盘被克隆或遭遇重放），配对将进入 `COMPROMISED` 状态并永久失效，必须执行 `floppy-key pair` 重新配对。
- **玩具用途**：本项目仅供复古玩具与趣味用途，请勿用于高安全要求的生产环境。

## License

[MIT](LICENSE)
