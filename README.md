# FloppyKey

将 3.5" 软盘作为物理密钥解锁 Linux 桌面的工具。

## 特性

- 插入软盘自动唤醒并解锁桌面（GNOME Wayland / X11）。
- 单向解锁：拔出软盘不自动锁屏。
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

插入 FAT12 格式软盘后执行：

```bash
floppy-key pair
```

### 命令

```bash
floppy-key status   # 查看硬件、介质与服务状态
floppy-key pair     # 制作钥匙软盘
floppy-key unlock   # 手动测试解锁
floppy-key reset    # 重置失败计数与会话锁定
floppy-key revoke   # 作废当前钥匙绑定
floppy-key daemon   # 前台运行守护进程
```

### 卸载

```bash
./uninstall.sh
```

## 说明

本项目仅为玩具用途，请勿用于高安全要求的生产环境。

## License

[MIT](LICENSE)
