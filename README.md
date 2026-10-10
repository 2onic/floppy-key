# FloppyKey

> **A retro novelty toy that unlocks your Linux desktop with a real 3.5" floppy disk.**  
> 一个极客仪式感玩具：把一张 3.5 英寸软盘作为物理实体钥匙，插入软盘，伴随着机械马达的转动声唤醒并解锁桌面。

---

## 特性 (Features)

- **纯粹的仪式感**：插入软盘，马达转动，验证钥匙，桌面瞬间点亮解锁。
- **单向防抖设计**：插盘即解锁，拔盘不误锁（锁屏仍由超时或快捷键接管，避免机械抖动导致意外锁屏）。
- **纯标准库零依赖**：纯 Python 3 实现，无第三方 pip 依赖，开箱即用。
- **纯用户态权限**：运行在 `systemd --user` 下，无需 `root` / `sudo`，通过原生 D-Bus / `loginctl` 解锁。
- **真实硬件传感**：直读 `/sys/block/<dev>/size` 硬件寄存器，彻底规避 Linux VFS 页面缓存导致的幽灵文件陷阱。

---

## 快速上手 (Quick Start)

### 1. 安装 (Installation)

克隆项目并运行安装脚本：

```bash
git clone https://github.com/your-username/floppy-key.git
cd floppy-key
./install.sh
```

安装脚本会将命令软链接至 `~/.local/bin/floppy-key`，并自动启动后台守护服务 `floppy-key.service`。

### 2. 制作钥匙 (Pairing)

插入你的 3.5 英寸软盘（FAT12 格式），运行：

```bash
floppy-key pair
```

程序会在软盘上生成高熵凭据并在本机记录加盐哈希，配对即刻生效！

### 3. 开始使用 (Usage)

按下 `Super + L` 锁屏，然后把配对好的软盘推入软驱 —— 享受咔哒声与桌面亮起的瞬间。

---

## CLI 命令速查 (Commands)

```bash
floppy-key status   # 查看软驱硬件、介质在位、配对状态与后台服务
floppy-key pair     # 为当前插入的软盘制作解锁钥匙
floppy-key unlock   # 手动测试桌面唤醒与解锁链路
floppy-key revoke   # 作废当前本机的钥匙绑定
floppy-key daemon   # 前台运行监听守护进程（调试使用）
```

---

## 卸载 (Uninstall)

如果不想玩了，运行一键卸载脚本即可彻底清理：

```bash
./uninstall.sh
```

---

## 免责声明 (Disclaimer)

这是一个**玩具（Toy / Novelty）**项目，仅供复古极客折腾、仪式感体验与娱乐，请勿将其用于高安全性生产环境！
