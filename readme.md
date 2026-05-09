<h1 align="center">WeChatMsg CLI</h1>
<div align="center">
    <img src="https://img.shields.io/badge/WeChat-4.0~4.1.x-green.svg">
    <img src="https://img.shields.io/badge/Platform-Windows-blue.svg">
    <img src="https://img.shields.io/badge/Python-3.10-yellow.svg">
    <img src="https://img.shields.io/github/license/LC044/WeChatMsg" />
</div>

> 基于 [LC044/WeChatMsg](https://github.com/LC044/WeChatMsg) 二次开发，新增 **CLI 命令行模式** 和 **微信 4.1.x 版本支持**。

## 新增特性

- **微信 4.1.x 支持** — 版本无关的密钥提取，不依赖 YARA 规则，支持微信 4.0 / 4.1.x
- **CLI 命令行模式** — 无需 GUI，命令行一键解密 + 导出
- **批量 CSV 导出** — 所有聊天记录批量导出为 CSV，Excel 直接打开
- **PyInstaller 打包** — 单个 exe 可执行文件，无需 Python 环境

## 快速开始

### 1. 解密数据库

```cmd
:: 以管理员身份运行 CMD
WeChatMsg.exe decrypt-v2 --db-dir "D:\...\xwechat_files\wxid_xxxx\db_storage"
```

- `--db-dir`: 微信数据库目录路径（微信设置 → 文件管理 中查看）
- 请确保**微信正在运行**，且以**管理员身份**运行本程序
- 解密后文件保存在 `./decrypted/` 目录

### 2. 导出聊天记录为 CSV

```cmd
python main.py export-csv --db-dir ./decrypted --output-dir ./csv_output
```

- 自动遍历所有联系人/群聊，每个对话生成一个 CSV 文件
- CSV 列: `wxid, 昵称, 备注, 消息ID, 类型, 发送人ID, 发送人, 时间, 内容`
- UTF-8 BOM 编码，Excel 直接打开无乱码

### 完整命令列表

```cmd
WeChatMsg.exe --help

:: 解密 (版本无关模式，支持 4.0/4.1.x)
WeChatMsg.exe decrypt-v2 --db-dir "D:\...\db_storage"

:: 解密 (YARA 模式，仅支持 4.0.3 及以下)
WeChatMsg.exe decrypt --version 4

:: 列出联系人
WeChatMsg.exe contacts --db-dir ./decrypted

:: 批量导出所有聊天记录为 CSV
WeChatMsg.exe export-csv --db-dir ./decrypted --output-dir ./csv_output

:: 导出单个联系人的聊天记录 (HTML/TXT/CSV/DOCX 等)
WeChatMsg.exe export --db-dir ./decrypted --wxid wxid_xxxx --format csv
```

## 解密原理

微信 4.x 使用 SQLCipher 4 加密数据库（AES-256-CBC + HMAC-SHA512）。WCDB 会在进程内存中缓存每个数据库的 raw key，格式为 `x'<enc_key><salt>'`。

本工具通过以下步骤完成版本无关的解密:

1. **扫描微信进程内存** — 正则匹配 `x'<hex>'` 模式
2. **匹配数据库 salt** — 读取每个 .db 文件头 16 字节作为 salt
3. **HMAC-SHA512 验证** — 确认 key 与 salt 的对应关系
4. **AES-256-CBC 解密** — 直接用提取的 enc_key 解密，不重复跑 PBKDF2

## 源码运行

```bash
# 安装依赖
pip install -r requirements.txt
pip install pyinstaller pycryptodome

# 解密
python main.py decrypt-v2 --db-dir "D:\...\db_storage"

# 导出 CSV
python main.py export-csv --db-dir ./decrypted --output-dir ./output
```

## 打包 exe

```bash
python -m PyInstaller WeChatMsg.spec --noconfirm
# 输出: dist/WeChatMsg/WeChatMsg.exe
```

## 项目结构

```
├── main.py              # CLI 入口 (decrypt-v2 / export-csv / contacts / export)
├── WeChatMsg.spec       # PyInstaller 打包配置
├── wxManager/           # 数据库管理层 (原项目)
│   ├── db_v4/           # V4 数据库接口
│   ├── decrypt/         # 解密模块
│   ├── model/           # 数据模型
│   └── parser/          # 消息解析器
├── exporter/            # 导出器 (HTML/TXT/CSV/DOCX/JSON)
└── doc/                 # 文档
```

## 技术参数

| 参数 | 值 |
|------|-----|
| 加密算法 | SQLCipher 4 (AES-256-CBC) |
| HMAC | HMAC-SHA512 |
| Page Size | 4096 bytes |
| Salt Size | 16 bytes |
| Key Size | 32 bytes |
| Reserve | 80 bytes (IV 16 + HMAC 64) |

## 原项目功能

基于 [LC044/WeChatMsg](https://github.com/LC044/WeChatMsg)，原项目支持:

- Windows 本地微信数据库解密（支持微信 4.0.3 及以下）
- 还原微信聊天界面（文本、图片、视频、表情包等）
- 多格式导出（HTML / CSV / TXT / Word / JSON）
- 可视化年度报告
- 前后端分离的 GUI

---

> \[!IMPORTANT]
> 
> 声明：该项目有且仅有一个目的："留痕"——我的数据我做主，前提是"我的数据"其次才是"我做主"，禁止任何人以任何形式将其用于任何非法用途，对于使用该程序所造成的任何后果，所有创作者不承担任何责任。
> 该软件不能找回删除的聊天记录，任何企图篡改微信聊天数据的想法都是无稽之谈。
> 如果该项目侵犯了您或您产品的任何权益，请联系我删除。

## 致谢

- 原项目: [LC044/WeChatMsg](https://github.com/LC044/WeChatMsg)
- 密钥提取参考: [ylytdeng/wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt)
- PC 微信工具: [xaoyaoo/PyWxDump](https://github.com/xaoyaoo/PyWxDump)

# License

WeChatMsg is licensed under [MIT](./LICENSE).

Copyright © 2022-2024 by SiYuan. CLI extension by wangneal.
