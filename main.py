#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
WeChatMsg CLI - 命令行工具
用于解密微信数据库、查看联系人、导出聊天记录
"""

import argparse
import csv
import ctypes
import ctypes.wintypes as wt
import functools
import hashlib
import hmac as hmac_mod
import json
import os
import re
import sqlite3
import struct
import subprocess
import sys
import time
from multiprocessing import freeze_support

from wxManager import Me, DatabaseConnection, MessageType
from wxManager.decrypt import get_info_v4, get_info_v3
from wxManager.decrypt.decrypt_dat import get_decode_code_v4
from wxManager.decrypt import decrypt_v4, decrypt_v3

from exporter.config import FileType
from exporter import (
    HtmlExporter, TxtExporter, AiTxtExporter, DocxExporter,
    MarkdownExporter, ExcelExporter, CSVExporter
)

# ---------------------------------------------------------------------------
# 版本无关的 key 提取（参考 wechat-decrypt 方案）
# WCDB 会在进程内存中缓存密钥，格式: x'<64hex_enc_key><32hex_salt>'
# 通过正则扫描内存 + HMAC-SHA512 验证，不依赖特定微信版本
# ---------------------------------------------------------------------------

_kernel32 = ctypes.windll.kernel32
_MEM_COMMIT = 0x1000
_READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
_PAGE_SZ = 4096
_KEY_SZ = 32
_SALT_SZ = 16


class _MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


def _read_mem(h, addr, sz):
    buf = ctypes.create_string_buffer(sz)
    n = ctypes.c_size_t(0)
    if _kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, sz, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def _enum_regions(h):
    regs = []
    addr = 0
    mbi = _MBI()
    while addr < 0x7FFFFFFFFFFF:
        if _kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == _MEM_COMMIT and mbi.Protect in _READABLE and 0 < mbi.RegionSize < 500 * 1024 * 1024:
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def _verify_key_for_db(enc_key, db_page1):
    """用 HMAC-SHA512 验证 enc_key 是否能解密这个 DB 的 page 1"""
    salt = db_page1[:_SALT_SZ]
    mac_salt = bytes(b ^ 0x3a for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=_KEY_SZ)
    hmac_data = db_page1[_SALT_SZ: _PAGE_SZ - 80 + 16]
    stored_hmac = db_page1[_PAGE_SZ - 64: _PAGE_SZ]
    h = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
    h.update(struct.pack('<I', 1))
    return h.digest() == stored_hmac


def _get_weixin_pid():
    """获取 Weixin.exe 进程 PID（取内存占用最大的）"""
    r = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True
    )
    best = (0, 0)
    for line in r.stdout.strip().split('\n'):
        if not line.strip():
            continue
        p = line.strip('"').split('","')
        if len(p) >= 5:
            pid = int(p[1])
            mem = int(p[4].replace(',', '').replace(' K', '').strip() or '0')
            if mem > best[1]:
                best = (pid, mem)
    return best[0]


def extract_keys_by_db_scan(db_dir):
    """
    版本无关的 key 提取：扫描微信进程内存中的 x'<hex>' 模式，
    匹配数据库文件的 salt 并通过 HMAC 验证。
    返回: dict { salt_hex: enc_key_hex }
    """
    # 1. 收集所有 DB 文件及其 salt
    db_files = []
    salt_to_dbs = {}
    for root, dirs, files in os.walk(db_dir):
        for f in files:
            if f.endswith('.db') and not f.endswith(('-wal', '-shm')):
                path = os.path.join(root, f)
                sz = os.path.getsize(path)
                if sz < _PAGE_SZ:
                    continue
                with open(path, 'rb') as fh:
                    page1 = fh.read(_PAGE_SZ)
                salt = page1[:_SALT_SZ].hex()
                db_files.append((path, salt, page1))
                if salt not in salt_to_dbs:
                    salt_to_dbs[salt] = []
                salt_to_dbs[salt].append(path)

    print(f'找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的 salt')

    # 2. 打开微信进程
    pid = _get_weixin_pid()
    if not pid:
        print('[ERROR] Weixin.exe 未运行，请先启动微信')
        return {}
    print(f'[+] Weixin.exe PID={pid}')

    h = _kernel32.OpenProcess(0x0010 | 0x0400, False, pid)
    if not h:
        print('[ERROR] 无法打开进程，请以管理员身份运行')
        return {}

    regions = _enum_regions(h)
    total_mb = sum(s for _, s in regions) / 1024 / 1024
    print(f'[+] 可读内存: {len(regions)} 区域, {total_mb:.0f}MB')

    # 3. 扫描内存中的 x'<hex>' 模式
    print('扫描 x\'<hex>\' 缓存密钥...')
    hex_re = re.compile(rb"x'([0-9a-fA-F]{64,192})'")
    key_map = {}
    all_hex_matches = 0
    t0 = time.time()

    for reg_idx, (base, size) in enumerate(regions):
        data = _read_mem(h, base, size)
        if not data:
            continue

        for m in hex_re.finditer(data):
            hex_str = m.group(1).decode()
            addr = base + m.start()
            all_hex_matches += 1
            hex_len = len(hex_str)

            if hex_len == 96:
                # enc_key(32bytes=64hex) + salt(16bytes=32hex)
                enc_key_hex = hex_str[:64]
                salt_hex = hex_str[64:]
                if salt_hex in salt_to_dbs and salt_hex not in key_map:
                    enc_key = bytes.fromhex(enc_key_hex)
                    for path, s, page1 in db_files:
                        if s == salt_hex:
                            if _verify_key_for_db(enc_key, page1):
                                key_map[salt_hex] = enc_key_hex
                                print(f'  [FOUND] salt={salt_hex[:16]}... key={enc_key_hex[:16]}...')
                                print(f'    数据库: {os.path.basename(path)}')
                            break

            elif hex_len == 64:
                enc_key = bytes.fromhex(hex_str)
                for path, salt_hex_db, page1 in db_files:
                    if salt_hex_db not in key_map:
                        if _verify_key_for_db(enc_key, page1):
                            key_map[salt_hex_db] = hex_str
                            print(f'  [FOUND] salt={salt_hex_db[:16]}... key={hex_str[:16]}...')
                            print(f'    数据库: {os.path.basename(path)}')
                            break

            elif hex_len > 96 and hex_len % 2 == 0:
                enc_key_hex = hex_str[:64]
                salt_hex = hex_str[-32:]
                if salt_hex in salt_to_dbs and salt_hex not in key_map:
                    enc_key = bytes.fromhex(enc_key_hex)
                    for path, s, page1 in db_files:
                        if s == salt_hex:
                            if _verify_key_for_db(enc_key, page1):
                                key_map[salt_hex] = enc_key_hex
                                print(f'  [FOUND] salt={salt_hex[:16]}... key={enc_key_hex[:16]}...')
                                print(f'    数据库: {os.path.basename(path)}')
                            break

        if (reg_idx + 1) % 200 == 0:
            elapsed = time.time() - t0
            progress = sum(s for _, s in regions[:reg_idx + 1]) / sum(s for _, s in regions) * 100
            print(f'  [{progress:.1f}%] {len(key_map)}/{len(salt_to_dbs)} salts matched, {all_hex_matches} hex patterns, {elapsed:.1f}s')

    elapsed = time.time() - t0
    print(f'扫描完成: {elapsed:.1f}s, {all_hex_matches} hex模式')
    print(f'结果: {len(key_map)}/{len(salt_to_dbs)} salts 找到密钥')

    _kernel32.CloseHandle(h)
    return key_map


def _decrypt_db_with_enckey(enc_key_hex, in_db_path, out_db_path):
    """用直接从内存提取的 enc_key 解密数据库（不跑 PBKDF2）

    enc_key 已经是派生后的 AES 密钥，直接用于 AES-256-CBC 解密。
    参数: SQLCipher 4, AES-256-CBC, HMAC-SHA512, reserve=80, page_size=4096
    完全对齐 wechat-decrypt (ylytdeng) 的解密逻辑。
    """
    import hashlib
    import struct
    import hmac as hmac_mod
    from Crypto.Cipher import AES

    SQLITE_HEADER = b"SQLite format 3\x00"
    RESERVE = 80  # IV(16) + HMAC(64)
    IV_SZ = 16
    HMAC_SZ = 64

    if not os.path.exists(in_db_path):
        return False

    file_size = os.path.getsize(in_db_path)
    total_pages = file_size // _PAGE_SZ
    if file_size % _PAGE_SZ != 0:
        total_pages += 1

    enc_key = bytes.fromhex(enc_key_hex)

    # 读取 page 1 并验证 HMAC（只在 page 1 上做验证）
    with open(in_db_path, 'rb') as fin:
        page1 = fin.read(_PAGE_SZ)

    if len(page1) < _PAGE_SZ:
        return False

    salt = page1[:_SALT_SZ]
    mac_salt = bytes(b ^ 0x3a for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=_KEY_SZ)

    # 验证 page 1 HMAC
    p1_hmac_data = page1[_SALT_SZ: _PAGE_SZ - RESERVE + IV_SZ]
    p1_stored_hmac = page1[_PAGE_SZ - HMAC_SZ: _PAGE_SZ]
    hm = hmac_mod.new(mac_key, p1_hmac_data, hashlib.sha512)
    hm.update(struct.pack('<I', 1))
    if hm.digest() != p1_stored_hmac:
        return False

    # 解密所有页面
    os.makedirs(os.path.dirname(out_db_path), exist_ok=True)
    with open(in_db_path, 'rb') as fin, open(out_db_path, 'wb') as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(_PAGE_SZ)
            if len(page) < _PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (_PAGE_SZ - len(page))
                else:
                    break

            # 全零页直接写入
            if all(b == 0 for b in page):
                fout.write(page)
                continue

            # IV 在 reserve 区域开头
            iv = page[_PAGE_SZ - RESERVE: _PAGE_SZ - RESERVE + IV_SZ]

            if pgno == 1:
                # page 1: 加密数据在 salt 之后到 reserve 之前
                encrypted = page[_SALT_SZ: _PAGE_SZ - RESERVE]
                cipher = AES.new(enc_key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted)
                # 输出: SQLite header + 解密数据 + 80字节 reserve（填零）
                fout.write(SQLITE_HEADER)
                fout.write(decrypted[len(SQLITE_HEADER) - _SALT_SZ:])
                fout.write(b'\x00' * RESERVE)
            else:
                # 其他页: 加密数据从 0 到 reserve
                encrypted = page[:_PAGE_SZ - RESERVE]
                cipher = AES.new(enc_key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted)
                # 输出: 解密数据 + 80字节 reserve（填零）
                fout.write(decrypted)
                fout.write(b'\x00' * RESERVE)

    return True


def get_version_list_path():
    """获取version_list.json的路径，支持PyInstaller打包"""
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, 'wxManager', 'decrypt', 'version_list.json')


def cmd_decrypt(args):
    """解密微信数据库 - 使用 YARA 方式（仅支持 4.0.3 及以下）"""
    print(f'开始解密 WeChat v{args.version} 数据库 (YARA 模式)...')
    print('提示: 如果 key 提取失败，请使用 decrypt-v2 命令（版本无关）')
    print(f'开始解密 WeChat v{args.version} 数据库...')

    try:
        if args.version == 4:
            wx_info_list = get_info_v4()
        else:
            version_list_path = get_version_list_path()
            if not os.path.exists(version_list_path):
                print(f'错误: 找不到 version_list.json 文件: {version_list_path}')
                return 1
            with open(version_list_path, 'r', encoding='utf-8') as f:
                version_list = json.load(f)
            wx_info_list = get_info_v3(version_list)

        if not wx_info_list:
            print('错误: 未找到正在运行的微信进程，请确保微信已启动')
            return 1

        for wx_info in wx_info_list:
            print(f'发现微信: {wx_info.nick_name} (wxid: {wx_info.wxid})')

            me = Me()
            me.wx_dir = wx_info.wx_dir
            me.wxid = wx_info.wxid
            me.name = wx_info.nick_name

            key = wx_info.key
            if not key:
                print(f'警告: 未找到 key，跳过 {wx_info.wxid}')
                continue

            output_dir = wx_info.wxid

            if args.version == 4:
                me.xor_key = get_decode_code_v4(wx_info.wx_dir)
                decrypt_v4.decrypt_db_files(key, src_dir=wx_info.wx_dir, dest_dir=output_dir)
                info_json_path = os.path.join(output_dir, 'db_storage', 'info.json')
            else:
                decrypt_v3.decrypt_db_files(key, src_dir=wx_info.wx_dir, dest_dir=output_dir)
                info_json_path = os.path.join(output_dir, 'Msg', 'info.json')

            os.makedirs(os.path.dirname(info_json_path), exist_ok=True)
            with open(info_json_path, 'w', encoding='utf-8') as f:
                json.dump(me.to_json(), f, ensure_ascii=False, indent=4)

            print(f'数据库解密成功: {output_dir}')

        print('全部完成!')
        return 0

    except Exception as e:
        print(f'解密失败: {e}')
        import traceback
        traceback.print_exc()
        return 1


def cmd_decrypt_v2(args):
    """解密微信数据库 - 版本无关模式（支持 4.0+ 包括 4.1.x）
    
    原理: WCDB 会在微信进程内存中缓存每个数据库的 raw key，
    格式为 x'<64hex_enc_key><32hex_salt>'。
    通过正则扫描内存匹配 DB 文件的 salt，并用 HMAC-SHA512 验证。
    此方法不依赖特定微信版本的内存布局。
    
    需要用户提供 db_dir 路径（微信设置 → 文件管理 中可以找到）。
    """
    db_dir = args.db_dir
    if not os.path.isdir(db_dir):
        print(f'错误: 数据库目录不存在: {db_dir}')
        print('提示: 路径可在微信设置 → 文件管理 中找到，格式如:')
        print('  D:\\xwechat_files\\wxid_xxxx\\db_storage')
        return 1

    print(f'数据库目录: {db_dir}')
    print('正在从微信进程内存提取密钥（版本无关模式）...')
    print('提示: 请确保微信正在运行，且以管理员身份运行本程序')
    print()

    try:
        key_map = extract_keys_by_db_scan(db_dir)
        if not key_map:
            print('\n未找到任何密钥。可能原因:')
            print('  1. 未以管理员身份运行')
            print('  2. 微信未在运行')
            print('  3. db_dir 路径不正确')
            return 1

        # 用找到的 key 解密所有数据库
        output_dir = args.output_dir
        os.makedirs(output_dir, exist_ok=True)

        success_count = 0
        fail_count = 0

        # 收集所有 DB 文件
        db_files = []
        for root, dirs, files in os.walk(db_dir):
            for f in files:
                if f.endswith('.db') and not f.endswith(('-wal', '-shm')):
                    path = os.path.join(root, f)
                    if os.path.getsize(path) < _PAGE_SZ:
                        continue
                    with open(path, 'rb') as fh:
                        page1 = fh.read(_PAGE_SZ)
                    salt = page1[:_SALT_SZ].hex()
                    db_files.append((path, salt, page1))

        print(f'\n开始解密 {len(db_files)} 个数据库文件...')

        for path, salt, page1 in db_files:
            if salt not in key_map:
                print(f'  跳过 (无密钥): {os.path.relpath(path, db_dir)}')
                fail_count += 1
                continue

            enc_key_hex = key_map[salt]
            rel_path = os.path.relpath(path, db_dir)
            out_path = os.path.join(output_dir, rel_path)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)

            # 直接用 enc_key 解密（不再跑 PBKDF2）
            result = _decrypt_db_with_enckey(enc_key_hex, path, out_path)
            if result:
                print(f'  OK: {rel_path}')
                success_count += 1
            else:
                print(f'  失败: {rel_path}')
                fail_count += 1

        print(f'\n解密完成: {success_count} 成功, {fail_count} 失败')
        print(f'解密文件保存在: {os.path.abspath(output_dir)}')

        # 保存 info.json
        # 尝试从 db_dir 路径提取 wxid
        dir_parts = db_dir.replace('/', '\\').split('\\')
        wxid = ''
        for part in dir_parts:
            if part.startswith('wxid_'):
                wxid = part
                break

        if wxid:
            me = Me()
            me.wxid = wxid
            me.wx_dir = os.path.dirname(db_dir)
            info_path = os.path.join(output_dir, 'info.json')
            with open(info_path, 'w', encoding='utf-8') as f:
                json.dump(me.to_json(), f, ensure_ascii=False, indent=4)

        return 0

    except Exception as e:
        print(f'解密失败: {e}')
        import traceback
        traceback.print_exc()
        return 1


def cmd_contacts(args):
    """列出所有联系人"""
    print(f'连接数据库: {args.db_dir} (v{args.db_version})')

    try:
        conn = DatabaseConnection(args.db_dir, args.db_version)
        database = conn.get_interface()

        if database is None:
            print('错误: 数据库初始化失败，请检查路径或版本是否正确')
            return 1

        contacts = database.get_contacts()
        if not contacts:
            print('未找到联系人')
            return 0

        print(f'\n共找到 {len(contacts)} 个联系人:\n')
        print(f'{"wxid":<25} {"昵称":<20} {"备注":<20}')
        print('-' * 70)

        for contact in contacts:
            wxid = contact.wxid or ''
            nickname = contact.nickname or ''
            remark = contact.remark or ''
            print(f'{wxid:<25} {nickname:<20} {remark:<20}')

            if contact.is_chatroom:
                members = database.get_chatroom_members(contact.wxid)
                print(f'  群成员: {len(members)} 人')

        print(f'\n总计: {len(contacts)} 个联系人')
        return 0

    except Exception as e:
        print(f'获取联系人失败: {e}')
        import traceback
        traceback.print_exc()
        return 1


def get_exporter_class(file_type: FileType):
    """根据FileType获取对应的Exporter类"""
    exporter_map = {
        FileType.HTML: HtmlExporter,
        FileType.TXT: TxtExporter,
        FileType.AI_TXT: AiTxtExporter,
        FileType.DOCX: DocxExporter,
        FileType.MARKDOWN: MarkdownExporter,
        FileType.XLSX: ExcelExporter,
        FileType.CSV: CSVExporter,
    }
    return exporter_map.get(file_type)


def cmd_export(args):
    """导出聊天记录"""
    print(f'导出聊天记录: wxid={args.wxid}, format={args.format}, output={args.output_dir}')

    try:
        conn = DatabaseConnection(args.db_dir, args.db_version)
        database = conn.get_interface()

        if database is None:
            print('错误: 数据库初始化失败，请检查路径或版本是否正确')
            return 1

        contact = database.get_contact_by_username(args.wxid)
        if contact is None:
            print(f'错误: 未找到联系人 {args.wxid}')
            return 1

        format_map = {
            'html': FileType.HTML,
            'txt': FileType.TXT,
            'ai_txt': FileType.AI_TXT,
            'docx': FileType.DOCX,
            'markdown': FileType.MARKDOWN,
            'xlsx': FileType.XLSX,
            'csv': FileType.CSV,
        }

        file_type = format_map.get(args.format.lower())
        if file_type is None:
            print(f'错误: 不支持的格式 {args.format}')
            print('支持的格式: html, txt, docx, csv, markdown, xlsx, ai_txt')
            return 1

        exporter_class = get_exporter_class(file_type)
        if exporter_class is None:
            print(f'错误: 不支持导出类型 {args.format}')
            return 1

        os.makedirs(args.output_dir, exist_ok=True)

        exporter = exporter_class(
            database,
            contact,
            output_dir=args.output_dir,
            type_=file_type,
            message_types=None,
            time_range=None,
            group_members=None
        )

        print(f'开始导出 {contact.remark or contact.nickname}({args.wxid}) ...')
        exporter.start()
        print('导出完成!')
        return 0

    except Exception as e:
        print(f'导出失败: {e}')
        import traceback
        traceback.print_exc()
        return 1


# ---------------------------------------------------------------------------
# 轻量级 CSV 导出（不依赖 wxManager ORM，直接查解密后的 SQLite）
# ---------------------------------------------------------------------------

# V4 消息类型 → 中文名
_MSG_TYPE_NAMES = {
    1: '文本', 3: '图片', 34: '语音', 43: '视频', 47: '表情包',
    48: '位置分享', 50: '音视频通话', 10000: '系统消息',
}


def _get_msg_type_name(local_type):
    """将 local_type 转为中文名"""
    if local_type in _MSG_TYPE_NAMES:
        return _MSG_TYPE_NAMES[local_type]
    # 49 开头的复合类型 (0x31 后缀)
    if local_type in (49, 25769803761):
        return '文件'
    # 大数类型判断
    if local_type > 10000 and (local_type & 0xFF) == 0x31:
        high = local_type >> 8
        if high == 0x500:
            return '分享链接'
        if high == 0x600:
            return '文件'
        if high == 0x7D0:
            return '转账/红包'
        if high == 0x300:
            return '音乐分享'
        if high == 0x100:
            return '链接'
        if high == 0x400:
            return '链接'
        if high == 0x4C0:
            return '链接'
        if high == 0x440:
            return '链接'
    return f'类型({local_type})'


def _extract_text_from_content(message_content, compress_content, local_type):
    """从消息原始内容中提取可读文本"""
    if not message_content:
        return ''

    content = message_content

    # 如果是 bytes，尝试解码
    if isinstance(content, bytes):
        # 检查是否是 protobuf 二进制（不可读）
        try:
            decoded = content.decode('utf-8')
            # 如果解码成功且大部分是可读字符，使用它
            printable = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t')
            if printable / max(len(decoded), 1) > 0.7:
                content = decoded
            else:
                content = '[二进制数据]'
        except (UnicodeDecodeError, ZeroDivisionError):
            try:
                content = content.decode('gbk')
            except Exception:
                content = '[二进制数据]'

    # 尝试从 compress_content 提取（XML 格式的消息）
    if (not content or content == '[二进制数据]') and compress_content:
        try:
            cc = compress_content
            if isinstance(cc, bytes):
                try:
                    cc = cc.decode('utf-8')
                except Exception:
                    try:
                        cc = cc.decode('gbk')
                    except Exception:
                        cc = ''
            if cc:
                title_m = re.search(r'<title>(.*?)</title>', cc, re.DOTALL)
                if title_m:
                    content = title_m.group(1)
                else:
                    # 截取可读部分
                    content = cc[:200]
        except Exception:
            pass

    # 截断过长内容
    if isinstance(content, str) and len(content) > 1000:
        content = content[:1000] + '...'
    return content


def _get_all_sessions(db_dir):
    """从 session.db 获取所有会话"""
    session_db = os.path.join(db_dir, 'session', 'session.db')
    if not os.path.exists(session_db):
        return []
    conn = sqlite3.connect(session_db)
    try:
        rows = conn.execute(
            "SELECT username, type, summary, last_timestamp, last_msg_type, last_sender_display_name "
            "FROM SessionTable ORDER BY sort_timestamp DESC"
        ).fetchall()
        return rows
    except Exception:
        return []
    finally:
        conn.close()


def _get_contacts(db_dir):
    """从 contact.db 获取所有联系人 {wxid: {nickname, remark, alias}}"""
    contact_db = os.path.join(db_dir, 'contact', 'contact.db')
    if not os.path.exists(contact_db):
        return {}
    conn = sqlite3.connect(contact_db)
    try:
        rows = conn.execute(
            "SELECT username, alias, remark, nick_name FROM contact "
            "WHERE (local_type=1 OR local_type=2 OR local_type=5)"
        ).fetchall()
        return {
            r[0]: {'alias': r[1] or '', 'remark': r[2] or '', 'nickname': r[3] or ''}
            for r in rows
        }
    except Exception:
        return {}
    finally:
        conn.close()


def _get_name2id_map(cursor):
    """获取 Name2Id 映射 {rowid: user_name}"""
    try:
        rows = cursor.execute("SELECT rowid, user_name FROM Name2Id").fetchall()
        return {r[0]: r[1] for r in rows}
    except Exception:
        return {}


def _export_messages_to_csv(db_dir, output_dir):
    """导出所有聊天记录到 CSV 文件

    策略: 遍历所有 message_*.db / biz_message_*.db 中的 Msg_ 表，
    用 Name2Id 的 is_session 字段反查会话 wxid（每个 Msg_ 表对应一个会话），
    然后用 wxid 关联 contact 表获取昵称/备注。
    """
    import csv
    import glob as glob_mod
    from datetime import datetime as _dt

    contacts = _get_contacts(db_dir)
    print(f'加载 {len(contacts)} 个联系人')

    # 查找所有消息数据库
    msg_dbs = []
    for pattern in ['message_*.db', 'biz_message_*.db']:
        for f in sorted(glob_mod.glob(os.path.join(db_dir, 'message', pattern))):
            msg_dbs.append(f)

    if not msg_dbs:
        print('错误: 未找到消息数据库 (message_0.db 等)')
        return False

    os.makedirs(output_dir, exist_ok=True)

    # CSV 输出列
    columns = ['wxid', '昵称', '备注', '消息ID', '类型', '发送人ID', '发送人', '时间', '内容']

    # 遍历每个消息数据库
    total_msgs = 0
    csv_count = 0

    for db_path in msg_dbs:
        db_name = os.path.basename(db_path)
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
        except Exception:
            continue

        # 获取 Name2Id 映射
        name2id = _get_name2id_map(cursor)
        if not name2id:
            conn.close()
            continue

        # 获取所有 Msg_ 表
        tables = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
        ).fetchall()

        for (table_name,) in tables:
            try:
                # 从 Name2Id 中找出 is_session=1 的记录 — 这就是该 Msg_ 表对应的会话 wxid
                # 实际上每个 Msg_ 表的消息都只属于一个会话，
                # 我们通过第一条消息的 real_sender_id 和会话关系来确定 wxid
                # 更简单的方法：Name2Id 中 is_session=1 的是会话名（wxid）
                session_names = {}
                for row in cursor.execute("SELECT rowid, user_name, is_session FROM Name2Id WHERE is_session=1").fetchall():
                    session_names[row[0]] = row[1]

                # 查询所有消息
                rows = cursor.execute(f"""
                    SELECT msg.server_id, msg.local_type, msg.real_sender_id,
                           msg.create_time, msg.message_content, msg.compress_content
                    FROM {table_name} AS msg
                    ORDER BY msg.sort_seq
                """).fetchall()
            except Exception:
                continue

            if not rows:
                continue

            # 确定会话 wxid: 从 Name2Id 的 is_session 记录中获取
            # 如果只有一个 is_session 记录，那就是它
            wxid = ''
            if len(session_names) == 1:
                wxid = list(session_names.values())[0]
            else:
                # 多个 session 时，通过表名 MD5 反查
                for _wxid, _info in contacts.items():
                    if hashlib.md5(_wxid.encode('utf-8')).hexdigest() == table_name[4:]:
                        wxid = _wxid
                        break
                if not wxid:
                    # 取第一条消息看看能否推断
                    continue

            info = contacts.get(wxid, {'nickname': '', 'remark': '', 'alias': ''})

            # 组装消息
            contact_msgs = []
            for row in rows:
                server_id, local_type, real_sender_id, create_time, \
                    message_content, compress_content = row

                # 发送人
                sender_id = name2id.get(real_sender_id, '')
                if sender_id in contacts:
                    si = contacts[sender_id]
                    sender_name = si.get('remark') or si.get('nickname') or sender_id
                else:
                    sender_name = sender_id

                # 时间
                try:
                    str_time = _dt.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    str_time = str(create_time)

                # 内容
                content = _extract_text_from_content(message_content, compress_content, local_type)
                type_name = _get_msg_type_name(local_type)

                contact_msgs.append([
                    server_id, type_name, sender_id, sender_name, str_time, content
                ])

            if contact_msgs:
                # 文件名安全处理
                display_name = info.get('remark') or info.get('nickname') or wxid
                safe_name = re.sub(r'[\\/:*?"<>|\s]', '_', display_name)
                # 限制文件名长度
                if len(safe_name) > 50:
                    safe_name = safe_name[:50]
                csv_path = os.path.join(output_dir, f'{safe_name}({wxid}).csv')

                with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    writer.writerow(columns)
                    for msg in contact_msgs:
                        writer.writerow([
                            wxid, info.get('nickname', ''), info.get('remark', '')
                        ] + msg)

                total_msgs += len(contact_msgs)
                csv_count += 1
                try:
                    print(f'  {display_name}: {len(contact_msgs)} 条消息')
                except UnicodeEncodeError:
                    print(f'  {wxid}: {len(contact_msgs)} 条消息')

        conn.close()

    print(f'\n导出完成: 共 {total_msgs} 条消息, {csv_count} 个 CSV 文件')
    print(f'输出目录: {os.path.abspath(output_dir)}')
    return True


def cmd_export_csv(args):
    """轻量级 CSV 导出 - 直接查询解密后的 SQLite，不依赖 wxManager ORM"""
    db_dir = args.db_dir
    if not os.path.isdir(db_dir):
        print(f'错误: 数据库目录不存在: {db_dir}')
        return 1

    output_dir = args.output_dir
    print(f'导出所有聊天记录到 CSV')
    print(f'数据库目录: {db_dir}')
    print(f'输出目录: {output_dir}')
    print()

    try:
        success = _export_messages_to_csv(db_dir, output_dir)
        return 0 if success else 1
    except Exception as e:
        print(f'导出失败: {e}')
        import traceback
        traceback.print_exc()
        return 1


def main():
    """主函数"""
    freeze_support()

    parser = argparse.ArgumentParser(
        description='WeChatMsg - 微信聊天记录导出工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  # 解密微信数据库 - 版本无关模式 (推荐，支持4.0/4.1.x)
  WeChatMsg.exe decrypt-v2 --db-dir "D:\\xwechat_files\\wxid_xxxx\\db_storage"

  # 批量导出所有聊天记录为CSV (推荐)
  WeChatMsg.exe export-csv --db-dir ./decrypted --output-dir ./csv_output

  # 列出联系人
  WeChatMsg.exe contacts --db-dir ./decrypted

  # 导出单个联系人聊天记录
  WeChatMsg.exe export --db-dir ./decrypted --wxid wxid_xxxx --format csv
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # decrypt子命令 (YARA模式，仅支持4.0.3及以下)
    decrypt_parser = subparsers.add_parser('decrypt', help='解密微信数据库 (YARA模式，支持4.0.3及以下)')
    decrypt_parser.add_argument(
        '--version', '-v',
        type=int,
        choices=[3, 4],
        default=4,
        help='微信版本 (3 或 4, 默认 4)'
    )

    # decrypt-v2子命令 (版本无关模式，支持4.0+包括4.1.x)
    decrypt_v2_parser = subparsers.add_parser(
        'decrypt-v2',
        help='解密微信数据库 (版本无关模式，支持4.0/4.1.x)'
    )
    decrypt_v2_parser.add_argument(
        '--db-dir', '-d',
        required=True,
        help='微信数据库目录路径 (如: D:\\xwechat_files\\wxid_xxxx\\db_storage)'
    )
    decrypt_v2_parser.add_argument(
        '--output-dir', '-o',
        default='./decrypted',
        help='解密后输出目录 (默认 ./decrypted)'
    )

    # contacts子命令
    contacts_parser = subparsers.add_parser('contacts', help='列出所有联系人')
    contacts_parser.add_argument(
        '--db-dir', '-d',
        required=True,
        help='数据库目录路径 (解密后的路径)'
    )
    contacts_parser.add_argument(
        '--db-version', '-v',
        type=int,
        choices=[3, 4],
        default=4,
        help='数据库版本 (3 或 4, 默认 4)'
    )

    # export子命令
    export_parser = subparsers.add_parser('export', help='导出聊天记录')
    export_parser.add_argument(
        '--db-dir', '-d',
        required=True,
        help='数据库目录路径'
    )
    export_parser.add_argument(
        '--db-version', '-v',
        type=int,
        choices=[3, 4],
        default=4,
        help='数据库版本 (3 或 4, 默认 4)'
    )
    export_parser.add_argument(
        '--wxid', '-w',
        required=True,
        help='联系人的wxid'
    )
    export_parser.add_argument(
        '--output-dir', '-o',
        default='./output',
        help='输出目录 (默认 ./output)'
    )
    export_parser.add_argument(
        '--format', '-f',
        choices=['html', 'txt', 'docx', 'csv', 'markdown', 'xlsx', 'ai_txt'],
        default='html',
        help='导出格式 (默认 html)'
    )

    # export-csv子命令 (轻量级，直接查SQLite)
    export_csv_parser = subparsers.add_parser(
        'export-csv',
        help='批量导出所有聊天记录为CSV (轻量级，不依赖wxManager)'
    )
    export_csv_parser.add_argument(
        '--db-dir', '-d',
        required=True,
        help='解密后的数据库目录路径'
    )
    export_csv_parser.add_argument(
        '--output-dir', '-o',
        default='./csv_output',
        help='CSV输出目录 (默认 ./csv_output)'
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == 'decrypt':
        return cmd_decrypt(args)
    elif args.command == 'decrypt-v2':
        return cmd_decrypt_v2(args)
    elif args.command == 'contacts':
        return cmd_contacts(args)
    elif args.command == 'export':
        return cmd_export(args)
    elif args.command == 'export-csv':
        return cmd_export_csv(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())