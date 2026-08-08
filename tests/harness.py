#!/usr/bin/env python3
"""剥离 mcp 依赖的 server.py 加载 harness（回归测试共享基础设施）。

容器 mcp 包为 2.0.0，server.py 用 1.x API（mcp.server.lowlevel），直接 import 抛错。
数据层只用 stdlib（sqlite3/json/uuid/re），故剥离 mcp import 后 exec 进独立模块测试。

关键坑（详见 skill references/test-harness.md）：
1. Python 3.13 函数注解在定义时立即求值 → `-> list[Tool]` 模块加载即 NameError
   → 必须在 exec 前注入 Tool/TextContent stub 桩类（能接收 kwargs，供 list_tools/call_tool 用）
2. DB_DIR 在模块加载时固定（Path(os.environ.get("FINDINGS_DB_DIR", ...))）
   → 每个测试必须先 make_test_dir() 设置环境变量，再 load_server()
3. DB_DIR.mkdir() 在模块加载时执行 → 测试目录必须在 exec 之前建好
"""

import os
import re
import shutil
import tempfile
import types
import unittest

# 仓库根 = tests/ 的上一级
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SERVER_PATH = os.path.join(_REPO_ROOT, "server.py")

# 需要剥离的行（MCP 1.x 依赖 + 装饰器）
_STRIP_PATTERNS = [
    r"^from mcp\.server\.lowlevel import Server\s*\n",
    r"^from mcp\.types import Tool, TextContent\s*\n",
    r"^from mcp\.server\.stdio import stdio_server\s*\n",
    r"^server = Server\(\"findings-mcp\"\)\s*\n",
    r"^@server\.list_tools\(\)\s*\n",
    r"^@server\.call_tool\(\)\s*\n",
]

# 桩类：能接收 kwargs（object() 构造不了 → 调 list_tools 时 Tool(name=...) 抛 TypeError）
_STUB_SRC = '''
class Tool:
    def __init__(self, *args, **kwargs):
        self.name = kwargs.get("name", args[0] if args else None)
        self.description = kwargs.get("description", "")
        self.inputSchema = kwargs.get("inputSchema", {})

class TextContent:
    def __init__(self, *args, **kwargs):
        self.text = kwargs.get("text", "")
'''


def load_server():
    """读取 server.py，剥离 mcp import/装饰器后 exec 进独立模块，返回模块 namespace。

    要求调用方已设置 os.environ["FINDINGS_DB_DIR"]（server.py 模块加载时固定 DB_DIR）。
    """
    src = open(_SERVER_PATH, encoding="utf-8").read()
    for pat in _STRIP_PATTERNS:
        src = re.sub(pat, "", src, flags=re.M)
    mod = types.ModuleType("server_stripped")
    exec(compile(_STUB_SRC + src, "server.py", "exec"), mod.__dict__)
    return mod


def make_test_dir(prefix="kmcp_test_"):
    """创建隔离测试目录并设置 FINDINGS_DB_DIR 环境变量，返回目录路径。

    server.py 模块加载时执行 DB_DIR.mkdir()；目录必须在此（exec 前）建好，
    否则 exec 后 rmtree 会把刚建的目录删掉 → sqlite3.connect 报
    "unable to open database file"。
    """
    d = tempfile.mkdtemp(prefix=prefix)
    os.environ["FINDINGS_DB_DIR"] = d
    return d


def wipe_dir(path):
    """删除整个测试目录（用于测试间清理）。"""
    shutil.rmtree(path, ignore_errors=True)


class HarnessTestCase(unittest.TestCase):
    """共享测试基类：每个测试方法独立隔离 FINDINGS_DB_DIR + 加载剥离模块。

    setUp 创建全新临时目录并设置环境变量、exec server.py；tearDown 清理目录，
    保证测试可重复运行且互不干扰。
    """

    def setUp(self):
        self.tmp = make_test_dir()
        self.mod = load_server()

    def tearDown(self):
        wipe_dir(self.tmp)
