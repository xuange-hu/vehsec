"""`python -m vehsec` 与 console script 等价。

存在的理由：README 里 `pip install .` 之前 console script 还不存在，
而 `python -m vehsec` 是源码树里唯一能跑通的入口。缺这个文件时
`python -m vehsec --help` 会报 "cannot be directly executed"。
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
