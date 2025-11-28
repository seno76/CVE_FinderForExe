#!/usr/bin/env python3
"""
Быстрый запуск GUI приложения Bochka
"""

import subprocess
import sys

try:
    import PyQt5
except ImportError:
    print("❌ PyQt5 не установлен")
    print("\nУстанови PyQt5:")
    print("  pip install PyQt5")
    sys.exit(1)

# Запусти GUI
subprocess.run([sys.executable, "apps/gui_scanner.py"])
