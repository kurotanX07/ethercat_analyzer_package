#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
EtherCATパケット解析ビューア起動スクリプト
"""

import tkinter as tk
from importlib import import_module

def main():
    """メインアプリケーションを起動します"""
    try:
        # モジュールをインポート
        pcap_viewer = import_module('16_improved_filter_stats')
        
        # アプリケーションの起動
        root = tk.Tk()
        app = pcap_viewer.PCAPViewer(root)
        root.mainloop()
    except Exception as e:
        print(f"エラー: アプリケーションの起動に失敗しました。{e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()