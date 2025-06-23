import os
import pandas as pd
import pyshark
import re
import struct
import binascii
import tkinter as tk
import json
from tkinter import Tk, filedialog, ttk, Frame, Button, Label, Scrollbar, VERTICAL, HORIZONTAL, RIGHT, BOTTOM, X, Y, END, Text, WORD, DISABLED, NORMAL, StringVar, Entry, Checkbutton, IntVar, LabelFrame, colorchooser
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class PCAPViewer:

    def __init__(self, root):
        self.root = root
        self.root.title("EtherCATパケット解析ビューア")
        self.root.geometry("1600x900")

        # データ保存用
        self.all_data = []
        self.filtered_data = [] # フィルタリング後のデータ
        self.is_filtered = False # フィルタリング状態フラグ
        self.is_ethernet_filtered = False # EtherCATフィルタリング状態フラグ
        self.is_basic_filtered = False # 基本フィルタリング状態フラグ
        self.pcap_file = None

        # 変数の初期化
        self.advanced_filter_var = StringVar()
        self.enable_prefilter = IntVar()
        self.enable_prefilter.set(0)

        # カラムとフィールドの定義を先に行う
        self.columns = ['No', 'Time', 'Timestamp', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'TimeDiff', 'TSDiff', 'ET2000']
        self.conditions = ['含む', '等しい', '以上', '以下', 'より大きい', 'より小さい', '開始する', '修了する', '一致する(正規表現)']
        self.ethercat_fields = ['Cmd', 'Index', 'ADP', 'ADO', 'LogAddr', 'Length_hex', 'LastIndicator', 'RoundTrip', 'Reserved', 'DataLength_dec', 'Interrupt', 'Data', 'WorkingCnt']

        # 事前フィルタに使用可能なフィールド定義
        self.prefilter_available_fields = [
            # 基本フィールド
            {"display": "No", "value": "frame.number"},
            {"display": "Time", "value": "frame.time"},
            {"display": "Source", "value": "eth.src"},
            {"display": "Destination", "value": "eth.dst"},
            {"display": "Protocol", "value": "eth.type"},
            {"display": "Length", "value": "frame.len"},
            {"display": "Info", "value": "frame.info"},
            # EtherCATフィールド
            {"display": "Cmd", "value": "ecat.cmd"},
            {"display": "Index", "value": "ecat.idx"},
            {"display": "ADP", "value": "ecat.adp"},
            {"display": "ADO", "value": "ecat.ado"},
            {"display": "LogAddr", "value": "ecat.logaddr"},
            {"display": "Data", "value": "ecat.data"},
            {"display": "WorkingCnt", "value": "ecat.wkc"}
        ]

        # 後処理フィルタに使用可能なフィールド定義
        self.postfilter_available_fields = [
            # 基本フィールド
            {"display": "No", "field": "No"},
            {"display": "Time", "field": "Time"},
            {"display": "Source", "field": "Source"},
            {"display": "Destination", "field": "Destination"},
            {"display": "Protocol", "field": "Protocol"},
            {"display": "Length", "field": "Length"},
            {"display": "Info", "field": "Info"},
            {"display": "時間差", "field": "TimeDiff"},
            {"display": "TS差", "field": "TSDiff"},
            # EtherCATフィールド
            {"display": "Cmd", "field": "EtherCAT.Cmd"},
            {"display": "Index", "field": "EtherCAT.Index"},
            {"display": "ADP", "field": "EtherCAT.ADP"},
            {"display": "ADO", "field": "EtherCAT.ADO"},
            {"display": "LogAddr", "field": "EtherCAT.LogAddr"},
            {"display": "Data", "field": "EtherCAT.Data"},
            {"display": "WorkingCnt", "field": "EtherCAT.WorkingCnt"},
            {"display": "ET2000 Timestamp", "field": "ET2000_Timestamp"}
        ]

        # ハイライト設定
        self.highlighted_values = {} # {カラム名: {値: 色}} の形式で保存
        self._defined_tree_tags = set()
        self._cell_highlights = [] # [(canvas, item, column), ...]
        self.default_highlight_color = "#00FF00" # 緑色

        # 事前フィルタ行リスト
        self.prefilter_rows = []
        self.prefilter_ethercat_rows = []
        
        # 後処理フィルタ行リスト
        self.postfilter_rows = []

        # EtherCAT Cmdの解説
        self.ethercat_cmd_dict = {
            "01": "LRW (Logical Read Write)",
            "02": "LRD (Logical Read)",
            "03": "LWR (Logical Write)",
            "04": "BRD (Broadcast Read)",
            "05": "BWR (Broadcast Write)",
            "07": "ARMW (Auto Increment Read Multiple Write)",
            "08": "APRD (Auto Increment Physical Read)",
            "09": "APWR (Auto Increment Physical Write)",
            "0a": "APRW (Auto Increment Physical Read Write)",
            "0c": "FPRD (Fixed Address Physical Read)",
            "0d": "FPWR (Fixed Address Physical Write)",
            "0e": "FPRW (Fixed Address Physical Read Write)"
        }

        # メインフレーム
        self.main_frame = Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # ボタンフレーム
        self.btn_frame = Frame(self.main_frame)
        self.btn_frame.pack(fill=X, pady=5)

        # ファイル選択ボタン
        self.select_btn = Button(self.btn_frame, text="PCAPNGファイルを選択", command=self.select_file)
        self.select_btn.pack(side=tk.LEFT, padx=5)

        # CSVエクスポートボタン
        self.export_btn = Button(self.btn_frame, text="CSVにエクスポート", command=self.export_to_csv)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        self.export_btn.config(state=tk.DISABLED) # 初期状態では無効

        # Excelエクスポートボタン
        self.export_excel_btn = Button(self.btn_frame, text="Excelにエクスポート", command=self.export_to_excel)
        self.export_excel_btn.pack(side=tk.LEFT, padx=5)
        self.export_excel_btn.config(state=tk.DISABLED) # 初期状態では無効

        # フィルタ設定保存ボタン
        self.save_filter_defaults_btn = Button(self.btn_frame, text="フィルタ設定を保存", command=self.save_filter_defaults)
        self.save_filter_defaults_btn.pack(side=tk.LEFT, padx=5)

        # ファイル情報フレーム
        self.file_info_frame = Frame(self.main_frame)
        self.file_info_frame.pack(fill=X, pady=5)

        # ファイル名表示ラベル
        self.file_label = Label(self.file_info_frame, text="ファイルが選択されていません")
        self.file_label.pack(side=tk.LEFT, pady=5, padx=(0, 20))

        # 特定条件のスループット情報表示ラベル
        self.throughput_label = Label(self.file_info_frame, text="")
        self.throughput_label.pack(side=tk.LEFT, pady=5)

        # --- 事前フィルタリングセクション --- #
        self.prefilter_frame = LabelFrame(self.main_frame, text="事前フィルタリング（ファイル読み込み時に適用）", font=("Arial", 10, "bold"))
        self.prefilter_frame.pack(fill=X, pady=5)

        # 事前フィルタリングの有効/無効
        self.prefilter_check = Checkbutton(self.prefilter_frame, text="事前フィルタリングを有効にする", variable=self.enable_prefilter)
        self.prefilter_check.pack(anchor=tk.W, padx=5)

        # 事前フィルタリングUIコントロール
        self.prefilter_controls = Frame(self.prefilter_frame)
        self.prefilter_controls.pack(fill=X, padx=5, pady=5)

        # 事前フィルタの条件選択フレーム
        self.prefilter_container = Frame(self.prefilter_controls)
        self.prefilter_container.pack(fill=X, pady=2)

        # 最初の事前フィルタ行
        self.create_prefilter_row(self.prefilter_container, 0)

        # 事前フィルタ行を追加するボタン
        self.add_prefilter_btn = Button(self.prefilter_controls, text="事前フィルタ条件を追加", command=self.add_prefilter_row)
        self.add_prefilter_btn.pack(anchor=tk.W, pady=5)

        # Wiresharkフィルタ式の直接入力
        prefilter_advanced_frame = Frame(self.prefilter_controls)
        prefilter_advanced_frame.pack(fill=X, pady=5)

        Label(prefilter_advanced_frame, text="高度なフィルタ式:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.advanced_filter_entry = Entry(prefilter_advanced_frame, textvariable=self.advanced_filter_var, width=60)
        self.advanced_filter_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E)

        # 高度なフィルタ式の説明
        hint_label = Label(prefilter_advanced_frame, text="Wireshark形式のフィルタ式を入力（例: ecat and !(eth.src == 00:00:00:00:00:00)）")
        hint_label.grid(row=1, column=1, padx=5, pady=0, sticky=tk.W)

        # 事前フィルタのプレビューラベル
        self.prefilter_preview = Label(self.prefilter_frame, text="フィルタ式: ecat", anchor=tk.W)
        self.prefilter_preview.pack(fill=X, padx=10, pady=5, anchor=tk.W)

        # --- 後処理フィルタリングセクション --- #
        self.postfilter_frame = LabelFrame(self.main_frame, text="後処理フィルタリング（表示データに適用）", font=("Arial", 10, "bold"))
        self.postfilter_frame.pack(fill=X, pady=5)

        # 後処理フィルタリングUIコントロール
        self.postfilter_controls = Frame(self.postfilter_frame)
        self.postfilter_controls.pack(fill=X, padx=5, pady=5)

        # 後処理フィルタの条件選択フレーム
        self.postfilter_container = Frame(self.postfilter_controls)
        self.postfilter_container.pack(fill=X, pady=2)

        # 最初の後処理フィルタ行
        self.create_postfilter_row(self.postfilter_container, 0)

        # 後処理フィルタ行を追加するボタン
        self.add_postfilter_btn = Button(self.postfilter_controls, text="後処理フィルタ条件を追加", command=self.add_postfilter_row)
        self.add_postfilter_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # フィルタを適用するボタン
        self.apply_filter_btn = Button(self.postfilter_controls, text="フィルタを適用", command=self.apply_postfilter)
        self.apply_filter_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # フィルタをリセットするボタン
        self.reset_filter_btn = Button(self.postfilter_controls, text="フィルタをリセット", command=self.reset_postfilter)
        self.reset_filter_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # 水平分割用のPanedWindow
        self.paned_window = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        # 左側：データ一覧のフレーム
        self.table_frame = Frame(self.paned_window)
        self.paned_window.add(self.table_frame, weight=3)

        # 右側：パケット詳細表示用フレーム
        self.detail_frame = Frame(self.paned_window)
        self.paned_window.add(self.detail_frame, weight=3)

        # 詳細表示用のNotebook（タブ付きパネル）
        self.detail_notebook = ttk.Notebook(self.detail_frame)
        self.detail_notebook.pack(fill=tk.BOTH, expand=True)

        # 基本情報タブ
        self.basic_frame = Frame(self.detail_notebook)
        self.detail_notebook.add(self.basic_frame, text="基本情報")

        # 基本情報のテキストエリア
        self.basic_text = Text(self.basic_frame, wrap=WORD)
        self.basic_text.pack(fill=tk.BOTH, expand=True)
        self.basic_text.config(state=DISABLED)

        # EtherCAT情報タブ
        self.ethercat_frame = Frame(self.detail_notebook)
        self.detail_notebook.add(self.ethercat_frame, text="EtherCAT情報")

        # EtherCAT情報のテキストエリア
        self.ethercat_text = Text(self.ethercat_frame, wrap=WORD)
        self.ethercat_text.pack(fill=tk.BOTH, expand=True)
        self.ethercat_text.config(state=DISABLED)

        # 16進データタブ
        self.hex_frame = Frame(self.detail_notebook)
        self.detail_notebook.add(self.hex_frame, text="16進データ")

        # 16進データのテキストエリア
        self.hex_text = Text(self.hex_frame, wrap=WORD)
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        self.hex_text.config(state=DISABLED)

        # ツリービューとスクロールバー
        self.tree_frame = Frame(self.table_frame)
        self.tree_frame.pack(fill=tk.BOTH, expand=True)

        # 垂直スクロールバー
        tree_vsb = Scrollbar(self.tree_frame, orient=VERTICAL)
        tree_vsb.pack(side=RIGHT, fill=Y)

        # 水平スクロールバー
        tree_hsb = Scrollbar(self.tree_frame, orient=HORIZONTAL)
        tree_hsb.pack(side=BOTTOM, fill=X)

        # ツリービュー
        self.tree = ttk.Treeview(self.tree_frame, columns=self.columns, show='headings', yscrollcommand=tree_vsb.set, xscrollcommand=tree_hsb.set)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # スクロールバーとツリービューの関連付け
        tree_vsb.config(command=self.tree.yview)
        tree_hsb.config(command=self.tree.xview)

        # カラムの設定
        self.tree.column('No', width=60, anchor=tk.CENTER)
        self.tree.column('Time', width=180, anchor=tk.W)
        self.tree.column('Timestamp', width=100, anchor=tk.W)
        self.tree.column('Source', width=130, anchor=tk.W)
        self.tree.column('Destination', width=130, anchor=tk.W)
        self.tree.column('Protocol', width=100, anchor=tk.W)
        self.tree.column('Length', width=60, anchor=tk.CENTER)
        self.tree.column('Info', width=300, anchor=tk.W)
        self.tree.column('TimeDiff', width=80, anchor=tk.CENTER)
        self.tree.column('TSDiff', width=80, anchor=tk.CENTER)
        self.tree.column('ET2000', width=100, anchor=tk.CENTER)  # ET2000タイムスタンプ列を追加

        # カラムヘッダーの設定
        self.tree.heading('#0', text='', anchor=tk.CENTER)
        self.tree.heading('No', text='No', anchor=tk.CENTER)
        self.tree.heading('Time', text='時間', anchor=tk.CENTER)
        self.tree.heading('Timestamp', text='タイムスタンプ', anchor=tk.CENTER)
        self.tree.heading('Source', text='送信元', anchor=tk.CENTER)
        self.tree.heading('Destination', text='宛先', anchor=tk.CENTER)
        self.tree.heading('Protocol', text='プロトコル', anchor=tk.CENTER)
        self.tree.heading('Length', text='長さ', anchor=tk.CENTER)
        self.tree.heading('Info', text='情報', anchor=tk.CENTER)
        self.tree.heading('TimeDiff', text='時間差(ms)', anchor=tk.CENTER)
        self.tree.heading('TSDiff', text='TS差(ms)', anchor=tk.CENTER)
        self.tree.heading('ET2000', text='ET2000 TS', anchor=tk.CENTER)  # ET2000タイムスタンプヘッダーを追加

        # 全てのUIコンポーネント設定後に、イベントハンドラを設定
        self.setup_event_handlers()

    def setup_event_handlers(self):
        """イベントハンドラの設定"""
        # フィールド選択時のヒント更新
        self.update_filter_hints()

        # フィルタ変更時のイベントハンドラを設定
        self.advanced_filter_var.trace_add("write", self.update_filter_preview)
        self.enable_prefilter.trace_add("write", self.update_filter_preview)
        
        # 最初のフィルタプレビュー更新
        self.update_filter_preview()
        
        # 選択イベントのバインド
        self.tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # ステータスバー
        self.status_bar = Label(self.root, text="準備完了", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=X)

    def select_file(self):
        """PCAPNGファイルを選択するダイアログを表示"""
        self.pcap_file = filedialog.askopenfilename(filetypes=[("PCAPNG files", "*.pcapng")])
        if not self.pcap_file:
            self.status_bar.config(text="ファイルが選択されませんでした。")
            return
        self.file_label.config(text=f"選択されたファイル: {os.path.basename(self.pcap_file)}")
        self.status_bar.config(text="ファイルを読み込んでいます...")
        self.root.update() # UIを更新
        try:
            self.process_pcap_file()
            self.export_btn.config(state=tk.NORMAL) # CSVエクスポートボタンを有効化
            self.export_excel_btn.config(state=tk.NORMAL) # Excelエクスポートボタンを有効化
        except Exception as e:
            self.status_bar.config(text=f"エラー: {str(e)}")
            print(f"例外の詳細: {e}") # デバッグ用

    def create_prefilter_row(self, parent, row_idx):
        """事前フィルタ行を作成"""
        filter_frame = Frame(parent)
        filter_frame.pack(fill=X, pady=2)

        # フィールド選択
        field_var = StringVar()
        field_options = [field['display'] for field in self.prefilter_available_fields]
        field_dropdown = ttk.Combobox(filter_frame, textvariable=field_var, values=field_options, width=15)
        field_dropdown.grid(row=0, column=0, padx=5, pady=2)
        field_dropdown.current(0)  # 最初の要素を選択

        # 条件選択
        condition_var = StringVar()
        condition_dropdown = ttk.Combobox(filter_frame, textvariable=condition_var, values=self.conditions, width=10)
        condition_dropdown.grid(row=0, column=1, padx=5, pady=2)
        condition_dropdown.current(0)  # 最初の要素を選択

        # 値入力
        value_var = StringVar()
        value_entry = Entry(filter_frame, textvariable=value_var, width=25)
        value_entry.grid(row=0, column=2, padx=5, pady=2)

        # AND/OR選択
        logic_var = StringVar()
        logic_var.set("AND")
        logic_dropdown = ttk.Combobox(filter_frame, textvariable=logic_var, values=["AND", "OR"], width=5)
        logic_dropdown.grid(row=0, column=3, padx=5, pady=2)

        # 行削除ボタン
        remove_btn = Button(filter_frame, text="削除", 
                           command=lambda: self.remove_prefilter_row(filter_frame, self.prefilter_rows, row_idx))
        remove_btn.grid(row=0, column=4, padx=5, pady=2)

        # フィルタ情報を辞書に格納
        filter_info = {
            'frame': filter_frame,
            'field_var': field_var,
            'condition_var': condition_var,
            'value_var': value_var,
            'logic_var': logic_var,
            'remove_btn': remove_btn
        }

        # 最初の行の場合、ヒントラベルを追加
        if row_idx == 0:
            hint_label = Label(filter_frame, text="例: 「Protocol」フィールドで「0x88a4 (EtherCAT)」を含む", font=("Arial", 8))
            hint_label.grid(row=1, column=0, columnspan=5, padx=5, pady=0, sticky=tk.W)
            filter_info['hint_label'] = hint_label

            # ヒント更新のためにドロップダウンの選択変更イベントをバインド
            field_dropdown.bind('<<ComboboxSelected>>', self.update_prefilter_hint)

        # フィルタ行リストに追加
        if row_idx < len(self.prefilter_rows):
            self.prefilter_rows.insert(row_idx, filter_info)
        else:
            self.prefilter_rows.append(filter_info)

        # この関数では直接update_filter_previewを呼び出さない
        return filter_info

    # その他必要なメソッドを追加
    def add_prefilter_row(self):
        """事前フィルタ行を追加"""
        self.create_prefilter_row(self.prefilter_container, len(self.prefilter_rows))
    
    def remove_prefilter_row(self, frame, filter_rows, idx):
        """事前フィルタ行を削除"""
        if len(filter_rows) <= 1:
            return  # 最低1行は残す

        # フレームを削除
        frame.destroy()

        # リストから削除
        if idx < len(filter_rows):
            filter_rows.pop(idx)

        # インデックスを更新
        for i in range(idx, len(filter_rows)):
            filter_rows[i]['remove_btn'].config(
                command=lambda i=i: self.remove_prefilter_row(filter_rows[i]['frame'], filter_rows, i))

        # フィルタプレビューを更新
        self.update_filter_preview()
        
    def update_filter_hints(self):
        """フィルタ行のヒントを更新するトリガー"""
        pass
        
    def update_prefilter_hint(self, event):
        """事前フィルタのヒントを更新"""
        if hasattr(event, 'widget'):
            combobox = event.widget
            field_display = combobox.get()
            
            # 親フレームを特定
            parent_frame = combobox.master
            
            # このフレームに関連するフィルタ情報を検索
            for filter_info in self.prefilter_rows:
                if filter_info['frame'] == parent_frame and 'hint_label' in filter_info:
                    hint_label = filter_info['hint_label']
                    
                    # ヒントテキストを生成
                    hint_text = "例: "
                    
                    if field_display == "Protocol":
                        hint_text += "「Protocol」フィールドで「0x88a4 (EtherCAT)」を含む"
                    elif field_display == "Source":
                        hint_text += "「Source」フィールドで「00:11:22:33:44:55」を含む"
                    elif field_display == "Cmd":
                        hint_text += "「Cmd」フィールドで「01」や「0x01」、「LRW」を含む"
                    else:
                        hint_text += f"「{field_display}」フィールドで適切な値を入力"
                    
                    hint_label.config(text=hint_text)
                    break
        
        # フィルタプレビューを更新
        self.update_filter_preview()
    
    def update_filter_preview(self, *args):
        """フィルタプレビューを更新"""
        preview_text = f"フィルタ式: {self.build_display_filter()}"
        self.prefilter_preview.config(text=preview_text)
    
    def build_display_filter(self):
        """Wiresharkの表示フィルタを構築"""
        if self.advanced_filter_var.get().strip():
            # 高度なフィルタが入力されている場合はそちらを優先
            return self.advanced_filter_var.get().strip()
        
        # 基本フィルタ式の構築
        filters = []
        
        for idx, filter_info in enumerate(self.prefilter_rows):
            field_display = filter_info['field_var'].get()
            condition = filter_info['condition_var'].get()
            value = filter_info['value_var'].get().strip()
            
            if not value:  # 値が空の場合はスキップ
                continue
            
            # 表示名からフィールド値を取得
            field_value = None
            for field in self.prefilter_available_fields:
                if field['display'] == field_display:
                    field_value = field['value']
                    break
            
            if field_value:
                # 条件に応じたフィルタ式を生成
                filter_expr = ""
                
                if condition == "含む":
                    filter_expr = f"{field_value} contains {value}"
                elif condition == "等しい":
                    filter_expr = f"{field_value} == {value}"
                elif condition == "以上":
                    filter_expr = f"{field_value} >= {value}"
                elif condition == "以下":
                    filter_expr = f"{field_value} <= {value}"
                elif condition == "より大きい":
                    filter_expr = f"{field_value} > {value}"
                elif condition == "より小さい":
                    filter_expr = f"{field_value} < {value}"
                elif condition == "開始する":
                    filter_expr = f"{field_value} matches \"^{value}\""
                elif condition == "修了する":
                    filter_expr = f"{field_value} matches \"{value}$\""
                elif condition == "一致する(正規表現)":
                    filter_expr = f"{field_value} matches \"{value}\""
                
                if filter_expr:
                    filters.append(filter_expr)
        
        # フィルタが空の場合はデフォルトでecatを使用
        if not filters:
            return "ecat"
        
        # 最初のフィルタ
        result = filters[0]
        
        # 2つ目以降のフィルタを論理演算子で結合
        for idx in range(1, len(filters)):
            logic = self.prefilter_rows[idx-1]['logic_var'].get().lower()
            result = f"({result}) {logic} ({filters[idx]})"
        
        return result
    
    def export_to_csv(self):
        """表示されているデータをCSVファイルにエクスポート"""
        if not self.all_data:
            self.status_bar.config(text="エクスポートするデータがありません。")
            return
        
        csv_file = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialdir=os.path.dirname(self.pcap_file) if self.pcap_file else "/"
        )
        
        if not csv_file:
            return
        
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = pd.DataFrame(self.filtered_data if self.is_filtered else self.all_data)
                writer.to_csv(f, index=False)
            
            self.status_bar.config(text=f"データがCSVファイルに正常にエクスポートされました: {csv_file}")
        except Exception as e:
            self.status_bar.config(text=f"CSVエクスポートエラー: {str(e)}")
    
    def export_to_excel(self):
        """表示されているデータをExcelファイルにエクスポート"""
        if not self.all_data:
            self.status_bar.config(text="エクスポートするデータがありません。")
            return
        
        excel_file = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
            initialdir=os.path.dirname(self.pcap_file) if self.pcap_file else "/"
        )
        
        if not excel_file:
            return
        
        try:
            # データをDataFrameに変換
            df = pd.DataFrame(self.filtered_data if self.is_filtered else self.all_data)
            
            # EtherCATの詳細情報を除外（複雑なネストされた辞書のため）
            if 'EtherCAT' in df.columns:
                df = df.drop('EtherCAT', axis=1)
            if 'filtered_datagrams' in df.columns:
                df = df.drop('filtered_datagrams', axis=1)
                
            # Excelに出力
            df.to_excel(excel_file, index=False)
            
            self.status_bar.config(text=f"データがExcelファイルに正常にエクスポートされました: {excel_file}")
        except Exception as e:
            self.status_bar.config(text=f"Excelエクスポートエラー: {str(e)}")

    def process_pcap_file(self):
        """選択されたPCAPNGファイルを処理してデータを抽出"""
        # 既存のTreeviewデータをクリア
        for i in self.tree.get_children():
            self.tree.delete(i)

        # 詳細テキストをクリア
        self.basic_text.config(state=NORMAL)
        self.basic_text.delete(1.0, END)
        self.basic_text.config(state=DISABLED)
        self.ethercat_text.config(state=NORMAL)
        self.ethercat_text.delete(1.0, END)
        self.ethercat_text.config(state=DISABLED)
        self.hex_text.config(state=NORMAL)
        self.hex_text.delete(1.0, END)
        self.hex_text.config(state=DISABLED)

        # 事前フィルタリングの設定
        display_filter = None
        if self.enable_prefilter.get() == 1:
            display_filter = self.build_display_filter()
            self.status_bar.config(text=f"フィルタ '{display_filter}' を適用してファイルを読み込んでいます...")
            self.root.update()

        # PCAPNGファイルを読み込む（事前フィルタリングあり/なし）
        try:
            if display_filter:
                cap = pyshark.FileCapture(self.pcap_file, display_filter=display_filter, use_json=True, include_raw=True)
            else:
                cap = pyshark.FileCapture(self.pcap_file, use_json=True, include_raw=True)
        except Exception as e:
            self.status_bar.config(text=f"ファイル読み込みエラー: {str(e)}")
            return

        # データを格納するリスト
        self.all_data = []
        self.filtered_data = []
        self.is_filtered = False
        self.is_ethercat_filtered = False
        self.is_basic_filtered = False
        previous_time = None
        previous_ts = None
        previous_et2000_ts = None  # ET2000タイムスタンプ用の変数を追加
        packet_count = 0

        # スループット計算用の特定フィルタデータ
        specific_filter_data = {
            'packets': [],
            'total_bytes': 0,
            'start_time': None,
            'end_time': None
        }

        # 処理状況を更新
        self.status_bar.config(text="パケットを処理中...")
        self.root.update()

        # .pcapngファイルのデータを取得し、要素別にデータ列を作る
        for packet in cap:
            if hasattr(packet, 'eth'):
                # 特定フィルタ条件に一致するか確認
                is_specific_condition = False
                if hasattr(packet, 'eth') and hasattr(packet, 'ecat'):
                    eth_addr = packet.eth.src if hasattr(packet.eth, 'src') else ""
                    eth_addr_dst = packet.eth.dst if hasattr(packet.eth, 'dst') else ""
                    ecat_cmd = packet.ecat.cmd if hasattr(packet.ecat, 'cmd') else ""
                    
                    # フィルタ条件: ((eth.addr == 02:10:b6:18:35:30) && !(ecat.cnd == 0x04)) && !(ecat.cmd == 0x05)
                    # 02以降の値はデータによって変更があるため、先頭が02のMACアドレスに一致するように変更
                    eth_addr_match = eth_addr.startswith("02:") or eth_addr_dst.startswith("02:")
                    ecat_cmd_not_04 = (ecat_cmd != "0x04" and ecat_cmd != "04")
                    ecat_cmd_not_05 = (ecat_cmd != "0x05" and ecat_cmd != "05")
                    
                    if eth_addr_match and ecat_cmd_not_04 and ecat_cmd_not_05:
                        is_specific_condition = True
                        packet_length = int(packet.length) if hasattr(packet, 'length') else 0
                        specific_filter_data['total_bytes'] += packet_length
                        
                        # 時間情報を記録
                        current_time = packet.sniff_time if hasattr(packet, 'sniff_time') else None
                        if current_time:
                            if specific_filter_data['start_time'] is None or current_time < specific_filter_data['start_time']:
                                specific_filter_data['start_time'] = current_time
                            if specific_filter_data['end_time'] is None or current_time > specific_filter_data['end_time']:
                                specific_filter_data['end_time'] = current_time
                        
                        specific_filter_data['packets'].append({
                            'length': packet_length,
                            'time': current_time
                        })

                # packetがecat属性を持っているか確認
                if hasattr(packet, 'ecat'):
                    ecat_layer = packet.ecat
                    # ecat属性の中にEtherCat_Diagramが存在するか確認
                    if hasattr(ecat_layer, 'ethercat_datagram'):
                        try:
                            ecat_layer = packet.ecat
                            current_time = packet.sniff_time
                            current_ts = current_time.timestamp()

                            # 時間差の計算
                            time_diff = None
                            ts_diff = None
                            if previous_time:
                                time_diff = (current_time - previous_time).total_seconds() * 1000  # ミリ秒に変換
                                # 旧計算方法はコメントアウト
                                # ts_diff = (current_ts - previous_ts) * 1000  # ミリ秒に変換
                            previous_time = current_time
                            previous_ts = current_ts

                            # プロトコルタイプの判定
                            protocol_type = 'ECAT(0x88a4)' if packet.eth.type == '0x88a4' else packet.eth.type

                            # Wiresharkスタイルの情報フィールドを生成
                            info_field = self.extract_wireshark_info(packet)
                            raw_data = packet.get_raw_packet()
                            formatted_data = ' '.join(f'{byte:02x}' for byte in raw_data)
                            formatted_data2 = formatted_data.replace(" ", "")

                            # EtherCATデータ解析
                            ethercat_data = self.parse_ethercat_data(formatted_data2)
                            
                            # ET2000タイムスタンプを抽出
                            et2000_timestamp = None
                            et2000_timestamp_detail = None
                            
                            if ethercat_data:
                                if 'ET2000_Timestamp' in ethercat_data:
                                    et2000_timestamp = ethercat_data['ET2000_Timestamp']
                                if 'ET2000_Timestamp_Detail' in ethercat_data:
                                    et2000_timestamp_detail = ethercat_data['ET2000_Timestamp_Detail']

                            # ET2000タイムスタンプを使用してTS差を計算
                            if et2000_timestamp is not None and previous_et2000_ts is not None:
                                ts_diff = (et2000_timestamp - previous_et2000_ts) / 1000  # ミリ秒に変換（ET2000はマイクロ秒単位）
                            previous_et2000_ts = et2000_timestamp

                            # パケット情報を保存
                            packet_info = {
                                'No': packet.number,
                                'Time': str(packet.sniff_time), # 文字列に変換して保存
                                'Timestamp': current_ts,
                                'Source': packet.eth.src,
                                'Destination': packet.eth.dst,
                                'Protocol': protocol_type,
                                'Length': packet.length,
                                'Info': info_field,
                                'TimeDiff': time_diff,
                                'TSDiff': ts_diff,
                                'Formatted_Data2': formatted_data2,
                                'EtherCAT': ethercat_data,
                                'ET2000_Timestamp': et2000_timestamp,
                                'ET2000_Timestamp_Detail': et2000_timestamp_detail,
                                'filtered_datagrams': []  # フィルタに一致したデータグラムのインデックスを格納
                            }
                            self.all_data.append(packet_info)
                            packet_count += 1
                        except Exception as e:
                            print(f"パケット処理エラー: {e}")

        # 特定条件のスループット情報を計算して表示
        if specific_filter_data['packets']:
            start_time = specific_filter_data['start_time']
            end_time = specific_filter_data['end_time']
            
            if start_time and end_time and start_time != end_time:
                duration_seconds = (end_time - start_time).total_seconds()
                if duration_seconds > 0:
                    avg_bytes_per_sec = specific_filter_data['total_bytes'] / duration_seconds
                    avg_bits_per_sec = avg_bytes_per_sec * 8
                    
                    # 単位を適切に調整
                    if avg_bits_per_sec >= 1000000:
                        avg_bits_display = f"{avg_bits_per_sec/1000000:.2f} Mbps"
                    elif avg_bits_per_sec >= 1000:
                        avg_bits_display = f"{avg_bits_per_sec/1000:.2f} Kbps"
                    else:
                        avg_bits_display = f"{avg_bits_per_sec:.2f} bps"
                        
                    if avg_bytes_per_sec >= 1000000:
                        avg_bytes_display = f"{avg_bytes_per_sec/1000000:.2f} MB/s"
                    elif avg_bytes_per_sec >= 1000:
                        avg_bytes_display = f"{avg_bytes_per_sec/1000:.2f} KB/s"
                    else:
                        avg_bytes_display = f"{avg_bytes_per_sec:.2f} B/s"
                    
                    # スループット情報をラベルに表示
                    throughput_text = f"指定フィルタ条件一致: {len(specific_filter_data['packets'])}パケット | 平均: {avg_bytes_display} ({avg_bits_display})"
                    self.throughput_label.config(text=throughput_text)
            else:
                self.throughput_label.config(text="指定フィルタ条件一致: 計算できません（時間範囲がありません）")
        else:
            self.throughput_label.config(text="指定フィルタ条件に一致するパケットはありません")

        self.filtered_data = self.all_data.copy()
        
        # ツリービューにデータを表示
        self.update_treeview_with_filtered_data()
        
        self.status_bar.config(text=f"ファイル読み込み完了。{packet_count}個のパケットを処理しました。")

    def extract_wireshark_info(self, packet):
        """Wiresharkスタイルの情報フィールドを生成"""
        try:
            # EtherCATパケットの場合
            if hasattr(packet, 'ecat') and hasattr(packet.ecat, 'ethercat_datagram'):
                info = []
                
                # コマンドとインデックスの情報を取得
                cmd = packet.ecat.cmd if hasattr(packet.ecat, 'cmd') else "Unknown"
                cmd_desc = self.ethercat_cmd_dict.get(cmd.lower(), f"CMD:{cmd}")
                info.append(cmd_desc)
                
                # LogAddrがあれば追加
                if hasattr(packet.ecat, 'logaddr'):
                    info.append(f"LogAddr: 0x{packet.ecat.logaddr}")
                
                # パケット数
                if hasattr(packet.ecat, 'ethercat_datagram'):
                    datagram_count = packet.ecat.ethercat_datagram
                    info.append(f"Datagram: {datagram_count}")
                
                return " | ".join(info)
            # その他のプロトコル
            else:
                return "Non-EtherCAT packet"
        except Exception as e:
            print(f"Info field extraction error: {e}")
            return "Error extracting info"
    
    def parse_ethercat_data(self, hex_data):
        """16進数データからEtherCATプロトコルの各フィールドを解析"""
        # EtherCATデータの最小長（ヘッダー+データグラム最小長）
        min_length = 2 + 10  # ヘッダー2バイト + データグラム最小長10バイト
        
        if len(hex_data) < min_length * 2:  # 16進数文字列なので長さは2倍
            return None
            
        # 結果を格納する辞書
        result = {
            'EtherCAT_Header': {},
            'EtherCAT_Datagrams': [],
            'Pad_bytes': None,
            'ET2000_Timestamp': None  # ET2000タイムスタンプフィールドを追加
        }
        
        # 解析位置のインデックス
        position = 28  # MACヘッダ(14バイト)とEtherType(2バイト)をスキップ
        
        # EtherCATヘッダー (2バイト)
        if position + 4 <= len(hex_data):
            header_hex = hex_data[position:position+4]
            
            # バイトの順序を入れ替え（リトルエンディアン→ビッグエンディアン）
            header_hex_swapped = header_hex[2:4] + header_hex[0:2]
            
            # 2進数に変換して各フィールドを抽出
            header_bin = bin(int(header_hex_swapped, 16))[2:].zfill(16)
            
            # Type (4ビット)
            result['EtherCAT_Header']['Type'] = header_bin[0:4]
            
            # Reserved (4ビット)
            result['EtherCAT_Header']['Reserved'] = header_bin[4:8]
            
            # Length (8ビット)
            result['EtherCAT_Header']['Length_bin'] = header_bin[8:16]
            result['EtherCAT_Header']['Length_hex'] = hex(int(header_bin[8:16], 2))[2:].zfill(2)
            result['EtherCAT_Header']['Length_dec'] = int(header_bin[8:16], 2)
            
            position += 4  # 2バイト(4文字)進める
            
            # EtherCATデータの実際の長さを計算
            total_length = result['EtherCAT_Header']['Length_dec']
            header_start = 28  # EtherCATヘッダーの開始位置
            ethercat_end = header_start + 4 + (total_length * 2)  # EtherCATフレームの終了位置
        else:
            return None
            
        # EtherCATデータグラム（可変長、複数存在する可能性あり）
        datagram_end_positions = []  # 各データグラムの終了位置を記録
        
        while position < ethercat_end:  # EtherCATフレーム内のデータグラムを処理
            # データグラムの最小長は10バイト(20文字)
            if position + 20 > len(hex_data):
                break
                
            datagram = {}
            
            # Cmd (1バイト)
            if position + 2 <= len(hex_data):
                datagram['Cmd'] = hex_data[position:position+2]
                position += 2
            else:
                break
                
            # Index (1バイト)
            if position + 2 <= len(hex_data):
                datagram['Index'] = hex_data[position:position+2]
                position += 2
            else:
                break
                
            # Address Position (2バイト) - バイトの順序を入れ替え
            if position + 4 <= len(hex_data):
                adp_hex = hex_data[position:position+4]
                datagram['ADP'] = adp_hex[2:4] + adp_hex[0:2]  # リトルエンディアン→ビッグエンディアン
                position += 4
            else:
                break
                
            # Address Offset (2バイト) - バイトの順序を入れ替え
            if position + 4 <= len(hex_data):
                ado_hex = hex_data[position:position+4]
                datagram['ADO'] = ado_hex[2:4] + ado_hex[0:2]  # リトルエンディアン→ビッグエンディアン
                position += 4
            else:
                break
                
            # Logical Address (4バイト) - これはADPとADOを組み合わせたもの
            datagram['LogAddr'] = datagram['ADP'] + datagram['ADO']
            
            # Length (2バイト) - バイトの順序を入れ替え
            if position + 4 <= len(hex_data):
                length_hex = hex_data[position:position+4]
                length_hex_swapped = length_hex[2:4] + length_hex[0:2]
                datagram['Length_hex'] = length_hex_swapped
                # 2進数に変換
                length_bin = bin(int(length_hex_swapped, 16))[2:].zfill(16)
                # Last indicator (1ビット)
                datagram['LastIndicator'] = length_bin[0:1]
                # Round trip (1ビット)
                datagram['RoundTrip'] = length_bin[1:2]
                # Reserved (3ビット)
                datagram['Reserved'] = length_bin[2:5]
                # Data Length (11ビット)
                data_length_bin = length_bin[5:16]
                datagram['DataLength_bin'] = data_length_bin
                datagram['DataLength_dec'] = int(data_length_bin, 2)
                position += 4
            else:
                break
                
            # Interrupt (2バイト) - バイトの順序を入れ替え
            if position + 4 <= len(hex_data):
                interrupt_hex = hex_data[position:position+4]
                datagram['Interrupt'] = interrupt_hex[2:4] + interrupt_hex[0:2]
                position += 4
            else:
                break
                
            # Data (可変長)
            data_length = datagram['DataLength_dec']
            if position + (data_length * 2) <= len(hex_data):
                datagram['Data'] = hex_data[position:position+(data_length*2)]
                position += (data_length * 2)
            else:
                break
                
            # Working Counter (2バイト) - バイトの順序を入れ替え
            if position + 4 <= len(hex_data):
                wkc_hex = hex_data[position:position+4]
                datagram['WorkingCnt'] = wkc_hex[2:4] + wkc_hex[0:2]
                position += 4
            else:
                break
                
            # データグラムをリストに追加
            result['EtherCAT_Datagrams'].append(datagram)
            datagram_end_positions.append(position)
            
            # LastIndicatorが1の場合、これが最後のデータグラム
            if datagram['LastIndicator'] == '1':
                break
                
        # パディングバイト（EtherCATフレームの後の残りのデータ）
        if len(datagram_end_positions) > 0:
            # 正しいEtherCATフレームの終了位置を取得
            actual_end = max(ethercat_end, datagram_end_positions[-1])
            if actual_end < len(hex_data):
                remaining_length = len(hex_data) - actual_end
                
                # 残りが32桁または64桁以下の場合、Pad Bytesとして処理
                if remaining_length <= 64:
                    pad_bytes = hex_data[actual_end:]
                    result['Pad_bytes'] = pad_bytes
                    
                    # ET2000タイムスタンプの抽出
                    if remaining_length >= 32:  # 32桁以上ある場合
                        et2000_timestamp_hex = pad_bytes
                        result['ET2000_Timestamp_Detail'] = self.parse_et2000_timestamp(et2000_timestamp_hex)
                        if result['ET2000_Timestamp_Detail'] and result['ET2000_Timestamp_Detail']['decimal'] is not None:
                            result['ET2000_Timestamp'] = result['ET2000_Timestamp_Detail']['decimal']
                        else:
                            result['ET2000_Timestamp'] = None
                
        return result

    def parse_et2000_timestamp(self, timestamp_hex):
        """ET2000タイムスタンプを解析してフォーマットする"""
        if not timestamp_hex:
            return None
            
        try:
            result = {
                'raw_hex': timestamp_hex,
                'is_et2000_enabled': False,
                'decimal': None,
                'formatted_timestamp': None,
                'original_timestamp_part': None
            }
            
            # ET2000が設定されているかを判断（64桁かどうか）
            if len(timestamp_hex) >= 64:
                result['is_et2000_enabled'] = True
                
                # 64桁の場合、16桁のタイムスタンプを抽出
                # タイムスタンプの位置を特定（仮定）
                # 多くの場合、これは後半32桁のどこかに位置する
                
                # まず64桁全体を確認
                self.debug_log(f"Full 64 hex: {timestamp_hex}")
                
                # タイムスタンプは後半32桁のどこかに位置する（仮定）
                last_32_chars = timestamp_hex[-32:]
                self.debug_log(f"Last 32 hex: {last_32_chars}")
                
                # ユーザーの説明によると、中間の16桁がタイムスタンプ
                # 12桁目から27桁目までの16桁を取得 (0始まりで11から26）
                timestamp_part = last_32_chars[0:16]
                result['original_timestamp_part'] = timestamp_part
                self.debug_log(f"Timestamp part (16 chars): {timestamp_part}")
                
                # リトルエンディアン形式で解釈（2桁ずつ取って反転）
                # 例: １２３４５６７８９０ab → 0xab9078563412
                formatted_ts = ''
                for i in range(len(timestamp_part)-2, -1, -2):
                    formatted_ts += timestamp_part[i:i+2]
                
                result['formatted_timestamp'] = formatted_ts
                self.debug_log(f"Formatted timestamp (little endian): {formatted_ts}")
                
                # 16進数として解釈
                result['decimal'] = int(formatted_ts, 16)
                
            elif len(timestamp_hex) >= 32:
                # 32桁の場合はET2000が未設定
                result['is_et2000_enabled'] = False
                # 単純に16進数として解釈
                try:
                    result['decimal'] = int(timestamp_hex, 16)
                except ValueError:
                    # 大きすぎる値の場合、32桁すべてを使わない
                    result['decimal'] = int(timestamp_hex[-16:], 16)
            
            return result
        except ValueError as e:
            self.debug_log(f"タイムスタンプ解析エラー: {e}")
            return None
            
    def debug_log(self, message):
        """デバッグログを出力（必要に応じてファイルに書き込むなどの処理を追加）"""
        print(message)
        # 必要に応じてログファイルへの書き込みなどを追加

    def on_packet_select(self, event):
        """パケットが選択されたときの処理"""
        selected_items = self.tree.selection()
        if not selected_items:
            return

        # 選択された行のインデックス
        item_id = selected_items[0]
        item_text = self.tree.item(item_id)['values']

        # 選択されたパケットのNo値を取得
        selected_no = item_text[0]

        # 該当するパケット情報を探す
        packet_info = None
        if self.is_filtered:
            for packet in self.filtered_data:
                if str(packet['No']) == str(selected_no):
                    packet_info = packet
                    break
        else:
            for packet in self.all_data:
                if str(packet['No']) == str(selected_no):
                    packet_info = packet
                    break
        
        if packet_info:
            # 基本情報タブに情報を表示
            self.basic_text.config(state=NORMAL)
            self.basic_text.delete(1.0, END)
            
            self.basic_text.insert(END, f"パケット番号: {packet_info['No']}\n")
            self.basic_text.insert(END, f"時間: {packet_info['Time']}\n")
            self.basic_text.insert(END, f"送信元: {packet_info['Source']}\n")
            self.basic_text.insert(END, f"宛先: {packet_info['Destination']}\n")
            self.basic_text.insert(END, f"プロトコル: {packet_info['Protocol']}\n")
            self.basic_text.insert(END, f"パケット長: {packet_info['Length']}\n")
            self.basic_text.insert(END, f"情報: {packet_info['Info']}\n")
            
            # 時間差情報を追加
            if 'TimeDiff' in packet_info and packet_info['TimeDiff'] is not None:
                self.basic_text.insert(END, f"時間差(ms): {packet_info['TimeDiff']:.3f}\n")
            if 'TSDiff' in packet_info and packet_info['TSDiff'] is not None:
                self.basic_text.insert(END, f"タイムスタンプ差(ms): {packet_info['TSDiff']:.3f}\n")
            
            # ET2000タイムスタンプ情報を追加
            if 'ET2000_Timestamp' in packet_info and packet_info['ET2000_Timestamp'] is not None:
                self.basic_text.insert(END, f"ET2000タイムスタンプ: 0x{packet_info['ET2000_Timestamp']:x}\n")
                
                # 詳細情報がある場合は表示
                if 'ET2000_Timestamp_Detail' in packet_info and packet_info['ET2000_Timestamp_Detail']:
                    detail = packet_info['ET2000_Timestamp_Detail']
                    if detail.get('is_et2000_enabled', False):
                        self.basic_text.insert(END, f"ET2000有効: はい\n")
                        if detail.get('formatted_timestamp'):
                            self.basic_text.insert(END, f"フォーマット済みタイムスタンプ: 0x{detail['formatted_timestamp']}\n")
                    else:
                        self.basic_text.insert(END, f"ET2000有効: いいえ\n")

            self.basic_text.config(state=DISABLED)
            
            # EtherCAT情報タブに情報を表示
            self.ethercat_text.config(state=NORMAL)
            self.ethercat_text.delete(1.0, END)
            
            if 'EtherCAT' in packet_info and packet_info['EtherCAT']:
                ethercat_data = packet_info['EtherCAT']
                
                # EtherCATヘッダー情報
                self.ethercat_text.insert(END, "===== EtherCAT Frame Header =====\n")
                header = ethercat_data.get('EtherCAT_Header', {})
                if header:
                    self.ethercat_text.insert(END, f"Type: {header.get('Type', '')}\n")
                    self.ethercat_text.insert(END, f"Reserved: {header.get('Reserved', '')}\n")
                    self.ethercat_text.insert(END, f"Length (binary): {header.get('Length_bin', '')}\n")
                    self.ethercat_text.insert(END, f"Length (hex): 0x{header.get('Length_hex', '')}\n")
                    self.ethercat_text.insert(END, f"Length (decimal): {header.get('Length_dec', '')}\n")
                
                # EtherCATデータグラム情報
                datagrams = ethercat_data.get('EtherCAT_Datagrams', [])
                for i, datagram in enumerate(datagrams):
                    self.ethercat_text.insert(END, f"\n===== EtherCAT Datagram #{i+1} =====\n")
                    
                    # コマンドの説明を追加
                    cmd_value = datagram.get('Cmd', '')
                    cmd_desc = self.ethercat_cmd_dict.get(cmd_value.lower(), "不明なコマンド")
                    self.ethercat_text.insert(END, f"Cmd: 0x{cmd_value} ({cmd_desc})\n")
                    self.ethercat_text.insert(END, f"Index: 0x{datagram.get('Index', '')}\n")
                    
                    # LogAddrに加えてADPとADOも表示
                    log_addr = datagram.get('LogAddr', '')
                    adp = datagram.get('ADP', '')
                    ado = datagram.get('ADO', '')
                    self.ethercat_text.insert(END, f"Log Addr: 0x{log_addr}\n")
                    self.ethercat_text.insert(END, f"ADP (Address Position): 0x{adp}\n")
                    self.ethercat_text.insert(END, f"ADO (Address Offset): 0x{ado}\n")
                    self.ethercat_text.insert(END, f"Length (hex): 0x{datagram.get('Length_hex', '')}\n")
                    self.ethercat_text.insert(END, f"Last Indicator: {datagram.get('LastIndicator', '')}\n")
                    self.ethercat_text.insert(END, f"Round Trip: {datagram.get('RoundTrip', '')}\n")
                    self.ethercat_text.insert(END, f"Reserved: {datagram.get('Reserved', '')}\n")
                    self.ethercat_text.insert(END, f"Data Length (binary): {datagram.get('DataLength_bin', '')}\n")
                    self.ethercat_text.insert(END, f"Data Length (decimal): {datagram.get('DataLength_dec', '')}\n")
                    self.ethercat_text.insert(END, f"Interrupt: 0x{datagram.get('Interrupt', '')}\n")
                    
                    # データは長いため、省略または適切にフォーマットして表示
                    data = datagram.get('Data', '')
                    if len(data) > 100:
                        self.ethercat_text.insert(END, f"Data: 0x{data[:100]}...(省略)\n")
                    else:
                        self.ethercat_text.insert(END, f"Data: 0x{data}\n")
                    self.ethercat_text.insert(END, f"Working Counter: 0x{datagram.get('WorkingCnt', '')}\n")
                
                # Pad bytes
                if ethercat_data.get('Pad_bytes'):
                    self.ethercat_text.insert(END, f"\n===== Pad Bytes =====\n")
                    pad_bytes = ethercat_data.get('Pad_bytes', '')
                    if len(pad_bytes) > 100:
                        self.ethercat_text.insert(END, f"Pad: 0x{pad_bytes[:100]}...(省略)\n")
                    else:
                        self.ethercat_text.insert(END, f"Pad: 0x{pad_bytes}\n")
                    
                # ET2000タイムスタンプの詳細情報
                if ethercat_data.get('ET2000_Timestamp_Detail'):
                    self.ethercat_text.insert(END, f"\n===== ET2000 Timestamp =====\n")
                    detail = ethercat_data.get('ET2000_Timestamp_Detail')
                    
                    # 基本情報
                    self.ethercat_text.insert(END, f"ET2000有効: {'はい' if detail.get('is_et2000_enabled', False) else 'いいえ'}\n")
                    
                    # 詳細情報
                    if detail.get('is_et2000_enabled', False):
                        # 元のPad Bytes（全体）
                        self.ethercat_text.insert(END, f"\n全Pad Bytes (64桁):\n")
                        raw_hex = detail['raw_hex']
                        for i in range(0, len(raw_hex), 8):
                            chunk = raw_hex[i:i+8]
                            self.ethercat_text.insert(END, f"{chunk} ")
                        self.ethercat_text.insert(END, "\n")
                        
                        # 後半32桁
                        if len(raw_hex) >= 32:
                            self.ethercat_text.insert(END, f"\n後半32桁:\n")
                            last_32 = raw_hex[-32:]
                            for i in range(0, len(last_32), 8):
                                chunk = last_32[i:i+8]
                                self.ethercat_text.insert(END, f"{chunk} ")
                            self.ethercat_text.insert(END, "\n")
                        
                        # タイムスタンプ部分（16桁）
                        if detail.get('original_timestamp_part'):
                            self.ethercat_text.insert(END, f"\nタイムスタンプ部分 (16桁):\n")
                            ts_part = detail['original_timestamp_part']
                            self.ethercat_text.insert(END, f"{ts_part}\n")
                            
                            # フォーマット済みタイムスタンプ（リトルエンディアン変換後）
                            if detail.get('formatted_timestamp'):
                                self.ethercat_text.insert(END, f"\nフォーマット済みタイムスタンプ (リトルエンディアン):\n")
                                self.ethercat_text.insert(END, f"0x{detail['formatted_timestamp']}\n")
                                self.ethercat_text.insert(END, f"変換例: {ts_part} → 0x{detail['formatted_timestamp']}\n")
                                
                                # 16進数値として表示
                                if detail.get('decimal') is not None:
                                    self.ethercat_text.insert(END, f"\n10進数値: {detail['decimal']}\n")
                    else:
                        # ET2000無効の場合（32桁）
                        self.ethercat_text.insert(END, f"\nPad Bytes (32桁):\n")
                        raw_hex = detail['raw_hex']
                        for i in range(0, len(raw_hex), 8):
                            chunk = raw_hex[i:i+8]
                            self.ethercat_text.insert(END, f"{chunk} ")
                        self.ethercat_text.insert(END, "\n")
                        
                        if detail.get('decimal') is not None:
                            self.ethercat_text.insert(END, f"\n10進数値: {detail['decimal']}\n")
                    
                    # タイムスタンプの解釈（時間値として）
                    if detail.get('decimal') is not None:
                        try:
                            decimal_value = detail['decimal']
                            # 仮定: 値はナノ秒単位のタイムスタンプ
                            ns_value = decimal_value
                            ms_value = ns_value / 1000000
                            seconds_value = ms_value / 1000
                            
                            self.ethercat_text.insert(END, f"\n推定時間値:\n")
                            self.ethercat_text.insert(END, f"ナノ秒: {ns_value}\n")
                            self.ethercat_text.insert(END, f"ミリ秒: {ms_value:.3f}\n")
                            self.ethercat_text.insert(END, f"秒: {seconds_value:.6f}\n")
                        except Exception as e:
                            self.ethercat_text.insert(END, f"\n時間値の計算エラー: {str(e)}\n")
            else:
                self.ethercat_text.insert(END, "EtherCATデータの解析に失敗しました。")
            
            self.ethercat_text.config(state=DISABLED)
            
            # 16進データタブに情報を表示
            self.hex_text.config(state=NORMAL)
            self.hex_text.delete(1.0, END)
            
            # 16進データの表示
            self.hex_text.insert(END, "16進データ:\n\n")
            
            # フォーマットして表示する（読みやすくするために32文字ごとに改行、またオフセットを表示）
            hex_data = packet_info.get('Formatted_Data2', '')
            for i in range(0, len(hex_data), 32):
                offset = i // 2
                line_data = hex_data[i:i+32]
                self.hex_text.insert(END, f"{offset:04x}: {line_data}\n")
            
            self.hex_text.config(state=DISABLED)

    def create_postfilter_row(self, parent, row_idx):
        """後処理フィルタ行を作成"""
        filter_frame = Frame(parent)
        filter_frame.pack(fill=X, pady=2)

        # フィールド選択
        field_var = StringVar()
        field_options = [field['display'] for field in self.postfilter_available_fields]
        field_dropdown = ttk.Combobox(filter_frame, textvariable=field_var, values=field_options, width=15)
        field_dropdown.grid(row=0, column=0, padx=5, pady=2)
        field_dropdown.current(0)  # 最初の要素を選択

        # 条件選択
        condition_var = StringVar()
        condition_dropdown = ttk.Combobox(filter_frame, textvariable=condition_var, values=self.conditions, width=10)
        condition_dropdown.grid(row=0, column=1, padx=5, pady=2)
        condition_dropdown.current(0)  # 最初の要素を選択

        # 値入力
        value_var = StringVar()
        value_entry = Entry(filter_frame, textvariable=value_var, width=25)
        value_entry.grid(row=0, column=2, padx=5, pady=2)

        # AND/OR選択
        logic_var = StringVar()
        logic_var.set("AND")
        logic_dropdown = ttk.Combobox(filter_frame, textvariable=logic_var, values=["AND", "OR"], width=5)
        logic_dropdown.grid(row=0, column=3, padx=5, pady=2)

        # 行削除ボタン
        remove_btn = Button(filter_frame, text="削除", 
                           command=lambda: self.remove_postfilter_row(filter_frame, row_idx))
        remove_btn.grid(row=0, column=4, padx=5, pady=2)

        # フィルタ情報を辞書に格納
        filter_info = {
            'frame': filter_frame,
            'field_var': field_var,
            'condition_var': condition_var,
            'value_var': value_var,
            'logic_var': logic_var,
            'remove_btn': remove_btn
        }

        # 最初の行の場合、ヒントラベルを追加
        if row_idx == 0:
            hint_label = Label(filter_frame, text="例: 「Protocol」フィールドで「ECAT」を含む", font=("Arial", 8))
            hint_label.grid(row=1, column=0, columnspan=5, padx=5, pady=0, sticky=tk.W)
            filter_info['hint_label'] = hint_label

        # フィルタ行リストに追加
        if row_idx < len(self.postfilter_rows):
            self.postfilter_rows.insert(row_idx, filter_info)
        else:
            self.postfilter_rows.append(filter_info)

        return filter_info

    def add_postfilter_row(self):
        """後処理フィルタ行を追加"""
        self.create_postfilter_row(self.postfilter_container, len(self.postfilter_rows))
    
    def remove_postfilter_row(self, frame, idx):
        """後処理フィルタ行を削除"""
        if len(self.postfilter_rows) <= 1:
            return  # 最低1行は残す

        # フレームを削除
        frame.destroy()

        # リストから削除
        if idx < len(self.postfilter_rows):
            self.postfilter_rows.pop(idx)

        # インデックスを更新
        for i in range(idx, len(self.postfilter_rows)):
            self.postfilter_rows[i]['remove_btn'].config(
                command=lambda i=i: self.remove_postfilter_row(
                    self.postfilter_rows[i]['frame'], i))

    def apply_postfilter(self):
        """後処理フィルタを適用する"""
        # フィルタが設定されていない場合は何もしない
        has_filter = False
        for filter_info in self.postfilter_rows:
            if filter_info['value_var'].get().strip():
                has_filter = True
                break
                
        if not has_filter:
            self.reset_postfilter()
            return
            
        # 元のデータを使用
        base_data = self.all_data
        filtered_result = []
        
        # 各行のフィルタを適用
        for packet in base_data:
            if self.match_packet_to_postfilter(packet):
                filtered_result.append(packet)
                
        # 結果を保存
        self.filtered_data = filtered_result
        self.is_filtered = True
        
        # ツリービューを更新
        self.update_treeview_with_filtered_data()
        
        # ステータスを更新
        self.status_bar.config(text=f"フィルタを適用しました。{len(filtered_result)}個のパケットが表示されています。")
        
    def match_packet_to_postfilter(self, packet):
        """パケットがフィルタ条件に一致するかチェック"""
        # フィルタがない場合は一致
        if not self.postfilter_rows:
            return True
            
        results = []
        
        for filter_info in self.postfilter_rows:
            field_display = filter_info['field_var'].get()
            condition = filter_info['condition_var'].get()
            value = filter_info['value_var'].get().strip()
            
            if not value:  # 値が空の場合はスキップ
                continue
                
            # 表示名からフィールドを取得
            field = None
            for f in self.postfilter_available_fields:
                if f['display'] == field_display:
                    field = f['field']
                    break
            
            if not field:
                continue
                
            # EtherCATフィールドの特別処理
            if field.startswith('EtherCAT.'):
                ethercat_field = field.split('.')[1]  # 'EtherCAT.Cmd' -> 'Cmd'
                
                if 'EtherCAT' in packet and packet['EtherCAT']:
                    # データグラムが複数ある場合は最初のものを使用
                    if ethercat_field in packet['EtherCAT']:
                        packet_value = packet['EtherCAT'][ethercat_field]
                    elif 'EtherCAT_Datagrams' in packet['EtherCAT'] and packet['EtherCAT']['EtherCAT_Datagrams']:
                        datagram = packet['EtherCAT']['EtherCAT_Datagrams'][0]
                        packet_value = datagram.get(ethercat_field, "")
                    else:
                        results.append(False)
                        continue
                else:
                    results.append(False)
                    continue
            elif field == 'ET2000_Timestamp':
                packet_value = packet.get('ET2000_Timestamp', None)
                if packet_value is None:
                    results.append(False)
                    continue
            else:
                # 通常のフィールド
                if field in packet:
                    packet_value = packet[field]
                else:
                    results.append(False)
                    continue
                
            # 型変換（必要に応じて）
            if field in ['TimeDiff', 'TSDiff'] and packet_value is not None:
                try:
                    filter_value = float(value)
                    packet_value = float(packet_value)
                except:
                    # 数値に変換できない場合は比較をスキップ
                    results.append(False)
                    continue
            elif field == 'ET2000_Timestamp' and packet_value is not None:
                try:
                    # 16進数または10進数として扱う
                    if value.lower().startswith('0x'):
                        filter_value = int(value, 16)
                    else:
                        filter_value = int(value)
                except:
                    results.append(False)
                    continue
            else:
                # 文字列として扱う
                packet_value = str(packet_value)
                filter_value = value
                
            # 条件に応じた比較
            match = False
            
            if condition == "含む":
                match = str(filter_value) in str(packet_value)
            elif condition == "等しい":
                if isinstance(packet_value, (int, float)) and isinstance(filter_value, (int, float)):
                    match = packet_value == filter_value
                else:
                    match = str(packet_value) == str(filter_value)
            elif condition == "以上":
                if isinstance(packet_value, (int, float)) and isinstance(filter_value, (int, float)):
                    match = packet_value >= filter_value
                else:
                    match = str(packet_value) >= str(filter_value)
            elif condition == "以下":
                if isinstance(packet_value, (int, float)) and isinstance(filter_value, (int, float)):
                    match = packet_value <= filter_value
                else:
                    match = str(packet_value) <= str(filter_value)
            elif condition == "より大きい":
                if isinstance(packet_value, (int, float)) and isinstance(filter_value, (int, float)):
                    match = packet_value > filter_value
                else:
                    match = str(packet_value) > str(filter_value)
            elif condition == "より小さい":
                if isinstance(packet_value, (int, float)) and isinstance(filter_value, (int, float)):
                    match = packet_value < filter_value
                else:
                    match = str(packet_value) < str(filter_value)
            elif condition == "開始する":
                match = str(packet_value).startswith(str(filter_value))
            elif condition == "修了する":
                match = str(packet_value).endswith(str(filter_value))
            elif condition == "一致する(正規表現)":
                try:
                    pattern = re.compile(str(filter_value))
                    match = bool(pattern.search(str(packet_value)))
                except:
                    match = False
            
            results.append(match)
        
        # 結果が空の場合は一致
        if not results:
            return True
            
        # 最初の結果
        final_result = results[0]
        
        # 2つ目以降の結果を論理演算子で結合
        for i in range(1, len(results)):
            logic = self.postfilter_rows[i-1]['logic_var'].get().upper()
            if logic == "AND":
                final_result = final_result and results[i]
            else:  # OR
                final_result = final_result or results[i]
        
        return final_result
        
    def reset_postfilter(self):
        """後処理フィルタをリセットする"""
        # フィルタリング状態をリセット
        self.filtered_data = self.all_data.copy()
        self.is_filtered = False
        
        # ツリービューを更新
        self.update_treeview_with_filtered_data()
        
        # ステータスを更新
        self.status_bar.config(text=f"フィルタをリセットしました。{len(self.all_data)}個のパケットが表示されています。")
        
    def update_treeview_with_filtered_data(self):
        """ツリービューを更新する"""
        # 既存のTreeviewデータをクリア
        for i in self.tree.get_children():
            self.tree.delete(i)
            
        # 表示するデータ
        display_data = self.filtered_data if self.is_filtered else self.all_data
        
        # Treeviewにデータを追加
        for packet in display_data:
            # 時間差の表示フォーマット
            time_diff = packet.get('TimeDiff')
            ts_diff = packet.get('TSDiff')
            time_diff_str = f"{time_diff:.3f}" if time_diff is not None else ""
            ts_diff_str = f"{ts_diff:.3f}" if ts_diff is not None else ""
            
            # ET2000タイムスタンプを16進数フォーマットで表示
            et2000_timestamp = packet.get('ET2000_Timestamp')
            et2000_str = f"0x{et2000_timestamp:x}" if et2000_timestamp is not None else ""
            
            # Treeviewにデータを追加
            self.tree.insert('', END, text='', values=(
                packet.get('No', ''),
                packet.get('Time', ''),
                packet.get('Timestamp', ''),
                packet.get('Source', ''),
                packet.get('Destination', ''),
                packet.get('Protocol', ''),
                packet.get('Length', ''),
                packet.get('Info', ''),
                time_diff_str,
                ts_diff_str,
                et2000_str  # ET2000タイムスタンプ列を追加
            ))

    def save_filter_defaults(self):
        """現在のフィルタ設定をデフォルト値として保存"""
        pass

if __name__ == "__main__":
    root = Tk()
    app = PCAPViewer(root)
    root.mainloop() 