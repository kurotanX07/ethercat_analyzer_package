# -*- coding: utf-8 -*-
"""
再利用可能なUIコンポーネントモジュール
"""
import tkinter as tk
from tkinter import ttk, Frame, Label, Button, Entry, StringVar, IntVar, Toplevel
from typing import Callable, List, Dict, Any, Optional
import threading
import time


class FilterRow:
    """フィルタ行コンポーネント"""
    
    def __init__(self, parent: Frame, row_idx: int, fields: List[str], conditions: List[str], 
                 remove_callback: Optional[Callable] = None, hint_text: str = ""):
        self.parent = parent
        self.row_idx = row_idx
        self.fields = fields
        self.conditions = conditions
        self.remove_callback = remove_callback
        
        self.frame = Frame(parent)
        self.frame.pack(fill=tk.X, pady=2)
        
        # 変数の初期化
        self.field_var = StringVar()
        self.condition_var = StringVar()
        self.value_var = StringVar()
        
        # デフォルト値の設定
        if fields:
            self.field_var.set(fields[0])
        if conditions:
            self.condition_var.set(conditions[0])
        
        self._create_widgets(hint_text)
    
    def _create_widgets(self, hint_text: str):
        """ウィジェットの作成"""
        # ラベルは最初の行のみ表示
        if self.row_idx == 0:
            Label(self.frame, text="フィールド:").grid(
                row=0, column=0, padx=5, pady=2, sticky=tk.W
            )
        
        # フィールド選択
        self.field_dropdown = ttk.Combobox(
            self.frame, 
            textvariable=self.field_var, 
            values=self.fields
        )
        self.field_dropdown.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)
        
        # 条件選択
        self.condition_dropdown = ttk.Combobox(
            self.frame, 
            textvariable=self.condition_var, 
            values=self.conditions, 
            width=15
        )
        self.condition_dropdown.grid(row=0, column=2, padx=5, pady=2, sticky=tk.W)
        
        # 値入力
        Label(self.frame, text="値:").grid(row=0, column=3, padx=5, pady=2, sticky=tk.W)
        self.value_entry = Entry(self.frame, textvariable=self.value_var, width=20)
        self.value_entry.grid(row=0, column=4, padx=5, pady=2, sticky=tk.W)
        
        # 削除ボタン（最初の行以外）
        if self.row_idx > 0 and self.remove_callback:
            self.remove_btn = Button(
                self.frame, 
                text="✕", 
                command=lambda: self.remove_callback(self)
            )
            self.remove_btn.grid(row=0, column=5, padx=5, pady=2)
        
        # ヒントラベル（最初の行のみ）
        if self.row_idx == 0 and hint_text:
            self.hint_label = Label(
                self.frame, 
                text=hint_text, 
                font=("Arial", 8)
            )
            self.hint_label.grid(row=1, column=0, columnspan=6, padx=5, pady=0, sticky=tk.W)
    
    def get_values(self) -> Dict[str, str]:
        """フィルタ値を取得"""
        return {
            'field': self.field_var.get(),
            'condition': self.condition_var.get(),
            'value': self.value_var.get()
        }
    
    def set_values(self, field: str, condition: str, value: str):
        """フィルタ値を設定"""
        self.field_var.set(field)
        self.condition_var.set(condition)
        self.value_var.set(value)
    
    def destroy(self):
        """フィルタ行を削除"""
        self.frame.destroy()


class ProgressDialog:
    """プログレス表示ダイアログ"""
    
    def __init__(self, parent, title="処理中", message="処理を実行しています..."):
        self.parent = parent
        self.title = title
        self.message = message
        self.dialog = None
        self.progress_var = tk.StringVar()
        self.cancelled = False
        
    def show(self):
        """ダイアログを表示"""
        self.dialog = Toplevel(self.parent)
        self.dialog.title(self.title)
        self.dialog.geometry("400x150")
        self.dialog.resizable(False, False)
        
        # 親ウィンドウの中央に配置
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # メインフレーム
        main_frame = Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # メッセージラベル
        self.message_label = Label(main_frame, text=self.message, font=("Arial", 10))
        self.message_label.pack(pady=(0, 10))
        
        # プログレスバー
        self.progress_bar = ttk.Progressbar(
            main_frame, 
            mode='indeterminate',
            length=300
        )
        self.progress_bar.pack(pady=(0, 10))
        self.progress_bar.start(10)
        
        # プログレス詳細ラベル
        self.progress_label = Label(main_frame, textvariable=self.progress_var, font=("Arial", 9))
        self.progress_label.pack(pady=(0, 10))
        
        # キャンセルボタン
        self.cancel_btn = Button(
            main_frame, 
            text="キャンセル", 
            command=self.cancel,
            width=10
        )
        self.cancel_btn.pack()
        
        # ダイアログを中央に配置
        self._center_dialog()
        
    def _center_dialog(self):
        """ダイアログを親ウィンドウの中央に配置"""
        self.dialog.update_idletasks()
        
        # 親ウィンドウの位置とサイズを取得
        parent_x = self.parent.winfo_rootx()
        parent_y = self.parent.winfo_rooty()
        parent_width = self.parent.winfo_width()
        parent_height = self.parent.winfo_height()
        
        # ダイアログのサイズを取得
        dialog_width = self.dialog.winfo_reqwidth()
        dialog_height = self.dialog.winfo_reqheight()
        
        # 中央の座標を計算
        x = parent_x + (parent_width - dialog_width) // 2
        y = parent_y + (parent_height - dialog_height) // 2
        
        self.dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
        
    def update_progress(self, message):
        """プログレス情報を更新"""
        if self.dialog and self.dialog.winfo_exists():
            self.progress_var.set(message)
            self.dialog.update_idletasks()
            
    def update_message(self, message):
        """メインメッセージを更新"""
        if self.dialog and self.dialog.winfo_exists():
            self.message_label.config(text=message)
            self.dialog.update_idletasks()
            
    def cancel(self):
        """処理をキャンセル"""
        self.cancelled = True
        self.hide()
        
    def is_cancelled(self):
        """キャンセルされたかチェック"""
        return self.cancelled
        
    def hide(self):
        """ダイアログを非表示"""
        if self.dialog and self.dialog.winfo_exists():
            self.progress_bar.stop()
            self.dialog.destroy()
            self.dialog = None


class StatusBar:
    """ステータスバーコンポーネント"""
    
    def __init__(self, parent):
        self.status_var = StringVar()
        self.status_var.set("準備完了")
        
        self.frame = Frame(parent)
        self.frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # ステータスラベル
        self.status_label = Label(
            self.frame,
            textvariable=self.status_var,
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 追加情報ラベル（右側）
        self.info_var = StringVar()
        self.info_label = Label(
            self.frame,
            textvariable=self.info_var,
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.E,
            width=20
        )
        self.info_label.pack(side=tk.RIGHT)
    
    def set_status(self, message: str):
        """ステータスメッセージを設定"""
        self.status_var.set(message)
    
    def set_info(self, info: str):
        """追加情報を設定"""
        self.info_var.set(info)


class ToolTip:
    """ツールチップ表示クラス"""
    
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        
        # イベントをバインド
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)
        self.widget.bind("<Motion>", self.on_motion)
    
    def show_tooltip(self, event=None):
        """ツールチップを表示"""
        if self.tooltip_window or not self.text:
            return
            
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        
        self.tooltip_window = Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        
        label = Label(
            self.tooltip_window,
            text=self.text,
            background="#ffffe0",
            relief="solid",
            borderwidth=1,
            font=("Arial", 9),
            padx=5,
            pady=3
        )
        label.pack()
    
    def hide_tooltip(self, event=None):
        """ツールチップを非表示"""
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None
            
    def on_motion(self, event=None):
        """マウス移動時の処理"""
        # ツールチップの位置を更新
        if self.tooltip_window:
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
            self.tooltip_window.wm_geometry(f"+{x}+{y}")


class SearchableCombobox(ttk.Combobox):
    """検索可能なコンボボックス"""
    
    def __init__(self, parent, values: List[str], **kwargs):
        super().__init__(parent, **kwargs)
        self.all_values = values
        self.configure(values=values)
        
        # 検索機能のバインド
        self.bind('<KeyRelease>', self.on_key_release)
        self.bind('<Button-1>', self.on_click)
    
    def on_key_release(self, event):
        """キー入力時の検索処理"""
        current_text = self.get().lower()
        
        if not current_text:
            # 空の場合は全ての値を表示
            self.configure(values=self.all_values)
        else:
            # 入力文字列を含む値のみを表示
            filtered_values = [
                value for value in self.all_values 
                if current_text in value.lower()
            ]
            self.configure(values=filtered_values)
    
    def on_click(self, event):
        """クリック時に全ての値を表示"""
        self.configure(values=self.all_values)


class CollapsibleFrame:
    """折りたたみ可能なフレーム"""
    
    def __init__(self, parent, title: str, initial_state: bool = True):
        self.parent = parent
        self.title = title
        self.is_expanded = initial_state
        
        # メインフレーム
        self.main_frame = Frame(parent)
        self.main_frame.pack(fill=tk.X, pady=2)
        
        # タイトルフレーム（クリック可能）
        self.title_frame = Frame(self.main_frame, cursor="hand2")
        self.title_frame.pack(fill=tk.X)
        
        # 展開/折りたたみアイコン
        self.icon_var = StringVar()
        self.update_icon()
        
        self.icon_label = Label(
            self.title_frame, 
            textvariable=self.icon_var, 
            font=("Arial", 10)
        )
        self.icon_label.pack(side=tk.LEFT, padx=5)
        
        # タイトルラベル
        self.title_label = Label(
            self.title_frame, 
            text=title, 
            font=("Arial", 10, "bold")
        )
        self.title_label.pack(side=tk.LEFT, padx=5)
        
        # コンテンツフレーム
        self.content_frame = Frame(self.main_frame)
        if self.is_expanded:
            self.content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # クリックイベントのバインド
        self.title_frame.bind("<Button-1>", self.toggle)
        self.icon_label.bind("<Button-1>", self.toggle)
        self.title_label.bind("<Button-1>", self.toggle)
    
    def update_icon(self):
        """アイコンを更新"""
        self.icon_var.set("▼" if self.is_expanded else "▶")
    
    def toggle(self, event=None):
        """展開/折りたたみを切り替え"""
        self.is_expanded = not self.is_expanded
        self.update_icon()
        
        if self.is_expanded:
            self.content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        else:
            self.content_frame.pack_forget()
    
    def get_content_frame(self) -> Frame:
        """コンテンツフレームを取得"""
        return self.content_frame 


class StatusProgressBar:
    """ステータスバー内のプログレスバー"""
    
    def __init__(self, parent_frame):
        self.parent_frame = parent_frame
        self.progress_frame = None
        self.progress_bar = None
        self.status_label = None
        
    def show(self, message="処理中..."):
        """プログレスバーを表示"""
        if self.progress_frame:
            self.hide()
            
        self.progress_frame = Frame(self.parent_frame)
        self.progress_frame.pack(side=tk.RIGHT, padx=5)
        
        self.status_label = Label(self.progress_frame, text=message, font=("Arial", 9))
        self.status_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            mode='indeterminate',
            length=100
        )
        self.progress_bar.pack(side=tk.LEFT)
        self.progress_bar.start(10)
        
    def update_status(self, message):
        """ステータスメッセージを更新"""
        if self.status_label:
            self.status_label.config(text=message)
            
    def hide(self):
        """プログレスバーを非表示"""
        if self.progress_bar:
            self.progress_bar.stop()
        if self.progress_frame:
            self.progress_frame.destroy()
            self.progress_frame = None
            self.progress_bar = None
            self.status_label = None


class LoadingOverlay:
    """ローディングオーバーレイ"""
    
    def __init__(self, parent):
        self.parent = parent
        self.overlay = None
        
    def show(self, message="読み込み中..."):
        """オーバーレイを表示"""
        if self.overlay:
            return
            
        self.overlay = Toplevel(self.parent)
        self.overlay.title("")
        self.overlay.configure(bg='white')
        self.overlay.attributes('-alpha', 0.8)
        self.overlay.overrideredirect(True)
        
        # 親ウィンドウと同じサイズ・位置に設定
        self.overlay.geometry(f"{self.parent.winfo_width()}x{self.parent.winfo_height()}+{self.parent.winfo_rootx()}+{self.parent.winfo_rooty()}")
        
        # メッセージとプログレスバー
        frame = Frame(self.overlay, bg='white')
        frame.place(relx=0.5, rely=0.5, anchor='center')
        
        Label(frame, text=message, font=("Arial", 12), bg='white').pack(pady=10)
        
        progress = ttk.Progressbar(frame, mode='indeterminate', length=200)
        progress.pack(pady=10)
        progress.start(10)
        
        self.overlay.transient(self.parent)
        self.overlay.grab_set()
        
    def hide(self):
        """オーバーレイを非表示"""
        if self.overlay:
            self.overlay.destroy()
            self.overlay = None 


class DataHighlightDialog:
    """データハイライト設定ダイアログ"""
    
    def __init__(self, parent, title="データハイライト設定", initial_color="#FFFF00", initial_values=None):
        self.parent = parent
        self.title = title
        self.initial_color = initial_color
        self.initial_values = initial_values or {}
        self.result = None
        self.dialog = None
        
    def show(self):
        """ダイアログを表示"""
        self.dialog = Toplevel(self.parent)
        self.dialog.title(self.title)
        self.dialog.geometry("500x400")
        self.dialog.resizable(False, False)
        
        # 親ウィンドウの中央に配置
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # メインフレーム
        main_frame = Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # カラー選択エリア
        color_frame = Frame(main_frame)
        color_frame.pack(fill=tk.X, pady=(0, 10))
        
        Label(color_frame, text="ハイライト色:", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))
        
        self.color_var = StringVar(value=self.initial_color)
        self.color_preview = Frame(color_frame, bg=self.initial_color, width=30, height=20)
        self.color_preview.pack(side=tk.LEFT, padx=(0, 10))
        
        self.color_entry = Entry(color_frame, textvariable=self.color_var, width=10)
        self.color_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.color_var.trace_add("write", self._update_color_preview)
        
        self.color_btn = Button(color_frame, text="色を選択", command=self._choose_color)
        self.color_btn.pack(side=tk.LEFT)
        
        # 値入力エリア
        values_frame = Frame(main_frame)
        values_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        Label(values_frame, text="ハイライト対象の値（1行に1つ）:", font=("Arial", 10)).pack(anchor=tk.W, pady=(0, 5))
        
        # 値リスト
        self.values_text = tk.Text(values_frame, wrap=tk.WORD, height=12)
        self.values_text.pack(fill=tk.BOTH, expand=True)
        
        # 初期値があれば設定
        if self.initial_values:
            initial_text = "\n".join(self.initial_values)
            self.values_text.insert("1.0", initial_text)
        
        # ボタンエリア
        btn_frame = Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.apply_btn = Button(btn_frame, text="適用", command=self._apply)
        self.apply_btn.pack(side=tk.RIGHT, padx=5)
        
        self.cancel_btn = Button(btn_frame, text="キャンセル", command=self._cancel)
        self.cancel_btn.pack(side=tk.RIGHT, padx=5)
        
        # ダイアログを中央に配置
        self._center_dialog()
        
        # モーダルとして表示
        self.parent.wait_window(self.dialog)
        return self.result
        
    def _center_dialog(self):
        """ダイアログを親ウィンドウの中央に配置"""
        self.dialog.update_idletasks()
        
        # 親ウィンドウの位置とサイズを取得
        parent_x = self.parent.winfo_rootx()
        parent_y = self.parent.winfo_rooty()
        parent_width = self.parent.winfo_width()
        parent_height = self.parent.winfo_height()
        
        # ダイアログのサイズを取得
        dialog_width = self.dialog.winfo_reqwidth()
        dialog_height = self.dialog.winfo_reqheight()
        
        # 中央の座標を計算
        x = parent_x + (parent_width - dialog_width) // 2
        y = parent_y + (parent_height - dialog_height) // 2
        
        self.dialog.geometry(f"+{x}+{y}")
    
    def _update_color_preview(self, *args):
        """カラープレビューを更新"""
        try:
            color = self.color_var.get()
            self.color_preview.config(bg=color)
        except:
            # 無効な色の場合は無視
            pass
    
    def _choose_color(self):
        """色選択ダイアログを表示"""
        from tkinter import colorchooser
        color = colorchooser.askcolor(initialcolor=self.color_var.get())
        if color[1]:  # color[1]はHEX値
            self.color_var.set(color[1])
    
    def _apply(self):
        """設定を適用"""
        # 値のリストを取得
        values_text = self.values_text.get("1.0", tk.END).strip()
        values = [v.strip() for v in values_text.split("\n") if v.strip()]
        
        self.result = {
            'color': self.color_var.get(),
            'values': values
        }
        self.dialog.destroy()
    
    def _cancel(self):
        """キャンセル"""
        self.result = None
        self.dialog.destroy() 