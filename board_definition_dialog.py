# -*- coding: utf-8 -*-
"""
ボード定義管理ダイアログ
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import Frame, Label, Button, Toplevel, Scrollbar, VERTICAL, HORIZONTAL, END
import os
from board_definition_parser import BoardDefinitionParser


class BoardDefinitionDialog:
    """ボード定義管理ダイアログクラス"""
    
    def __init__(self, parent):
        self.parent = parent
        self.parser = BoardDefinitionParser()
        self.dialog = None
        self.tree = None
        
        # デフォルトの保存ファイル
        self.default_save_file = "board_definitions.json"
        
        # 起動時に保存されたデータを読み込む
        self.load_saved_definitions()
    
    def show(self):
        """ダイアログを表示"""
        if self.dialog and self.dialog.winfo_exists():
            self.dialog.lift()
            return
        
        self.dialog = Toplevel(self.parent)
        self.dialog.title("ボード定義管理")
        self.dialog.geometry("800x600")
        
        # メインフレーム
        main_frame = Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # ボタンフレーム
        btn_frame = Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        # ヘッダーファイル読み込みボタン
        load_btn = Button(
            btn_frame, 
            text="ヘッダーファイルを読み込む", 
            command=self.load_header_files
        )
        load_btn.pack(side=tk.LEFT, padx=5)
        
        # 定義を保存ボタン
        save_btn = Button(
            btn_frame,
            text="定義を保存",
            command=self.save_definitions
        )
        save_btn.pack(side=tk.LEFT, padx=5)
        
        # 定義を読み込みボタン
        load_saved_btn = Button(
            btn_frame,
            text="保存された定義を読み込む",
            command=self.load_definitions_from_file
        )
        load_saved_btn.pack(side=tk.LEFT, padx=5)
        
        # クリアボタン
        clear_btn = Button(
            btn_frame,
            text="クリア",
            command=self.clear_definitions
        )
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # 情報ラベル
        self.info_label = Label(main_frame, text="定義が読み込まれていません", anchor=tk.W)
        self.info_label.pack(fill=tk.X, pady=(0, 5))
        
        # ツリービューフレーム
        tree_frame = Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # スクロールバー
        vsb = Scrollbar(tree_frame, orient=VERTICAL)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        hsb = Scrollbar(tree_frame, orient=HORIZONTAL)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # ツリービュー
        self.tree = ttk.Treeview(
            tree_frame,
            columns=('address', 'board_name', 'hex_value'),
            show='headings',
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # スクロールバーの設定
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        
        # カラムの設定
        self.tree.heading('address', text='アドレス')
        self.tree.heading('board_name', text='ボード名')
        self.tree.heading('hex_value', text='10進数値')
        
        self.tree.column('address', width=150, anchor=tk.CENTER)
        self.tree.column('board_name', width=300, anchor=tk.W)
        self.tree.column('hex_value', width=150, anchor=tk.CENTER)
        
        # 現在のデータを表示
        self.update_tree_view()
        
        # ステータスバー
        self.status_bar = Label(
            self.dialog, 
            text="準備完了", 
            bd=1, 
            relief=tk.SUNKEN, 
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def load_header_files(self):
        """ヘッダーファイルを選択して読み込む"""
        file_paths = filedialog.askopenfilenames(
            title="ヘッダーファイルを選択",
            filetypes=[("Header files", "*.h"), ("All files", "*.*")]
        )
        
        if not file_paths:
            return
        
        self.status_bar.config(text="ヘッダーファイルを解析中...")
        self.dialog.update()
        
        try:
            # ファイルを解析
            result = self.parser.parse_header_files(list(file_paths))
            
            # 結果を表示
            self.update_tree_view()
            
            # 情報を更新
            self.info_label.config(
                text=f"読み込み完了: {result['total_definitions']}個の定義、{result['total_boards']}個のボード"
            )
            self.status_bar.config(text="ヘッダーファイルの解析が完了しました")
            
        except Exception as e:
            messagebox.showerror("エラー", f"ファイル読み込みエラー: {str(e)}")
            self.status_bar.config(text="エラーが発生しました")
    
    def update_tree_view(self):
        """ツリービューを更新"""
        # 既存のアイテムをクリア
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # ボード定義を追加
        for address, board_name in self.parser.get_all_board_definitions():
            # 10進数値も表示
            try:
                dec_value = int(address, 16)
                dec_str = f"{dec_value:,}"
            except:
                dec_str = ""
            
            self.tree.insert('', END, values=(
                f"0x{address}",
                board_name,
                dec_str
            ))
    
    def save_definitions(self):
        """定義をファイルに保存"""
        if not self.parser.board_mappings:
            messagebox.showwarning("警告", "保存する定義がありません")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=self.default_save_file
        )
        
        if not file_path:
            return
        
        try:
            self.parser.save_to_file(file_path)
            messagebox.showinfo("成功", "定義を保存しました")
            self.status_bar.config(text=f"保存完了: {file_path}")
        except Exception as e:
            messagebox.showerror("エラー", f"保存エラー: {str(e)}")
    
    def load_definitions_from_file(self):
        """保存された定義を読み込む"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=self.default_save_file
        )
        
        if not file_path:
            return
        
        try:
            if self.parser.load_from_file(file_path):
                self.update_tree_view()
                
                total_boards = len(self.parser.board_mappings)
                total_defs = len(self.parser.definitions)
                
                self.info_label.config(
                    text=f"読み込み完了: {total_defs}個の定義、{total_boards}個のボード"
                )
                messagebox.showinfo("成功", "定義を読み込みました")
                self.status_bar.config(text=f"読み込み完了: {file_path}")
            else:
                messagebox.showerror("エラー", "ファイルの読み込みに失敗しました")
        except Exception as e:
            messagebox.showerror("エラー", f"読み込みエラー: {str(e)}")
    
    def load_saved_definitions(self):
        """起動時に保存された定義を自動的に読み込む"""
        if os.path.exists(self.default_save_file):
            try:
                self.parser.load_from_file(self.default_save_file)
            except:
                # エラーが発生しても続行
                pass
    
    def clear_definitions(self):
        """定義をクリア"""
        if messagebox.askyesno("確認", "すべての定義をクリアしますか？"):
            self.parser.definitions.clear()
            self.parser.board_mappings.clear()
            self.parser.expression_cache.clear()
            
            self.update_tree_view()
            self.info_label.config(text="定義がクリアされました")
            self.status_bar.config(text="クリア完了")
    
    def get_parser(self) -> BoardDefinitionParser:
        """パーサーインスタンスを取得"""
        return self.parser