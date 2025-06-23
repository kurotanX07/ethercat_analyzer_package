# -*- coding: utf-8 -*-
"""
エラーハンドリング用モジュール
"""
import logging
import traceback
from typing import Optional, Callable


class ErrorHandler:
    """エラーハンドリングを統一するクラス"""
    
    def __init__(self, status_callback: Optional[Callable[[str], None]] = None):
        """
        Args:
            status_callback: ステータス更新用のコールバック関数
        """
        self.status_callback = status_callback
        self.setup_logging()
    
    def setup_logging(self):
        """ログ設定を初期化"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('pcap_viewer.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def handle_exception(self, e: Exception, context: str = "", user_message: str = "") -> None:
        """
        例外を統一的に処理する
        
        Args:
            e: 発生した例外
            context: エラーが発生したコンテキスト
            user_message: ユーザーに表示するメッセージ
        """
        # ログに詳細を記録
        error_details = f"{context}: {str(e)}\n{traceback.format_exc()}"
        self.logger.error(error_details)
        
        # ユーザーにフレンドリーなメッセージを表示
        if user_message:
            display_message = user_message
        else:
            display_message = f"エラーが発生しました: {str(e)}"
        
        if self.status_callback:
            self.status_callback(display_message)
        
        print(f"エラー詳細: {error_details}")  # デバッグ用
    
    def safe_execute(self, func: Callable, *args, context: str = "", user_message: str = "", **kwargs):
        """
        関数を安全に実行する
        
        Args:
            func: 実行する関数
            context: エラーが発生した場合のコンテキスト
            user_message: エラー時のユーザーメッセージ
        
        Returns:
            関数の実行結果、またはエラー時はNone
        """
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_copy = e  # 例外変数をコピー
            self.handle_exception(error_copy, context, user_message)
            return None


class FileError(Exception):
    """ファイル関連のエラー"""
    pass


class FilterError(Exception):
    """フィルタ関連のエラー"""
    pass


class DataProcessingError(Exception):
    """データ処理関連のエラー"""
    pass 