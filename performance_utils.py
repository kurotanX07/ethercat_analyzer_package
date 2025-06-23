# -*- coding: utf-8 -*-
"""
パフォーマンス改善ユーティリティモジュール
"""
import time
import threading
from typing import Callable, Any, Optional
from functools import wraps

# psutilをインポートを追加
try:
    import psutil
except ImportError:
    psutil = None


class PerformanceMonitor:
    """パフォーマンス監視クラス"""
    
    def __init__(self):
        self.execution_times = {}
    
    def measure_time(self, func_name: str = None):
        """実行時間を測定するデコレータ"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                name = func_name or func.__name__
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    end_time = time.time()
                    execution_time = end_time - start_time
                    self.execution_times[name] = execution_time
                    print(f"[Performance] {name}: {execution_time:.3f}秒")
            return wrapper
        return decorator
    
    def get_execution_times(self):
        """実行時間の履歴を取得"""
        return self.execution_times.copy()


class BackgroundProcessor:
    """バックグラウンド処理クラス"""
    
    def __init__(self, progress_callback: Optional[Callable[[int, str], None]] = None):
        self.progress_callback = progress_callback
        self.is_cancelled = False
    
    def process_in_background(self, func: Callable, *args, **kwargs):
        """バックグラウンドで処理を実行"""
        def worker():
            try:
                result = func(*args, **kwargs)
                if self.progress_callback:
                    self.progress_callback(100, "処理完了")
                return result
            except Exception as e:
                error_message = str(e)  # 例外メッセージをローカル変数にコピー
                if self.progress_callback:
                    self.progress_callback(-1, f"エラー: {error_message}")
                raise
        
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()
        return thread
    
    def cancel(self):
        """処理をキャンセル"""
        self.is_cancelled = True


class DataCache:
    """データキャッシュクラス"""
    
    def __init__(self, max_size: int = 1000):
        self.cache = {}
        self.max_size = max_size
        self.access_order = []
    
    def get(self, key: str) -> Any:
        """キャッシュからデータを取得"""
        if key in self.cache:
            # アクセス順序を更新
            self.access_order.remove(key)
            self.access_order.append(key)
            return self.cache[key]
        return None
    
    def set(self, key: str, value: Any):
        """キャッシュにデータを設定"""
        if key in self.cache:
            # 既存のキーの場合は値を更新
            self.cache[key] = value
            self.access_order.remove(key)
            self.access_order.append(key)
        else:
            # 新しいキーの場合
            if len(self.cache) >= self.max_size:
                # 最も古いアクセスのキーを削除
                oldest_key = self.access_order.pop(0)
                del self.cache[oldest_key]
            
            self.cache[key] = value
            self.access_order.append(key)
    
    def clear(self):
        """キャッシュをクリア"""
        self.cache.clear()
        self.access_order.clear()
    
    def size(self) -> int:
        """キャッシュサイズを取得"""
        return len(self.cache)


class BatchProcessor:
    """バッチ処理クラス"""
    
    def __init__(self, batch_size: int = 100):
        self.batch_size = batch_size
    
    def process_in_batches(self, items: list, processor: Callable, progress_callback: Optional[Callable] = None):
        """アイテムをバッチ処理"""
        results = []
        total_items = len(items)
        
        for i in range(0, total_items, self.batch_size):
            batch = items[i:i + self.batch_size]
            batch_results = []
            
            for item in batch:
                try:
                    result = processor(item)
                    batch_results.append(result)
                except Exception as e:
                    error_message = str(e)  # 例外メッセージをローカル変数にコピー
                    print(f"バッチ処理エラー: {error_message}")
                    batch_results.append(None)
            
            results.extend(batch_results)
            
            # 進捗報告
            if progress_callback:
                progress = min(100, int((i + len(batch)) / total_items * 100))
                progress_callback(progress, f"{i + len(batch)}/{total_items}件処理完了")
        
        return results


class MemoryOptimizer:
    """メモリ最適化クラス"""
    
    @staticmethod
    def optimize_data_structure(data: list) -> list:
        """データ構造を最適化"""
        # 重複データの除去や圧縮などの最適化処理
        optimized_data = []
        seen = set()
        
        for item in data:
            # 辞書の場合はキーでユニーク性をチェック
            if isinstance(item, dict):
                key = item.get('No', id(item))
                if key not in seen:
                    seen.add(key)
                    optimized_data.append(item)
            else:
                if item not in seen:
                    seen.add(item)
                    optimized_data.append(item)
        
        return optimized_data
    
    @staticmethod
    def compress_string_data(data: str) -> str:
        """文字列データの圧縮（簡易版）"""
        # 連続する空白の圧縮
        import re
        compressed = re.sub(r'\s+', ' ', data)
        return compressed.strip()


# memory_usage_psutil関数を追加
def memory_usage_psutil():
    """
    psutilを使って現在のプロセスのメモリ使用量を取得する
    
    Returns:
        float: メモリ使用量（MB）、psutilがインストールされていない場合は0
    """
    if psutil is None:
        print("警告: psutilがインストールされていません。'pip install psutil'でインストールしてください。")
        return 0
        
    # 現在のプロセスを取得
    process = psutil.Process()
    
    # メモリ情報を取得 (バイト単位)
    memory_info = process.memory_info()
    
    # MB単位に変換して返す
    return memory_info.rss / (1024 * 1024) 