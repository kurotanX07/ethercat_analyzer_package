# -*- coding: utf-8 -*-
"""
ボード定義解析モジュール
.hファイルから#define定義を読み込み、ボードタイプとアドレスのマッピングを作成
"""
import re
import os
import json
from typing import Dict, List, Tuple, Any, Optional
from collections import OrderedDict


class BoardDefinitionParser:
    """ヘッダーファイルからボード定義を解析するクラス"""
    
    def __init__(self):
        self.definitions = OrderedDict()  # 定義名 -> 値のマッピング
        self.board_mappings = OrderedDict()  # アドレス -> ボード名のマッピング
        self.expression_cache = {}  # 評価済み式のキャッシュ
        
    def parse_header_files(self, file_paths: List[str]) -> Dict[str, Any]:
        """
        複数のヘッダーファイルを解析
        
        Args:
            file_paths: 解析するヘッダーファイルのパスリスト
            
        Returns:
            解析結果の辞書
        """
        # 各ファイルを順番に解析
        for file_path in file_paths:
            if os.path.exists(file_path):
                self._parse_single_file(file_path)
        
        # ボードアドレスを計算
        self._calculate_board_addresses()
        
        return {
            'definitions': dict(self.definitions),
            'board_mappings': dict(self.board_mappings),
            'total_definitions': len(self.definitions),
            'total_boards': len(self.board_mappings)
        }
    
    def _parse_single_file(self, file_path: str):
        """単一のヘッダーファイルを解析"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # #defineパターンを検索
            # 形式: #define NAME VALUE または #define NAME (EXPRESSION)
            define_pattern = r'#define\s+(\w+)\s+(.+?)(?=\n|$)'
            
            for match in re.finditer(define_pattern, content):
                name = match.group(1).strip()
                value = match.group(2).strip()
                
                # コメントを除去
                if '//' in value:
                    value = value[:value.index('//')].strip()
                if '/*' in value:
                    value = re.sub(r'/\*.*?\*/', '', value).strip()
                
                # 値を保存
                if value:
                    self.definitions[name] = value
                    
        except Exception as e:
            print(f"ファイル解析エラー ({file_path}): {e}")
    
    def _calculate_board_addresses(self):
        """ボードアドレスを計算してマッピングを作成"""
        # MA0_やMA1_で始まる定義を探す（これらがボード定義と仮定）
        board_pattern = re.compile(r'^MA\d+_\w+')
        
        for name, value in self.definitions.items():
            if board_pattern.match(name):
                try:
                    # 値を評価してアドレスを取得
                    address = self._evaluate_expression(value)
                    if address is not None:
                        # アドレスを16進数文字列に変換（8桁固定）
                        hex_address = f"{address:08x}".upper()
                        self.board_mappings[hex_address] = name
                except Exception as e:
                    print(f"アドレス計算エラー ({name}): {e}")
    
    def _evaluate_expression(self, expression: str) -> Optional[int]:
        """
        C言語の式を評価して整数値を返す
        
        Args:
            expression: 評価する式
            
        Returns:
            評価結果の整数値、評価できない場合はNone
        """
        # キャッシュをチェック
        if expression in self.expression_cache:
            return self.expression_cache[expression]
        
        try:
            # 括弧で囲まれている場合は除去
            expression = expression.strip()
            if expression.startswith('(') and expression.endswith(')'):
                expression = expression[1:-1].strip()
            
            # 16進数リテラル
            if expression.startswith('0x') or expression.startswith('0X'):
                result = int(expression, 16)
                self.expression_cache[expression] = result
                return result
            
            # 10進数リテラル
            if expression.isdigit():
                result = int(expression)
                self.expression_cache[expression] = result
                return result
            
            # 定義済みシンボルの参照
            if expression in self.definitions:
                result = self._evaluate_expression(self.definitions[expression])
                self.expression_cache[expression] = result
                return result
            
            # 複雑な式の評価
            result = self._evaluate_complex_expression(expression)
            if result is not None:
                self.expression_cache[expression] = result
            return result
            
        except Exception as e:
            print(f"式評価エラー ({expression}): {e}")
            return None
    
    def _evaluate_complex_expression(self, expression: str) -> Optional[int]:
        """複雑な式を評価"""
        # 式内のシンボルを値に置き換え
        modified_expr = expression
        
        # シンボルを値に置き換え（長い名前から順に置き換え）
        sorted_symbols = sorted(self.definitions.keys(), key=len, reverse=True)
        for symbol in sorted_symbols:
            if symbol in modified_expr:
                # シンボルが単語境界にある場合のみ置き換え
                pattern = r'\b' + re.escape(symbol) + r'\b'
                value = self._evaluate_expression(self.definitions[symbol])
                if value is not None:
                    modified_expr = re.sub(pattern, str(value), modified_expr)
        
        try:
            # Pythonの式として評価（ビット演算も含む）
            # 安全な評価のため、許可された演算のみを含む
            allowed_names = {
                '__builtins__': {},
                'abs': abs,
                'min': min,
                'max': max,
            }
            
            # C言語の演算子をPython形式に変換
            modified_expr = modified_expr.replace('<<', '<<')
            modified_expr = modified_expr.replace('>>', '>>')
            modified_expr = modified_expr.replace('|', '|')
            modified_expr = modified_expr.replace('&', '&')
            modified_expr = modified_expr.replace('^', '^')
            
            # 評価
            result = eval(modified_expr, allowed_names, {})
            return int(result)
            
        except Exception as e:
            # 評価できない場合はNoneを返す
            return None
    
    def get_board_name(self, log_address: str) -> Optional[str]:
        """
        ログアドレスからボード名を取得
        
        Args:
            log_address: ログアドレス（16進数文字列）
            
        Returns:
            ボード名、見つからない場合はNone
        """
        # 0xプレフィックスを除去して大文字に変換
        address = log_address.upper().replace('0X', '')
        
        # 8桁に正規化
        address = address.zfill(8)
        
        return self.board_mappings.get(address)
    
    def save_to_file(self, file_path: str):
        """
        解析結果をファイルに保存
        
        Args:
            file_path: 保存先ファイルパス
        """
        data = {
            'definitions': dict(self.definitions),
            'board_mappings': dict(self.board_mappings)
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def load_from_file(self, file_path: str) -> bool:
        """
        保存されたデータを読み込み
        
        Args:
            file_path: 読み込むファイルパス
            
        Returns:
            読み込み成功の場合True
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.definitions = OrderedDict(data.get('definitions', {}))
            self.board_mappings = OrderedDict(data.get('board_mappings', {}))
            self.expression_cache.clear()
            
            return True
            
        except Exception as e:
            print(f"データ読み込みエラー: {e}")
            return False
    
    def get_formatted_board_info(self, log_address: str) -> str:
        """
        フォーマット済みのボード情報を取得
        
        Args:
            log_address: ログアドレス
            
        Returns:
            フォーマット済みの文字列（例: "MA0_PROT04_00_S(00080000)"）
        """
        board_name = self.get_board_name(log_address)
        
        if board_name:
            # アドレスを8桁の大文字16進数に正規化
            address = log_address.upper().replace('0X', '').zfill(8)
            return f"{board_name}({address})"
        else:
            # ボード名が見つからない場合は元のアドレスをそのまま返す
            return log_address
    
    def get_all_board_definitions(self) -> List[Tuple[str, str]]:
        """
        すべてのボード定義を取得
        
        Returns:
            (アドレス, ボード名)のタプルのリスト
        """
        return [(addr, name) for addr, name in self.board_mappings.items()]