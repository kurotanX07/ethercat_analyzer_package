# -*- coding: utf-8 -*-
"""
データ処理ユーティリティモジュール
"""
from datetime import datetime
from typing import Dict, List, Any, Optional
import re
from config import ETHERCAT_CMD_DICT


class DataProcessor:
    """データ処理関連のユーティリティクラス"""
    
    @staticmethod
    def calculate_time_diff(current_time: datetime, previous_time: Optional[datetime]) -> Optional[float]:
        """
        時間差を計算する（ミリ秒）
        
        Args:
            current_time: 現在の時間
            previous_time: 前の時間
            
        Returns:
            時間差（ミリ秒）、計算できない場合はNone
        """
        if previous_time and current_time:
            return (current_time - previous_time).total_seconds() * 1000
        return None
    
    @staticmethod
    def calculate_timestamp_diff(current_ts: float, previous_ts: Optional[float]) -> Optional[float]:
        """
        タイムスタンプ差を計算する（ミリ秒）
        
        Args:
            current_ts: 現在のタイムスタンプ
            previous_ts: 前のタイムスタンプ
            
        Returns:
            タイムスタンプ差（ミリ秒）、計算できない場合はNone
        """
        if previous_ts is not None and current_ts is not None:
            return (current_ts - previous_ts) * 1000
        return None
    
    @staticmethod
    def format_time_diff(time_diff: Optional[float]) -> str:
        """
        時間差を表示用にフォーマットする
        
        Args:
            time_diff: 時間差（ミリ秒）
            
        Returns:
            フォーマットされた文字列
        """
        return f"{time_diff:.3f}" if time_diff is not None else ""
    
    @staticmethod
    def normalize_hex_value(value: str) -> Any:
        """
        16進数表記を標準化する
        
        Args:
            value: 変換する値
            
        Returns:
            正規化された値
        """
        try:
            # 0xプレフィックスがある場合は16進数として解釈
            if value.lower().startswith('0x'):
                return int(value, 16)
            # 16進数っぽい文字列の場合も16進数として解釈
            elif all(c in '0123456789abcdefABCDEF' for c in value):
                return int(value, 16)
            # それ以外は通常の値として返す
            else:
                return value
        except ValueError:
            # 変換できない場合は元の値をそのまま返す
            return value
    
    @staticmethod
    def get_cmd_description(cmd_val: str) -> str:
        """
        コマンド値からコマンドタイプの説明を取得
        
        Args:
            cmd_val: コマンド値
            
        Returns:
            コマンドの説明
        """
        # 16進数の場合は文字列に変換
        if isinstance(cmd_val, int):
            cmd_hex = f"{cmd_val:02x}".lower()
        else:
            # 0xプレフィックスがある場合は削除
            cmd_hex = cmd_val.replace("0x", "").lower()
        
        # 辞書から説明を取得
        return ETHERCAT_CMD_DICT.get(cmd_hex, f"CMD({cmd_hex})")
    
    @staticmethod
    def compare_values(value_str: str, condition: str, compare_value: str) -> bool:
        """
        値の比較を行う
        
        Args:
            value_str: 比較対象の値
            condition: 比較条件
            compare_value: 比較する値
            
        Returns:
            比較結果
        """
        # 16進数表記の変換
        try:
            norm_value_str = value_str.lower()
            norm_compare_value = compare_value.lower()
            
            # 両方とも16進数の場合は数値比較
            if (all(c in '0123456789abcdef' for c in norm_value_str) and 
                all(c in '0123456789abcdef' for c in norm_compare_value)):
                
                if condition in ['等しい', '以上', '以下', 'より大きい', 'より小さい']:
                    value_num = int(norm_value_str, 16)
                    compare_num = int(norm_compare_value, 16)
                    
                    if condition == '等しい':
                        return value_num == compare_num
                    elif condition == '以上':
                        return value_num >= compare_num
                    elif condition == '以下':
                        return value_num <= compare_num
                    elif condition == 'より大きい':
                        return value_num > compare_num
                    elif condition == 'より小さい':
                        return value_num < compare_num
        except ValueError:
            # 16進数変換できない場合は文字列として処理
            pass
        
        # 数値比較
        try:
            if condition in ['等しい', '以上', '以下', 'より大きい', 'より小さい']:
                value_num = float(value_str)
                compare_num = float(compare_value)
                
                if condition == '等しい':
                    return value_num == compare_num
                elif condition == '以上':
                    return value_num >= compare_num
                elif condition == '以下':
                    return value_num <= compare_num
                elif condition == 'より大きい':
                    return value_num > compare_num
                elif condition == 'より小さい':
                    return value_num < compare_num
        except ValueError:
            # 数値変換できない場合は文字列として処理
            pass
        
        # 文字列条件の処理
        if condition == '含む':
            return compare_value.lower() in value_str.lower()
        elif condition == '等しい':
            return value_str.lower() == compare_value.lower()
        elif condition == '開始する':
            return value_str.lower().startswith(compare_value.lower())
        elif condition == '終了する':
            return value_str.lower().endswith(compare_value.lower())
        elif condition == '一致する(正規表現)':
            try:
                pattern = re.compile(compare_value, re.IGNORECASE)
                return bool(pattern.search(value_str))
            except re.error:
                return False
        
        return False


class EtherCATParser:
    """EtherCATデータ解析クラス"""
    
    @staticmethod
    def parse_ethercat_data(hex_data: str) -> Dict[str, Any]:
        """
        16進数データからEtherCATプロトコルの各フィールドを解析
        
        Args:
            hex_data: 16進数データ文字列
            
        Returns:
            解析結果の辞書
        """
        try:
            # EtherCAT解析結果を格納する辞書
            result = {
                'EtherCAT_Header': {},
                'EtherCAT_Datagrams': []
            }
            
            # Ethernet ヘッダー (14バイト) をスキップ
            position = 28  # 宛先MAC(12) + 送信元MAC(12) + Type(4) = 28桁の16進数
            
            # EtherCAT Frame Header (2バイト) を解析
            header_hex = hex_data[position:position+4]
            
            # 2バイトを入れ替え
            header_hex_swapped = header_hex[2:4] + header_hex[0:2]
            
            # 16進数を2進数に変換
            header_bin = bin(int(header_hex_swapped, 16))[2:].zfill(16)
            
            # Type (4ビット)
            result['EtherCAT_Header']['Type'] = header_bin[:4]
            
            # Reserved (1ビット)
            result['EtherCAT_Header']['Reserved'] = header_bin[4:5]
            
            # Length (11ビット)
            length_bin = header_bin[5:16]
            result['EtherCAT_Header']['Length_bin'] = length_bin
            result['EtherCAT_Header']['Length_hex'] = hex(int(length_bin, 2))[2:].upper()
            result['EtherCAT_Header']['Length_dec'] = int(length_bin, 2)
            position += 4  # EtherCAT Frame Header (4桁の16進数)
            
            # 全体の長さ
            total_length = result['EtherCAT_Header']['Length_dec'] * 2
            end_position = position + total_length
            
            # EtherCAT Datagramsの解析
            datagram_count = 0
            while position < end_position:
                datagram_count += 1
                datagram = {}
                
                # 各フィールドを順次解析
                if not EtherCATParser._parse_datagram_fields(hex_data, position, datagram):
                    break
                
                # データグラムリストに追加
                result['EtherCAT_Datagrams'].append(datagram)
                
                # 次のデータグラムの位置を計算
                position = EtherCATParser._calculate_next_position(position, datagram)
            
            # 残りはPad bytesとして扱う
            if position < len(hex_data) and position < end_position:
                result['Pad_bytes'] = hex_data[position:end_position]
            elif position < len(hex_data):
                # ヘッダーの長さフィールドに基づいてパディングを設定
                length_header = result['EtherCAT_Header']['Length_dec']
                expected_end = 28 + 4 + (length_header * 2)
                if expected_end < len(hex_data):
                    result['Pad_bytes'] = hex_data[expected_end:]
                
            return result
            
        except Exception as e:
            error_message = str(e)  # 例外メッセージをローカル変数にコピー
            print(f"EtherCAT解析エラー: {error_message}")
            return {}
    
    @staticmethod
    def _parse_datagram_fields(hex_data: str, position: int, datagram: Dict[str, Any]) -> bool:
        """
        データグラムのフィールドを解析
        
        Args:
            hex_data: 16進数データ
            position: 現在の位置
            datagram: データグラム辞書
            
        Returns:
            解析成功の場合True
        """
        try:
            # Cmd (1バイト)
            if position + 2 <= len(hex_data):
                datagram['Cmd'] = hex_data[position:position+2]
                position += 2
            else:
                return False
            
            # Index (1バイト)
            if position + 2 <= len(hex_data):
                datagram['Index'] = hex_data[position:position+2]
                position += 2
            else:
                return False
            
            # Log Addr (4バイト) - バイトの順序を入れ替え
            if position + 8 <= len(hex_data):
                log_addr = hex_data[position:position+8]
                datagram['LogAddr'] = log_addr[6:8] + log_addr[4:6] + log_addr[2:4] + log_addr[0:2]
                # ADPとADOの分離（上位4桁と下位4桁）
                adp = datagram['LogAddr'][:4]  # 上位4桁
                ado = datagram['LogAddr'][4:]  # 下位4桁
                datagram['ADP'] = adp  # Address Position
                datagram['ADO'] = ado  # Address Offset
                position += 8
            else:
                return False
            
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
                return False
            
            # Interrupt (2バイト) - バイトの順序を入れ替え
            if position + 4 <= len(hex_data):
                interrupt_hex = hex_data[position:position+4]
                datagram['Interrupt'] = interrupt_hex[2:4] + interrupt_hex[0:2]
                position += 4
            else:
                return False
            
            # Data (可変長)
            data_length = datagram['DataLength_dec']
            if position + (data_length * 2) <= len(hex_data):
                datagram['Data'] = hex_data[position:position+(data_length*2)]
                position += (data_length * 2)
            else:
                return False
            
            # Working Counter (2バイト) - バイトの順序を入れ替え
            if position + 4 <= len(hex_data):
                wkc_hex = hex_data[position:position+4]
                datagram['WorkingCnt'] = wkc_hex[2:4] + wkc_hex[0:2]
                position += 4
            else:
                return False
            
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def _calculate_next_position(position: int, datagram: Dict[str, Any]) -> int:
        """
        次のデータグラムの位置を計算
        
        Args:
            position: 現在の位置
            datagram: 現在のデータグラム
            
        Returns:
            次の位置
        """
        # Cmd(2) + Index(2) + LogAddr(8) + Length(4) + Interrupt(4) + Data + WorkingCnt(4)
        data_length = datagram.get('DataLength_dec', 0)
        return position + 2 + 2 + 8 + 4 + 4 + (data_length * 2) + 4 

# 以下の関数はコードの互換性のために追加
def hex_to_decimal(hex_str):
    """16進数文字列を10進数に変換"""
    if isinstance(hex_str, str):
        hex_str = hex_str.replace('0x', '')
        try:
            return int(hex_str, 16)
        except ValueError:
            return 0
    return 0

def hex_to_binary(hex_str):
    """16進数文字列を2進数文字列に変換"""
    if isinstance(hex_str, str):
        hex_str = hex_str.replace('0x', '')
        try:
            return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)
        except ValueError:
            return '0'
    return '0'