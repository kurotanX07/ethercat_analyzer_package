# -*- coding: utf-8 -*-
"""
EtherCATパケット解析ビューア設定ファイル
"""

# UI設定
WINDOW_TITLE = "EtherCATパケット解析ビューア"
WINDOW_GEOMETRY = "1600x900"
DEFAULT_HIGHLIGHT_COLOR = "#00FF00"

# カラム定義
COLUMNS = ['No', 'Time', 'Timestamp', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'TimeDiff', 'TSDiff']

# フィルタ条件
CONDITIONS = ['含む', '等しい', '以上', '以下', 'より大きい', 'より小さい', '開始する', '修了する', '一致する(正規表現)']

# EtherCATフィールド
ETHERCAT_FIELDS = ['Cmd', 'Index', 'ADP', 'ADO', 'LogAddr', 'Length_hex', 'LastIndicator', 'RoundTrip', 'Reserved', 'DataLength_dec', 'Interrupt', 'Data', 'WorkingCnt']

# 事前フィルタ利用可能フィールド
PREFILTER_AVAILABLE_FIELDS = [
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

# EtherCAT コマンド辞書
ETHERCAT_CMD_DICT = {
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

# ファイル設定
SUPPORTED_FILE_TYPES = [("PCAPNG files", "*.pcapng")]
DEFAULT_FILTER_FILE = "filter_defaults.json"

# パフォーマンス設定
UI_UPDATE_INTERVAL = 10  # パケット処理時のUI更新間隔
MAX_DISPLAY_DATA_LENGTH = 100  # 詳細表示でのデータ最大長
BATCH_SIZE = 100  # バッチ処理サイズ
CACHE_SIZE = 1000  # キャッシュサイズ

# ログ設定
LOG_LEVEL = "INFO"
LOG_FILE = "pcap_viewer.log"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# UI設定の詳細
FONT_FAMILY = "Arial"
FONT_SIZE = 10
MONOSPACE_FONT = "Courier New"

# 色設定
COLORS = {
    "highlight_default": "#00FF00",
    "highlight_data": "#ffff00",
    "error": "#FF0000",
    "warning": "#FFA500",
    "success": "#008000"
}