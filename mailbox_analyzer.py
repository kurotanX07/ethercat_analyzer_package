# -*- coding: utf-8 -*-
"""
メールボックス通信解析モジュール
EtherCATのメールボックス通信（CoE、FoE、EoE、SoE）を解析
"""
import tkinter as tk
from tkinter import ttk, Frame, Label, Button, Toplevel, Scrollbar, VERTICAL, HORIZONTAL, END, Text, NORMAL, DISABLED
from collections import defaultdict, Counter, OrderedDict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from typing import Dict, List, Tuple, Any, Optional
import struct


class MailboxAnalyzer:
    """メールボックス通信解析クラス"""
    
    # メールボックスプロトコルタイプ
    MAILBOX_PROTOCOLS = {
        0x01: "CoE (CANopen over EtherCAT)",
        0x02: "EoE (Ethernet over EtherCAT)", 
        0x03: "FoE (File Access over EtherCAT)",
        0x04: "SoE (Servo Drive Profile over EtherCAT)",
        0x05: "VoE (Vendor specific over EtherCAT)"
    }
    
    # CoE SDOコマンド
    COE_SDO_COMMANDS = {
        0x20: "SDO Download Request",
        0x30: "SDO Download Response",
        0x40: "SDO Upload Request", 
        0x50: "SDO Upload Response",
        0x60: "SDO Segment Download Request",
        0x70: "SDO Segment Download Response",
        0x80: "SDO Abort Transfer"
    }
    
    def __init__(self, parent, data: List[Dict], board_parser=None):
        self.parent = parent
        self.data = data
        self.board_parser = board_parser
        self.window = None
        self.mailbox_data = []
        
    def show(self):
        """メールボックス解析ウィンドウを表示"""
        if self.window and self.window.winfo_exists():
            self.window.lift()
            return
            
        self.window = Toplevel(self.parent)
        self.window.title("メールボックス通信解析")
        self.window.geometry("1400x900")
        
        # メールボックス通信を抽出
        self.extract_mailbox_communications()
        
        # ノートブックでタブを作成
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 各タブを追加
        self.create_overview_tab(notebook)
        self.create_coe_analysis_tab(notebook)
        self.create_mailbox_sequence_tab(notebook)
        self.create_object_dictionary_tab(notebook)
        self.create_mailbox_errors_tab(notebook)
        self.create_statistics_tab(notebook)
        
    def extract_mailbox_communications(self):
        """データからメールボックス通信を抽出"""
        self.mailbox_data = []
        
        for packet in self.data:
            if packet.get('EtherCAT') and 'EtherCAT_Datagrams' in packet['EtherCAT']:
                for datagram in packet['EtherCAT']['EtherCAT_Datagrams']:
                    # メールボックス通信の特徴を検出
                    # 通常、特定のLogAddrレンジやデータパターンで識別
                    if self.is_mailbox_communication(datagram):
                        mailbox_info = self.parse_mailbox_data(datagram, packet)
                        if mailbox_info:
                            self.mailbox_data.append(mailbox_info)
                            
    def is_mailbox_communication(self, datagram):
        """データグラムがメールボックス通信かどうか判定"""
        # メールボックス通信の判定基準
        # 1. データ長が一定以上（通常8バイト以上）
        # 2. 特定のコマンドタイプ（FPRD/FPWR/FPRW）
        # 3. 特定のアドレスレンジ
        
        cmd = datagram.get('Cmd', '')
        data_length = datagram.get('DataLength_dec', 0)
        
        # FPRDまたはFPWRコマンドで、データ長が8バイト以上
        if cmd in ['0c', '0d', '0e'] and data_length >= 8:
            return True
            
        return False
        
    def parse_mailbox_data(self, datagram, packet):
        """メールボックスデータを解析"""
        data = datagram.get('Data', '')
        if len(data) < 16:  # 最小8バイト
            return None
            
        try:
            # メールボックスヘッダーの解析（最初の6バイト）
            # Length (2bytes), Address (2bytes), Priority:Type (1byte), Count (1byte)
            mb_length = int(data[0:4], 16)  # リトルエンディアン
            mb_address = int(data[4:8], 16)
            mb_type_priority = int(data[8:10], 16)
            mb_count = int(data[10:12], 16)
            
            mb_type = mb_type_priority & 0x0F
            mb_priority = (mb_type_priority >> 4) & 0x0F
            
            mailbox_info = {
                'packet_no': packet['No'],
                'time': packet['Time'],
                'timestamp': packet.get('Timestamp', 0),
                'src': packet.get('Source', ''),
                'dst': packet.get('Destination', ''),
                'logaddr': datagram.get('LogAddr', ''),
                'cmd': datagram.get('Cmd', ''),
                'mb_length': mb_length,
                'mb_address': mb_address,
                'mb_type': mb_type,
                'mb_priority': mb_priority,
                'mb_count': mb_count,
                'mb_protocol': self.MAILBOX_PROTOCOLS.get(mb_type, f"Unknown({mb_type})"),
                'data': data[12:],  # メールボックスヘッダー以降のデータ
                'raw_data': data
            }
            
            # プロトコル別の追加解析
            if mb_type == 0x01:  # CoE
                self.parse_coe_data(mailbox_info)
                
            return mailbox_info
            
        except Exception as e:
            print(f"メールボックスデータ解析エラー: {e}")
            return None
            
    def parse_coe_data(self, mailbox_info):
        """CoEデータを解析"""
        data = mailbox_info['data']
        if len(data) < 8:
            return
            
        try:
            # CoEヘッダー（2バイト）
            coe_header = int(data[0:4], 16)
            service = (coe_header >> 12) & 0x0F
            
            mailbox_info['coe_service'] = service
            
            if service == 2:  # SDO Service
                # SDO Command Specifier
                sdo_cs = int(data[4:6], 16)
                mailbox_info['sdo_command'] = self.COE_SDO_COMMANDS.get(sdo_cs & 0xE0, f"Unknown(0x{sdo_cs:02x})")
                
                # Index and Subindex
                if len(data) >= 12:
                    index = int(data[8:10] + data[6:8], 16)  # リトルエンディアン
                    subindex = int(data[10:12], 16)
                    mailbox_info['sdo_index'] = f"0x{index:04X}"
                    mailbox_info['sdo_subindex'] = f"0x{subindex:02X}"
                    
                    # SDOデータ
                    if len(data) > 12:
                        mailbox_info['sdo_data'] = data[12:]
                        
        except Exception as e:
            print(f"CoEデータ解析エラー: {e}")
            
    def create_overview_tab(self, notebook):
        """概要タブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="概要")
        
        # テキストエリア
        text_frame = Frame(tab)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget = Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)
        
        # 概要情報を表示
        text_widget.insert(END, "=== メールボックス通信概要 ===\n\n")
        
        text_widget.insert(END, f"【検出されたメールボックス通信】\n")
        text_widget.insert(END, f"総メールボックス通信数: {len(self.mailbox_data)}\n\n")
        
        # プロトコル別統計
        protocol_stats = Counter()
        for mb in self.mailbox_data:
            protocol_stats[mb['mb_protocol']] += 1
            
        text_widget.insert(END, "【プロトコル別統計】\n")
        for protocol, count in protocol_stats.most_common():
            text_widget.insert(END, f"{protocol}: {count}通信\n")
            
        # ノード別統計
        text_widget.insert(END, "\n【ノード別メールボックス通信】\n")
        node_stats = defaultdict(lambda: {'send': 0, 'recv': 0})
        
        for mb in self.mailbox_data:
            logaddr = mb['logaddr']
            if self.board_parser:
                board_name = self.board_parser.get_board_name(logaddr)
                node_name = board_name if board_name else f"0x{logaddr}"
            else:
                node_name = f"0x{logaddr}"
                
            if mb['cmd'] in ['0c', '0e']:  # Read
                node_stats[node_name]['recv'] += 1
            else:  # Write
                node_stats[node_name]['send'] += 1
                
        for node, stats in sorted(node_stats.items()):
            text_widget.insert(END, f"{node}: 送信{stats['send']}回, 受信{stats['recv']}回\n")
            
        text_widget.config(state=DISABLED)
        
    def create_coe_analysis_tab(self, notebook):
        """CoE解析タブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="CoE解析")
        
        # CoE通信のみをフィルタ
        coe_data = [mb for mb in self.mailbox_data if mb['mb_type'] == 0x01]
        
        if not coe_data:
            Label(tab, text="CoE通信が検出されませんでした").pack(pady=20)
            return
            
        # 上部：SDOコマンド統計
        stats_frame = Frame(tab)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # SDOコマンド統計を表示
        sdo_stats = Counter()
        for mb in coe_data:
            if 'sdo_command' in mb:
                sdo_stats[mb['sdo_command']] += 1
                
        # グラフ表示
        if sdo_stats:
            fig, ax = plt.subplots(figsize=(8, 4))
            commands = list(sdo_stats.keys())
            counts = list(sdo_stats.values())
            
            ax.bar(commands, counts)
            ax.set_xlabel('SDOコマンド')
            ax.set_ylabel('回数')
            ax.set_title('SDOコマンド使用統計')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            
            canvas = FigureCanvasTkAgg(fig, stats_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        # 下部：SDO通信リスト
        list_frame = Frame(tab)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # ツリービューでSDO通信を表示
        columns = ('No', 'Time', 'Node', 'Command', 'Index', 'SubIndex', 'Data')
        tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # カラム設定
        tree.column('No', width=60)
        tree.column('Time', width=150)
        tree.column('Node', width=150)
        tree.column('Command', width=200)
        tree.column('Index', width=80)
        tree.column('SubIndex', width=80)
        tree.column('Data', width=200)
        
        for col in columns:
            tree.heading(col, text=col)
            
        # スクロールバー
        vsb = Scrollbar(list_frame, orient=VERTICAL, command=tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=vsb.set)
        
        # データを追加
        for mb in coe_data:
            if 'sdo_command' in mb:
                logaddr = mb['logaddr']
                if self.board_parser:
                    board_name = self.board_parser.get_board_name(logaddr)
                    node = board_name if board_name else f"0x{logaddr}"
                else:
                    node = f"0x{logaddr}"
                    
                values = (
                    mb['packet_no'],
                    mb['time'],
                    node,
                    mb.get('sdo_command', ''),
                    mb.get('sdo_index', ''),
                    mb.get('sdo_subindex', ''),
                    mb.get('sdo_data', '')[:20] + '...' if mb.get('sdo_data', '') else ''
                )
                tree.insert('', END, values=values)
                
        tree.pack(fill=tk.BOTH, expand=True)
        
    def create_mailbox_sequence_tab(self, notebook):
        """メールボックスシーケンスタブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="通信シーケンス")
        
        # シーケンス図を表示
        if not self.mailbox_data:
            Label(tab, text="表示するデータがありません").pack(pady=20)
            return
            
        # グラフフレーム
        graph_frame = Frame(tab)
        graph_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 時系列でメールボックス通信を可視化
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # ノードリストを作成
        nodes = set()
        for mb in self.mailbox_data:
            nodes.add(mb['src'])
            nodes.add(mb['dst'])
            
        nodes = sorted(list(nodes))
        node_positions = {node: i for i, node in enumerate(nodes)}
        
        # 通信を矢印で表示
        for i, mb in enumerate(self.mailbox_data[:100]):  # 最初の100個のみ
            src_pos = node_positions.get(mb['src'], 0)
            dst_pos = node_positions.get(mb['dst'], 1)
            
            # プロトコルによって色分け
            color_map = {
                0x01: 'blue',   # CoE
                0x02: 'green',  # EoE
                0x03: 'orange', # FoE
                0x04: 'red',    # SoE
                0x05: 'purple'  # VoE
            }
            color = color_map.get(mb['mb_type'], 'gray')
            
            ax.annotate('', xy=(dst_pos, i), xytext=(src_pos, i),
                       arrowprops=dict(arrowstyle='->', color=color, lw=1.5))
            
            # ラベル
            if 'sdo_command' in mb:
                label = mb['sdo_command'].split()[0]
            else:
                label = mb['mb_protocol'].split()[0]
                
            ax.text((src_pos + dst_pos) / 2, i, label, 
                   ha='center', va='bottom', fontsize=8)
        
        # 軸設定
        ax.set_xlim(-0.5, len(nodes) - 0.5)
        ax.set_ylim(-1, min(100, len(self.mailbox_data)))
        ax.set_xticks(range(len(nodes)))
        ax.set_xticklabels(nodes, rotation=45, ha='right')
        ax.set_ylabel('シーケンス番号')
        ax.set_title('メールボックス通信シーケンス')
        ax.grid(True, alpha=0.3)
        ax.invert_yaxis()
        
        plt.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def create_object_dictionary_tab(self, notebook):
        """オブジェクトディクショナリタブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="オブジェクトディクショナリ")
        
        # アクセスされたオブジェクトを集計
        object_access = defaultdict(lambda: {'read': 0, 'write': 0, 'values': []})
        
        for mb in self.mailbox_data:
            if 'sdo_index' in mb and 'sdo_subindex' in mb:
                obj_key = f"{mb['sdo_index']}:{mb['sdo_subindex']}"
                
                if 'Upload' in mb.get('sdo_command', ''):
                    object_access[obj_key]['read'] += 1
                elif 'Download' in mb.get('sdo_command', ''):
                    object_access[obj_key]['write'] += 1
                    
                if 'sdo_data' in mb and mb['sdo_data']:
                    object_access[obj_key]['values'].append(mb['sdo_data'])
                    
        # ツリービューで表示
        tree_frame = Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('Object', 'Read', 'Write', 'Total', 'Values')
        tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        
        # カラム設定
        tree.column('Object', width=150)
        tree.column('Read', width=80)
        tree.column('Write', width=80)
        tree.column('Total', width=80)
        tree.column('Values', width=300)
        
        for col in columns:
            tree.heading(col, text=col)
            
        # データを追加
        for obj_key, stats in sorted(object_access.items()):
            total = stats['read'] + stats['write']
            values_str = ', '.join(set(stats['values'][:5]))  # 最初の5個のユニーク値
            if len(stats['values']) > 5:
                values_str += '...'
                
            tree.insert('', END, values=(
                obj_key,
                stats['read'],
                stats['write'],
                total,
                values_str
            ))
            
        # スクロールバー
        vsb = Scrollbar(tree_frame, orient=VERTICAL, command=tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=vsb.set)
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        # オブジェクトの説明（既知のオブジェクト）
        info_frame = Frame(tab)
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        Label(info_frame, text="一般的なオブジェクト:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        Label(info_frame, text="0x1000:0x00 - Device Type").pack(anchor=tk.W)
        Label(info_frame, text="0x1008:0x00 - Device Name").pack(anchor=tk.W)
        Label(info_frame, text="0x1009:0x00 - Hardware Version").pack(anchor=tk.W)
        Label(info_frame, text="0x100A:0x00 - Software Version").pack(anchor=tk.W)
        Label(info_frame, text="0x1018:0x00 - Identity Object").pack(anchor=tk.W)
        
    def create_mailbox_errors_tab(self, notebook):
        """エラー解析タブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="エラー解析")
        
        # エラーを検出
        errors = []
        
        # タイムアウト検出（レスポンスが遅い）
        request_response_pairs = self.find_request_response_pairs()
        
        for pair in request_response_pairs:
            if pair['response_time'] > 0.1:  # 100ms以上
                errors.append({
                    'type': 'タイムアウト',
                    'request': pair['request'],
                    'response': pair['response'],
                    'delay': pair['response_time']
                })
                
        # SDO Abort検出
        for mb in self.mailbox_data:
            if mb.get('sdo_command', '').startswith('SDO Abort'):
                errors.append({
                    'type': 'SDO Abort',
                    'packet': mb
                })
                
        # エラー表示
        text_frame = Frame(tab)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget = Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)
        
        text_widget.insert(END, "=== メールボックス通信エラー解析 ===\n\n")
        
        if not errors:
            text_widget.insert(END, "エラーは検出されませんでした。\n")
        else:
            text_widget.insert(END, f"検出されたエラー: {len(errors)}件\n\n")
            
            for error in errors[:50]:  # 最初の50件
                if error['type'] == 'タイムアウト':
                    text_widget.insert(END, f"【タイムアウト】\n")
                    text_widget.insert(END, f"リクエスト: パケット#{error['request']['packet_no']}\n")
                    text_widget.insert(END, f"レスポンス: パケット#{error['response']['packet_no']}\n")
                    text_widget.insert(END, f"遅延: {error['delay']*1000:.1f}ms\n\n")
                    
                elif error['type'] == 'SDO Abort':
                    text_widget.insert(END, f"【SDO Abort】\n")
                    text_widget.insert(END, f"パケット#{error['packet']['packet_no']}\n")
                    text_widget.insert(END, f"時刻: {error['packet']['time']}\n")
                    if 'sdo_index' in error['packet']:
                        text_widget.insert(END, f"オブジェクト: {error['packet']['sdo_index']}:{error['packet']['sdo_subindex']}\n")
                    text_widget.insert(END, "\n")
                    
        text_widget.config(state=DISABLED)
        
    def find_request_response_pairs(self):
        """リクエスト・レスポンスのペアを検出"""
        pairs = []
        pending_requests = {}
        
        for mb in self.mailbox_data:
            if 'sdo_command' in mb:
                # リクエスト
                if 'Request' in mb['sdo_command']:
                    key = (mb.get('sdo_index', ''), mb.get('sdo_subindex', ''), mb['logaddr'])
                    pending_requests[key] = mb
                    
                # レスポンス
                elif 'Response' in mb['sdo_command']:
                    key = (mb.get('sdo_index', ''), mb.get('sdo_subindex', ''), mb['logaddr'])
                    if key in pending_requests:
                        request = pending_requests[key]
                        response_time = mb['timestamp'] - request['timestamp']
                        
                        pairs.append({
                            'request': request,
                            'response': mb,
                            'response_time': response_time
                        })
                        
                        del pending_requests[key]
                        
        return pairs
        
    def create_statistics_tab(self, notebook):
        """統計タブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="統計")
        
        # 統計情報を計算
        stats = self.calculate_statistics()
        
        # グラフエリア
        graph_frame = Frame(tab)
        graph_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 2x2のサブプロット
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 8))
        
        # 1. 時間帯別メールボックス通信数
        if stats['hourly_distribution']:
            hours = list(stats['hourly_distribution'].keys())
            counts = list(stats['hourly_distribution'].values())
            ax1.bar(hours, counts)
            ax1.set_xlabel('時間')
            ax1.set_ylabel('通信数')
            ax1.set_title('時間帯別メールボックス通信')
            ax1.grid(True, alpha=0.3)
        
        # 2. プロトコル別円グラフ
        if stats['protocol_distribution']:
            protocols = list(stats['protocol_distribution'].keys())
            counts = list(stats['protocol_distribution'].values())
            ax2.pie(counts, labels=protocols, autopct='%1.1f%%')
            ax2.set_title('プロトコル別分布')
        
        # 3. レスポンスタイム分布
        if stats['response_times']:
            ax3.hist(stats['response_times'], bins=50, edgecolor='black')
            ax3.set_xlabel('レスポンスタイム (ms)')
            ax3.set_ylabel('頻度')
            ax3.set_title('レスポンスタイム分布')
            ax3.grid(True, alpha=0.3)
        
        # 4. ノード別通信頻度（上位10）
        if stats['node_communication']:
            nodes = list(stats['node_communication'].keys())[:10]
            counts = list(stats['node_communication'].values())[:10]
            ax4.barh(nodes, counts)
            ax4.set_xlabel('通信数')
            ax4.set_title('ノード別通信頻度（上位10）')
            ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def calculate_statistics(self):
        """統計情報を計算"""
        stats = {
            'hourly_distribution': defaultdict(int),
            'protocol_distribution': Counter(),
            'response_times': [],
            'node_communication': Counter()
        }
        
        # プロトコル分布
        for mb in self.mailbox_data:
            stats['protocol_distribution'][mb['mb_protocol'].split()[0]] += 1
            
            # ノード別統計
            logaddr = mb['logaddr']
            if self.board_parser:
                board_name = self.board_parser.get_board_name(logaddr)
                node = board_name if board_name else f"0x{logaddr}"
            else:
                node = f"0x{logaddr}"
            stats['node_communication'][node] += 1
        
        # レスポンスタイム統計
        pairs = self.find_request_response_pairs()
        for pair in pairs:
            stats['response_times'].append(pair['response_time'] * 1000)  # ms単位
            
        return statss