# -*- coding: utf-8 -*-
"""
データフロー解析モジュール
EtherCATパケットのデータのやり取りを分析
"""
import tkinter as tk
from tkinter import ttk, Frame, Label, Button, Toplevel, Scrollbar, VERTICAL, HORIZONTAL, END, Text, NORMAL, DISABLED, Canvas
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.patches import Rectangle
import matplotlib.patches as mpatches
import networkx as nx
from typing import Dict, List, Tuple, Any
import numpy as np
from datetime import datetime


class DataFlowAnalyzer:
    """データフロー解析クラス"""
    
    def __init__(self, parent, data: List[Dict], board_parser=None):
        self.parent = parent
        self.data = data
        self.board_parser = board_parser
        self.window = None
        
    def show(self):
        """データ解析ウィンドウを表示"""
        if self.window and self.window.winfo_exists():
            self.window.lift()
            return
            
        self.window = Toplevel(self.parent)
        self.window.title("データフロー解析")
        self.window.geometry("1400x900")
        
        # ノートブックでタブを作成
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 各タブを追加
        self.create_communication_matrix_tab(notebook)
        self.create_data_flow_tab(notebook)
        self.create_timeline_visualization_tab(notebook)  # 新規追加
        self.create_command_response_tab(notebook)
        self.create_payload_analysis_tab(notebook)
        self.create_error_analysis_tab(notebook)
        self.create_summary_tab(notebook)
        
    def create_communication_matrix_tab(self, notebook):
        """通信マトリックスタブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="通信マトリックス")
        
        # データを解析
        comm_matrix = self.analyze_communication_matrix()
        
        # 表示エリア
        display_frame = Frame(tab)
        display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # ヒートマップを作成
        if comm_matrix:
            self.plot_communication_heatmap(display_frame, comm_matrix)
        else:
            Label(display_frame, text="通信データがありません").pack()
            
    def analyze_communication_matrix(self) -> Dict[Tuple[str, str], int]:
        """ノード間の通信マトリックスを解析"""
        comm_matrix = defaultdict(int)
        
        for packet in self.data:
            src = packet.get('Source', 'Unknown')
            dst = packet.get('Destination', 'Unknown')
            comm_matrix[(src, dst)] += 1
            
        return dict(comm_matrix)
        
    def plot_communication_heatmap(self, parent_frame, comm_matrix):
        """通信マトリックスのヒートマップを表示"""
        # ユニークなノードを抽出
        nodes = set()
        for (src, dst) in comm_matrix.keys():
            nodes.add(src)
            nodes.add(dst)
        nodes = sorted(list(nodes))
        
        # マトリックスデータを作成
        matrix_data = []
        for src in nodes:
            row = []
            for dst in nodes:
                count = comm_matrix.get((src, dst), 0)
                row.append(count)
            matrix_data.append(row)
            
        # グラフを作成
        fig, ax = plt.subplots(figsize=(10, 8))
        im = ax.imshow(matrix_data, cmap='YlOrRd', aspect='auto')
        
        # 軸ラベル
        ax.set_xticks(range(len(nodes)))
        ax.set_yticks(range(len(nodes)))
        ax.set_xticklabels(nodes, rotation=45, ha='right')
        ax.set_yticklabels(nodes)
        ax.set_xlabel('宛先')
        ax.set_ylabel('送信元')
        ax.set_title('ノード間通信頻度マトリックス')
        
        # カラーバー
        plt.colorbar(im, ax=ax, label='パケット数')
        
        # 値を表示
        for i in range(len(nodes)):
            for j in range(len(nodes)):
                if matrix_data[i][j] > 0:
                    text = ax.text(j, i, str(matrix_data[i][j]),
                                 ha="center", va="center", color="black", fontsize=8)
        
        plt.tight_layout()
        
        # Tkinterに埋め込む
        canvas = FigureCanvasTkAgg(fig, parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def create_data_flow_tab(self, notebook):
        """データフロー可視化タブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="データフロー")
        
        # コントロールフレーム
        control_frame = Frame(tab)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        Label(control_frame, text="表示するパケット数:").pack(side=tk.LEFT, padx=5)
        
        packet_count_var = tk.StringVar(value="100")
        packet_count_entry = tk.Entry(control_frame, textvariable=packet_count_var, width=10)
        packet_count_entry.pack(side=tk.LEFT, padx=5)
        
        update_btn = Button(control_frame, text="更新", 
                          command=lambda: self.update_data_flow(tab, int(packet_count_var.get())))
        update_btn.pack(side=tk.LEFT, padx=5)
        
        # 初期表示
        self.update_data_flow(tab, 100)
        
    def update_data_flow(self, parent_tab, packet_count):
        """データフローグラフを更新"""
        # 既存のグラフをクリア
        for widget in parent_tab.winfo_children():
            if isinstance(widget, Frame) and widget.winfo_children():
                for child in widget.winfo_children():
                    if hasattr(child, 'get_tk_widget'):
                        widget.destroy()
                        
        # グラフフレーム
        graph_frame = Frame(parent_tab)
        graph_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # ネットワークグラフを作成
        G = nx.DiGraph()
        
        # 指定数のパケットを解析
        for packet in self.data[:packet_count]:
            if packet.get('EtherCAT') and 'EtherCAT_Datagrams' in packet['EtherCAT']:
                src = packet.get('Source', 'Unknown')
                
                for datagram in packet['EtherCAT']['EtherCAT_Datagrams']:
                    log_addr = datagram.get('LogAddr', '')
                    if log_addr:
                        # ボード名を取得
                        if self.board_parser:
                            board_name = self.board_parser.get_board_name(log_addr)
                            dst = board_name if board_name else f"0x{log_addr}"
                        else:
                            dst = f"0x{log_addr}"
                        
                        # エッジを追加（重みを増やす）
                        if G.has_edge(src, dst):
                            G[src][dst]['weight'] += 1
                        else:
                            G.add_edge(src, dst, weight=1)
                            
        # グラフを描画
        fig, ax = plt.subplots(figsize=(12, 8))
        
        if len(G.nodes()) > 0:
            pos = nx.spring_layout(G, k=2, iterations=50)
            
            # ノードを描画
            nx.draw_networkx_nodes(G, pos, node_color='lightblue', 
                                 node_size=1000, ax=ax)
            
            # エッジを描画（太さを重みに応じて変更）
            edges = G.edges()
            weights = [G[u][v]['weight'] for u, v in edges]
            max_weight = max(weights) if weights else 1
            
            for (u, v) in edges:
                weight = G[u][v]['weight']
                width = 1 + (weight / max_weight) * 5
                nx.draw_networkx_edges(G, pos, [(u, v)], width=width, 
                                     alpha=0.6, edge_color='gray', ax=ax,
                                     connectionstyle="arc3,rad=0.1", 
                                     arrowsize=20)
            
            # ラベルを描画
            labels = {}
            for node in G.nodes():
                # 長いMACアドレスは短縮
                if ':' in node and len(node) > 10:
                    labels[node] = node[:8] + '...'
                else:
                    labels[node] = node
                    
            nx.draw_networkx_labels(G, pos, labels, font_size=8, ax=ax)
            
            # エッジラベル（パケット数）
            edge_labels = nx.get_edge_attributes(G, 'weight')
            nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=6, ax=ax)
            
            ax.set_title(f'データフローグラフ（最初の{packet_count}パケット）')
            ax.axis('off')
        else:
            ax.text(0.5, 0.5, 'データフローが検出されませんでした', 
                   ha='center', va='center', transform=ax.transAxes)
            
        plt.tight_layout()
        
        # Tkinterに埋め込む
        canvas = FigureCanvasTkAgg(fig, graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def create_command_response_tab(self, notebook):
        """コマンド・レスポンス分析タブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="コマンド・レスポンス")
        
        # 分析結果を表示
        cmd_analysis = self.analyze_command_response()
        
        # スクロール可能なテキストエリア
        text_frame = Frame(tab)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget = Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)
        
        # 分析結果を表示
        text_widget.insert(END, "=== EtherCATコマンド・レスポンス分析 ===\n\n")
        
        # コマンド統計
        text_widget.insert(END, "【コマンド使用統計】\n")
        for cmd, count in sorted(cmd_analysis['cmd_stats'].items(), 
                               key=lambda x: x[1], reverse=True):
            text_widget.insert(END, f"{cmd}: {count}回\n")
            
        text_widget.insert(END, "\n【Round Tripフラグ分析】\n")
        text_widget.insert(END, f"Round Trip設定あり: {cmd_analysis['round_trip_count']}パケット\n")
        text_widget.insert(END, f"Round Trip設定なし: {cmd_analysis['non_round_trip_count']}パケット\n")
        
        text_widget.insert(END, "\n【Working Counter分析】\n")
        wkc_stats = cmd_analysis['wkc_stats']
        if wkc_stats:
            text_widget.insert(END, f"Working Counter値の分布:\n")
            for wkc, count in sorted(wkc_stats.items(), 
                                   key=lambda x: x[1], reverse=True)[:10]:
                text_widget.insert(END, f"  0x{wkc}: {count}回\n")
                
        text_widget.insert(END, "\n【インデックス使用状況】\n")
        idx_stats = cmd_analysis['idx_stats']
        if idx_stats:
            text_widget.insert(END, f"使用されているインデックス:\n")
            for idx, count in sorted(idx_stats.items(), 
                                   key=lambda x: x[1], reverse=True)[:20]:
                text_widget.insert(END, f"  Index 0x{idx}: {count}回\n")
                
        text_widget.config(state=DISABLED)
        
    def analyze_command_response(self) -> Dict[str, Any]:
        """コマンドとレスポンスの関係を分析"""
        analysis = {
            'cmd_stats': Counter(),
            'round_trip_count': 0,
            'non_round_trip_count': 0,
            'wkc_stats': Counter(),
            'idx_stats': Counter()
        }
        
        for packet in self.data:
            if packet.get('EtherCAT') and 'EtherCAT_Datagrams' in packet['EtherCAT']:
                for datagram in packet['EtherCAT']['EtherCAT_Datagrams']:
                    # コマンド統計
                    cmd = datagram.get('Cmd', '')
                    if cmd:
                        cmd_desc = self.get_cmd_description(cmd)
                        analysis['cmd_stats'][cmd_desc] += 1
                        
                    # Round Trip統計
                    if datagram.get('RoundTrip') == '1':
                        analysis['round_trip_count'] += 1
                    else:
                        analysis['non_round_trip_count'] += 1
                        
                    # Working Counter統計
                    wkc = datagram.get('WorkingCnt', '')
                    if wkc:
                        analysis['wkc_stats'][wkc] += 1
                        
                    # Index統計
                    idx = datagram.get('Index', '')
                    if idx:
                        analysis['idx_stats'][idx] += 1
                        
        return analysis
        
    def get_cmd_description(self, cmd):
        """コマンドの説明を取得"""
        cmd_dict = {
            "01": "LRW", "02": "LRD", "03": "LWR", "04": "BRD", "05": "BWR",
            "07": "ARMW", "08": "APRD", "09": "APWR", "0a": "APRW",
            "0c": "FPRD", "0d": "FPWR", "0e": "FPRW"
        }
        return cmd_dict.get(cmd.lower(), f"CMD:0x{cmd}")
        
    def create_payload_analysis_tab(self, notebook):
        """ペイロード分析タブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="データペイロード")
        
        # コントロールフレーム
        control_frame = Frame(tab)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        Label(control_frame, text="LogAddr:").pack(side=tk.LEFT, padx=5)
        
        # LogAddr選択
        logaddr_var = tk.StringVar()
        logaddr_combo = ttk.Combobox(control_frame, textvariable=logaddr_var, width=30)
        
        # 使用されているLogAddrを収集
        logaddrs = set()
        for packet in self.data:
            if packet.get('EtherCAT') and 'EtherCAT_Datagrams' in packet['EtherCAT']:
                for datagram in packet['EtherCAT']['EtherCAT_Datagrams']:
                    log_addr = datagram.get('LogAddr', '')
                    if log_addr:
                        if self.board_parser:
                            board_info = self.board_parser.get_formatted_board_info(log_addr)
                        else:
                            board_info = f"0x{log_addr}"
                        logaddrs.add(board_info)
                        
        logaddr_combo['values'] = sorted(list(logaddrs))
        if logaddrs:
            logaddr_combo.current(0)
        logaddr_combo.pack(side=tk.LEFT, padx=5)
        
        analyze_btn = Button(control_frame, text="分析", 
                           command=lambda: self.analyze_payload(tab, logaddr_var.get()))
        analyze_btn.pack(side=tk.LEFT, padx=5)
        
        # 結果表示エリア
        result_frame = Frame(tab)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
    def analyze_payload(self, parent_tab, selected_logaddr):
        """特定のLogAddrのペイロードを分析"""
        # 結果フレームをクリア
        for widget in parent_tab.winfo_children():
            if isinstance(widget, Frame) and widget != parent_tab.winfo_children()[0]:
                widget.destroy()
                
        result_frame = Frame(parent_tab)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # スクロール可能なテキストエリア
        text_frame = Frame(result_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget = Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)
        
        # 選択されたLogAddrのデータを収集
        payload_data = []
        for packet in self.data:
            if packet.get('EtherCAT') and 'EtherCAT_Datagrams' in packet['EtherCAT']:
                for datagram in packet['EtherCAT']['EtherCAT_Datagrams']:
                    log_addr = datagram.get('LogAddr', '')
                    if log_addr:
                        if self.board_parser:
                            board_info = self.board_parser.get_formatted_board_info(log_addr)
                        else:
                            board_info = f"0x{log_addr}"
                            
                        if board_info == selected_logaddr:
                            payload_data.append({
                                'packet_no': packet['No'],
                                'time': packet['Time'],
                                'cmd': datagram.get('Cmd', ''),
                                'data': datagram.get('Data', ''),
                                'wkc': datagram.get('WorkingCnt', '')
                            })
                            
        # 結果を表示
        text_widget.insert(END, f"=== {selected_logaddr} のペイロード分析 ===\n\n")
        text_widget.insert(END, f"総データグラム数: {len(payload_data)}\n\n")
        
        if payload_data:
            # データ変化の検出
            text_widget.insert(END, "【データ変化検出】\n")
            prev_data = None
            change_count = 0
            
            for i, entry in enumerate(payload_data[:100]):  # 最初の100個のみ表示
                if prev_data and prev_data != entry['data']:
                    change_count += 1
                    text_widget.insert(END, f"\nパケット#{entry['packet_no']} ({entry['time']}):\n")
                    text_widget.insert(END, f"  コマンド: 0x{entry['cmd']}\n")
                    text_widget.insert(END, f"  前のデータ: {prev_data[:64]}{'...' if len(prev_data) > 64 else ''}\n")
                    text_widget.insert(END, f"  新しいデータ: {entry['data'][:64]}{'...' if len(entry['data']) > 64 else ''}\n")
                    text_widget.insert(END, f"  WKC: 0x{entry['wkc']}\n")
                    
                prev_data = entry['data']
                
            text_widget.insert(END, f"\n\nデータ変化回数: {change_count}\n")
            
            # データパターン分析
            text_widget.insert(END, "\n【データパターン分析】\n")
            data_patterns = Counter()
            for entry in payload_data:
                if entry['data']:
                    # 最初の8バイトをパターンとして使用
                    pattern = entry['data'][:16]
                    data_patterns[pattern] += 1
                    
            text_widget.insert(END, "頻出データパターン（先頭8バイト）:\n")
            for pattern, count in data_patterns.most_common(10):
                text_widget.insert(END, f"  {pattern}: {count}回\n")
                
        text_widget.config(state=DISABLED)
        
    def create_error_analysis_tab(self, notebook):
        """エラー分析タブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="エラー分析")
        
        # エラー分析を実行
        error_analysis = self.analyze_errors()
        
        # 結果表示
        display_frame = Frame(tab)
        display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # テキストエリア
        text_frame = Frame(display_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget = Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)
        
        # エラー分析結果を表示
        text_widget.insert(END, "=== エラー・異常分析 ===\n\n")
        
        # タイムアウト候補
        text_widget.insert(END, "【大きな時間差（タイムアウト候補）】\n")
        for entry in error_analysis['timeouts']:
            text_widget.insert(END, f"パケット#{entry['packet_no']}: {entry['time_diff']:.3f}ms\n")
            text_widget.insert(END, f"  時刻: {entry['time']}\n")
            text_widget.insert(END, f"  情報: {entry['info']}\n\n")
            
        # Working Counter異常
        text_widget.insert(END, "\n【Working Counter異常値】\n")
        for wkc, packets in error_analysis['abnormal_wkc'].items():
            if wkc != '0000' and len(packets) < 10:  # 稀なWKC値
                text_widget.insert(END, f"WKC=0x{wkc}: {len(packets)}パケット\n")
                for pkt in packets[:5]:
                    text_widget.insert(END, f"  パケット#{pkt}\n")
                    
        # 再送の可能性
        text_widget.insert(END, "\n【同一データの連続送信（再送の可能性）】\n")
        for entry in error_analysis['retransmissions']:
            text_widget.insert(END, f"パケット#{entry['packet_no1']} と #{entry['packet_no2']}\n")
            text_widget.insert(END, f"  LogAddr: {entry['logaddr']}\n")
            text_widget.insert(END, f"  データ: {entry['data'][:32]}...\n\n")
            
        text_widget.config(state=DISABLED)
        
    def analyze_errors(self) -> Dict[str, Any]:
        """エラーや異常を分析"""
        analysis = {
            'timeouts': [],
            'abnormal_wkc': defaultdict(list),
            'retransmissions': []
        }
        
        # タイムアウト検出（時間差が大きいパケット）
        for packet in self.data:
            time_diff = packet.get('TimeDiff')
            if time_diff and time_diff > 10.0:  # 10ms以上の遅延
                analysis['timeouts'].append({
                    'packet_no': packet['No'],
                    'time': packet['Time'],
                    'time_diff': time_diff,
                    'info': packet.get('Info', '')
                })
                
        # Working Counter異常
        for packet in self.data:
            if packet.get('EtherCAT') and 'EtherCAT_Datagrams' in packet['EtherCAT']:
                for datagram in packet['EtherCAT']['EtherCAT_Datagrams']:
                    wkc = datagram.get('WorkingCnt', '')
                    if wkc:
                        analysis['abnormal_wkc'][wkc].append(packet['No'])
                        
        # 再送検出（同一データの連続送信）
        prev_datagrams = {}
        for i, packet in enumerate(self.data):
            if packet.get('EtherCAT') and 'EtherCAT_Datagrams' in packet['EtherCAT']:
                for datagram in packet['EtherCAT']['EtherCAT_Datagrams']:
                    log_addr = datagram.get('LogAddr', '')
                    data = datagram.get('Data', '')
                    
                    if log_addr and data:
                        key = (log_addr, data)
                        if key in prev_datagrams and i - prev_datagrams[key]['idx'] < 5:
                            analysis['retransmissions'].append({
                                'packet_no1': prev_datagrams[key]['packet_no'],
                                'packet_no2': packet['No'],
                                'logaddr': log_addr,
                                'data': data
                            })
                        prev_datagrams[key] = {'idx': i, 'packet_no': packet['No']}
                        
        # 最初の10件のみに制限
        analysis['timeouts'] = analysis['timeouts'][:10]
        analysis['retransmissions'] = analysis['retransmissions'][:10]
        
        return analysis
        
    def create_summary_tab(self, notebook):
        """サマリータブを作成"""
        tab = Frame(notebook)
        notebook.add(tab, text="サマリー")
        
        # サマリー情報を計算
        summary = self.calculate_summary()
        
        # 表示
        text_frame = Frame(tab)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget = Text(text_frame, wrap=tk.WORD, font=("Arial", 11))
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        text_widget.insert(END, "=== データ解析サマリー ===\n\n")
        
        text_widget.insert(END, f"【基本統計】\n")
        text_widget.insert(END, f"総パケット数: {summary['total_packets']}\n")
        text_widget.insert(END, f"EtherCATパケット数: {summary['ethercat_packets']}\n")
        text_widget.insert(END, f"総データグラム数: {summary['total_datagrams']}\n")
        text_widget.insert(END, f"ユニークなノード数: {summary['unique_nodes']}\n")
        text_widget.insert(END, f"ユニークなLogAddr数: {summary['unique_logaddrs']}\n\n")
        
        text_widget.insert(END, f"【時間統計】\n")
        text_widget.insert(END, f"記録時間: {summary['duration']:.3f}秒\n")
        text_widget.insert(END, f"平均パケット間隔: {summary['avg_interval']:.3f}ms\n")
        text_widget.insert(END, f"最大パケット間隔: {summary['max_interval']:.3f}ms\n\n")
        
        text_widget.insert(END, f"【通信パターン】\n")
        text_widget.insert(END, f"最も活発な送信元: {summary['most_active_src']}\n")
        text_widget.insert(END, f"最も使用されたコマンド: {summary['most_used_cmd']}\n")
        text_widget.insert(END, f"最もアクセスされたLogAddr: {summary['most_accessed_logaddr']}\n\n")
        
        text_widget.insert(END, f"【データ品質】\n")
        text_widget.insert(END, f"タイムアウト候補: {summary['timeout_count']}件\n")
        text_widget.insert(END, f"データ変更頻度: {summary['data_change_rate']:.1f}%\n")
        
        text_widget.config(state=DISABLED)
        
    def calculate_summary(self) -> Dict[str, Any]:
        """サマリー情報を計算"""
        summary = {
            'total_packets': len(self.data),
            'ethercat_packets': 0,
            'total_datagrams': 0,
            'unique_nodes': set(),
            'unique_logaddrs': set(),
            'duration': 0,
            'avg_interval': 0,
            'max_interval': 0,
            'most_active_src': '',
            'most_used_cmd': '',
            'most_accessed_logaddr': '',
            'timeout_count': 0,
            'data_change_rate': 0
        }
        
        src_counter = Counter()
        cmd_counter = Counter()
        logaddr_counter = Counter()
        time_diffs = []
        
        for packet in self.data:
            # 基本カウント
            if packet.get('EtherCAT'):
                summary['ethercat_packets'] += 1
                
                if 'EtherCAT_Datagrams' in packet['EtherCAT']:
                    summary['total_datagrams'] += len(packet['EtherCAT']['EtherCAT_Datagrams'])
                    
                    for datagram in packet['EtherCAT']['EtherCAT_Datagrams']:
                        # コマンド統計
                        cmd = datagram.get('Cmd', '')
                        if cmd:
                            cmd_desc = self.get_cmd_description(cmd)
                            cmd_counter[cmd_desc] += 1
                            
                        # LogAddr統計
                        log_addr = datagram.get('LogAddr', '')
                        if log_addr:
                            summary['unique_logaddrs'].add(log_addr)
                            if self.board_parser:
                                board_info = self.board_parser.get_formatted_board_info(log_addr)
                            else:
                                board_info = f"0x{log_addr}"
                            logaddr_counter[board_info] += 1
                            
            # ノード統計
            src = packet.get('Source')
            dst = packet.get('Destination')
            if src:
                summary['unique_nodes'].add(src)
                src_counter[src] += 1
            if dst:
                summary['unique_nodes'].add(dst)
                
            # 時間統計
            time_diff = packet.get('TimeDiff')
            if time_diff:
                time_diffs.append(time_diff)
                if time_diff > 10.0:
                    summary['timeout_count'] += 1
                    
        # 集計
        summary['unique_nodes'] = len(summary['unique_nodes'])
        summary['unique_logaddrs'] = len(summary['unique_logaddrs'])
        
        if self.data:
            # 記録時間
            first_time = self.data[0].get('Timestamp', 0)
            last_time = self.data[-1].get('Timestamp', 0)
            summary['duration'] = last_time - first_time
            
        if time_diffs:
            summary['avg_interval'] = sum(time_diffs) / len(time_diffs)
            summary['max_interval'] = max(time_diffs)
            
        if src_counter:
            summary['most_active_src'] = src_counter.most_common(1)[0][0]
            
        if cmd_counter:
            summary['most_used_cmd'] = cmd_counter.most_common(1)[0][0]
            
        if logaddr_counter:
            summary['most_accessed_logaddr'] = logaddr_counter.most_common(1)[0][0]
            
        return summary