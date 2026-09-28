"""Windows Wi-Fi discovery and advertised PHY capability viewer."""

import csv
import asyncio
from datetime import datetime
import json
from pathlib import Path
import sys
import threading
import time

from PySide6.QtCore import QThread, QTimer, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QPainter, QPen
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout,
                               QFrame, QGroupBox, QHBoxLayout,
                               QLabel, QLineEdit, QMainWindow, QMessageBox,
                               QPushButton, QSpinBox, QSplitter, QTabWidget, QTableWidget,
                               QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
                               QHeaderView, QGraphicsScene, QGraphicsView)

from analyzer import channel_analysis
from frame_logic import normalize_mac
from monitor_engine import CHANNELS, CaptureOptions, MonitorEngine
from native_wifi import WifiApi


STYLE = """
QMainWindow, QWidget#root { background: #f3f6fb; color: #1d2b3a; }
QWidget { font-family: 'Segoe UI'; font-size: 10pt; }
QLabel#pageTitle { color: #16283c; font-size: 19pt; font-weight: 700; }
QLabel#subtitle, QLabel#helpText { color: #607286; }
QLabel#summary { color: #385b76; padding: 5px 2px; }
QLabel#statusPill { color: #075e55; background: #d9f5ea; border-radius: 11px;
                    padding: 5px 12px; font-size: 9pt; font-weight: 700; }
QLabel#statusPill[state="recording"] { color: #8b4800; background: #ffedce; }
QLabel#statusPill[state="error"] { color: #922d35; background: #fce6e8; }
QLabel#statusPill[state="stopped"] { color: #536679; background: #e2eaf1; }
QFrame#toolbar, QFrame#captureCard, QFrame#eventCard {
    background: #ffffff; border: 1px solid #dce5ef; border-radius: 11px;
}
QFrame#toolbar { padding: 5px; }
QTabWidget::pane { background: #ffffff; border: 1px solid #dce5ef;
                   border-radius: 8px; top: -1px; }
QTabBar::tab { background: #e9eef5; color: #496176; border: 1px solid #dce5ef;
               padding: 10px 20px; min-width: 85px; }
QTabBar::tab:selected { background: #ffffff; color: #145e78;
                        border-bottom: 2px solid #1594a6; font-weight: 600; }
QTabBar::tab:hover:!selected { background: #dceaf3; }
QGroupBox { border: 1px solid #e1e9f1; border-radius: 8px; margin-top: 14px;
            padding: 14px 12px 12px 12px; font-weight: 600; color: #304b61; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
QLineEdit, QComboBox, QSpinBox, QTextEdit, QTableWidget, QGraphicsView {
    background: #ffffff; color: #213547; border: 1px solid #cfdae6;
    border-radius: 6px; padding: 6px; selection-background-color: #c8eaf0;
    selection-color: #17334a;
}
QComboBox, QSpinBox, QLineEdit { min-height: 24px; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid #13899c; }
QComboBox:disabled { color: #617387; background: #edf1f5; border-color: #e1e7ee; }
QLineEdit:disabled { color: #9ba9b8; background: #edf1f5; border-color: #e1e7ee; }
QPushButton { color: #255071; background: #ecf3f9; border: 1px solid #cddfe9;
              border-radius: 6px; padding: 8px 13px; font-weight: 600; }
QPushButton:hover { background: #d9edf4; border-color: #7bbcc8; }
QPushButton:disabled { color: #9aa9b6; background: #eff3f6; border-color: #e1e7ed; }
QPushButton#primaryButton { color: white; background: #087b8f; border-color: #087b8f; }
QPushButton#primaryButton:hover { background: #07697c; }
QPushButton#primaryButton:disabled { color: #99a9b7; background: #e8edf2;
                                     border-color: #dce4eb; }
QTableWidget { alternate-background-color: #f5f9fc; gridline-color: #edf1f5; }
QTableWidget::item { padding: 4px; }
QTableWidget::item:selected { background: #d2ebf0; color: #17334a; }
QHeaderView::section { background: #edf3f8; color: #38536a; border: 0;
                       border-bottom: 1px solid #dce5ee; padding: 9px 7px;
                       font-weight: 600; }
QStatusBar { color: #4b6478; background: #e9f0f6; }
QSplitter::handle { background: #e4ebf2; }
"""


class ScanWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, selected_guid=None, active_scan=True):
        super().__init__()
        self.selected_guid = selected_guid
        self.active_scan = active_scan

    def run(self):
        try:
            with WifiApi() as api:
                interfaces = api.interfaces()
                selected = next((i for i in interfaces if i[0] == self.selected_guid), None)
                if not selected:
                    selected = next((i for i in interfaces if "A9000" in i[1].upper()), None)
                if not selected:
                    selected = interfaces[0] if interfaces else None
                if selected is None:
                    self.completed.emit((interfaces, None, []))
                    return
                if self.active_scan:
                    api.scan(selected[0])
                    # WlanScan returns before results arrive; short wait, then read BSS cache.
                    time.sleep(4)
                networks = api.bss_list(selected[0], selected[1])
                self.completed.emit((interfaces, selected[0], networks))
        except Exception as exc:
            self.failed.emit(str(exc))


class MonitorWorker(QThread):
    message = Signal(str, object)

    def __init__(self):
        super().__init__()
        self.stop_requested = threading.Event()
        self.engine = MonitorEngine(lambda name, value: self.message.emit(name, value))

    def run(self):
        asyncio.run(self.engine.run(self.stop_requested.is_set))

    def submit(self, action, value=None):
        self.engine.submit(action, value)

    def stop(self):
        self.stop_requested.set()


class ChannelView(QWidget):
    """A BSSID count and approximate occupied-frequency view for each band."""

    def __init__(self):
        super().__init__()
        self.networks = []
        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Band"))
        self.band = QComboBox()
        self.band.addItems(["2.4 GHz", "5 GHz", "6 GHz"])
        self.band.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.band)
        controls.addStretch()
        layout.addLayout(controls)
        self.overview = QLabel()
        self.overview.setWordWrap(True)
        layout.addWidget(self.overview)
        self.groups = QTableWidget(0, 6)
        self.groups.setHorizontalHeaderLabels(["Primary channel", "MHz", "BSSIDs",
                                               "Other primary overlap", "Strongest RSSI",
                                               "Widths unknown"])
        self.groups.setEditTriggers(QTableWidget.NoEditTriggers)
        self.groups.verticalHeader().setVisible(False)
        self.groups.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.groups.setMaximumHeight(220)
        layout.addWidget(self.groups)
        self.legend = QLabel("Red: shared primary channel · Amber: overlaps another primary · "
                             "Teal: no overlap in shown footprint · Dashed border: actual width unknown")
        self.legend.setWordWrap(True)
        layout.addWidget(self.legend)
        self.scene = QGraphicsScene(self)
        self.chart = QGraphicsView(self.scene)
        self.chart.setRenderHint(QPainter.Antialiasing)
        layout.addWidget(self.chart, 1)
        self.note = QLabel("Each row is a BSSID, not necessarily a separate physical AP. "
                           "Frequency overlap indicates possible contention; it does not measure airtime, "
                           "interference, or channel utilization. Widths not decoded may hide more overlap.")
        self.note.setWordWrap(True)
        layout.addWidget(self.note)
        self.refresh()

    def set_networks(self, networks):
        self.networks = networks
        self.refresh()

    def refresh(self):
        selected = [n for n in self.networks if n.band == self.band.currentText()]
        selected.sort(key=lambda n: (n.frequency_mhz, -n.rssi_dbm, n.ssid))
        footprints, shared, adjacent = channel_analysis(selected)
        active = sum(bool(shared[i] or adjacent[i]) for i in range(len(selected)))
        estimated = sum(f.estimated for f in footprints)
        self.overview.setText(f"{len(selected)} BSSIDs · {active} have overlap in shown footprints · "
                              f"{estimated} widths unknown (minimum shown)")

        groups = {}
        for i, n in enumerate(selected):
            groups.setdefault((n.frequency_mhz, n.channel), []).append(i)
        self.groups.setRowCount(0)
        for (frequency, channel), indices in sorted(groups.items()):
            row = self.groups.rowCount()
            self.groups.insertRow(row)
            other = {j for i in indices for j in adjacent[i]}
            values = [channel, frequency, len(indices), len(other),
                      max(selected[i].rssi_dbm for i in indices),
                      sum(footprints[i].estimated for i in indices)]
            for col, value in enumerate(values):
                item = QTableWidgetItem()
                item.setData(Qt.DisplayRole, value)
                self.groups.setItem(row, col, item)

        self.scene.clear()
        if not selected:
            self.scene.addText("No access points detected in this band.")
            self.scene.setSceneRect(0, 0, 850, 100)
            return
        lows = [low for f in footprints for low, _ in f.ranges]
        highs = [high for f in footprints for _, high in f.ranges]
        left = min(lows) - 10
        right = max(highs) + 10
        if selected[0].band == "2.4 GHz":
            left, right = min(left, 2400), max(right, 2495)
        graph_x, graph_width = 260, 970
        scale = graph_width / max(1, right - left)
        scene_width = graph_x + graph_width + 35
        scene_height = 66 + len(selected) * 30
        self.scene.setSceneRect(0, 0, scene_width, scene_height)
        tick = 10 if right - left < 140 else 20 if right - left < 280 else 50
        first_tick = int(left // tick + 1) * tick
        for mhz in range(first_tick, int(right) + 1, tick):
            x = graph_x + (mhz - left) * scale
            self.scene.addLine(x, 29, x, scene_height - 9,
                               QPen(QColor("#e2e8ee"), 1))
            label = self.scene.addText(str(mhz))
            label.setDefaultTextColor(QColor("#4b5563"))
            label.setPos(x - 16, 4)

        for i, n in enumerate(selected):
            y = 50 + i * 30
            color = (QColor("#d95454") if shared[i] else
                     QColor("#e5a33f") if adjacent[i] else QColor("#44a6a0"))
            label = self.scene.addText(f"{n.ssid[:19]:19}  ch {n.channel}")
            label.setDefaultTextColor(QColor("#263240"))
            label.setPos(0, y - 5)
            for low, high in footprints[i].ranges:
                x = graph_x + (low - left) * scale
                pen = QPen(color.darker(125), 1.4,
                           Qt.DashLine if footprints[i].estimated else Qt.SolidLine)
                rect = self.scene.addRect(x, y, max(3, (high - low) * scale), 19,
                                          pen, QBrush(color))
                rect.setToolTip(f"{n.ssid} · {n.bssid}\nPrimary ch {n.channel} · "
                                f"{n.rssi_dbm} dBm\n{footprints[i].description}\n"
                                f"Shown range {low:g}–{high:g} MHz\n"
                                f"Shared primary: {len(shared[i])} · "
                                f"Other primary overlap: {len(adjacent[i])}")


class MainWindow(QMainWindow):
    COLUMNS = ["SSID", "BSSID", "Band", "Channel", "MHz", "RSSI dBm",
               "Advertised PHY", "Width", "Security hint", "Driver PHY"]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("A9000 Capture Tool")
        self.resize(1450, 860)
        self.setStyleSheet(STYLE)
        self.networks = []
        self.visible = []
        self.worker = None
        self.interfaces = []
        self.radio = MonitorWorker()
        self.radio.message.connect(self.monitor_message)
        self.radio_ready = False
        self.capturing = False
        self.last_a9000_networks = []
        self.ap_channels = {}
        self.native_networks = []

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(18, 14, 18, 12)
        layout.setSpacing(9)
        heading = QHBoxLayout()
        title_column = QVBoxLayout()
        title_column.setSpacing(0)
        title = QLabel("A9000 Capture Tool")
        title.setObjectName("pageTitle")
        title_column.addWidget(title)
        subtitle = QLabel("Passive 802.11 capture, radio discovery and channel overlap")
        subtitle.setObjectName("subtitle")
        title_column.addWidget(subtitle)
        heading.addLayout(title_column)
        heading.addStretch()
        self.status_pill = QLabel("STARTING")
        self.status_pill.setObjectName("statusPill")
        heading.addWidget(self.status_pill)
        layout.addLayout(heading)
        toolbar = QFrame()
        toolbar.setObjectName("toolbar")
        layout.addWidget(toolbar)
        controls = QHBoxLayout(toolbar)
        controls.setContentsMargins(10, 8, 10, 8)
        controls.setSpacing(9)
        controls.addWidget(QLabel("Discovery source"))
        self.adapter = QComboBox()
        self.adapter.setMinimumWidth(310)
        self.adapter.addItem("A9000 · passive USB monitor", "a9000")
        self.adapter.currentIndexChanged.connect(self.change_adapter)
        controls.addWidget(self.adapter)
        controls.addWidget(QLabel("Auto survey"))
        self.interval = QComboBox()
        for seconds in (10, 15, 30, 60, 120, 300):
            self.interval.addItem(f"Every {seconds} s", seconds)
        self.interval.setCurrentIndex(1)
        self.interval.setToolTip("A9000 interval is measured after a sweep finishes. "
                                 "Windows WLAN scans stay at least 30 seconds apart.")
        self.interval.currentIndexChanged.connect(self.change_interval)
        controls.addWidget(self.interval)
        self.export_button = QPushButton("Export JSON")
        self.export_button.clicked.connect(self.export_json)
        controls.addWidget(self.export_button)
        self.csv_button = QPushButton("Export CSV")
        self.csv_button.clicked.connect(self.export_csv)
        controls.addWidget(self.csv_button)
        controls.addStretch()
        controls.addWidget(QLabel("Filter"))
        self.filter_text = QLineEdit()
        self.filter_text.setPlaceholderText("SSID, BSSID, band, channel, PHY…")
        self.filter_text.setMinimumWidth(215)
        self.filter_text.textChanged.connect(self.populate)
        controls.addWidget(self.filter_text)
        self.summary = QLabel("Starting A9000 passive monitor...")
        self.summary.setObjectName("summary")
        layout.addWidget(self.summary)
        main_tabs = QTabWidget()
        layout.addWidget(main_tabs, 1)
        split = QSplitter(Qt.Vertical)
        main_tabs.addTab(split, "Networks")
        self.channel_view = ChannelView()
        main_tabs.addTab(self.channel_view, "Channel overlaps")
        main_tabs.addTab(self.create_capture_tab(), "Capture")
        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self.show_selected)
        split.addWidget(self.table)

        tabs = QTabWidget()
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.elements = QTableWidget(0, 3)
        self.elements.setHorizontalHeaderLabels(["ID", "Information element", "Value (hex)"])
        self.elements.setEditTriggers(QTableWidget.NoEditTriggers)
        self.elements.setAlternatingRowColors(True)
        self.elements.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.elements.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.raw = QTextEdit()
        self.raw.setReadOnly(True)
        self.raw.setFontFamily("Consolas")
        tabs.addTab(self.details, "BSS details")
        tabs.addTab(self.elements, "Information elements")
        tabs.addTab(self.raw, "IE bytes")
        split.addWidget(tabs)
        split.setSizes([470, 250])
        self.statusBar().showMessage("Starting monitor · auto survey every 15 s")
        self.native_timer = QTimer(self)
        self.native_timer.timeout.connect(self.auto_native_scan)
        self.native_timer.start(30_000)
        self.radio.start()
        QTimer.singleShot(1200, lambda: self.start_scan(False))

    def create_capture_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)
        lead = QLabel("Capture a connection")
        lead.setObjectName("pageTitle")
        layout.addWidget(lead)
        lead = QLabel("Listen on one channel and save a Wireshark PCAP. "
                      "Select an access point in Networks to prefill the controls. "
                      "Surveys pause during recording.")
        lead.setObjectName("helpText")
        lead.setWordWrap(True)
        layout.addWidget(lead)
        card = QFrame()
        card.setObjectName("captureCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 14, 16, 16)
        settings = QHBoxLayout()
        settings.setSpacing(18)
        radio_group = QGroupBox("RADIO & ACCESS POINT")
        radio_form = QFormLayout(radio_group)
        radio_form.setSpacing(10)
        settings.addWidget(radio_group, 1)
        self.capture_channel = QComboBox()
        for ch in CHANNELS:
            self.capture_channel.addItem(f"{ch} · {'2.4' if ch <= 14 else '5'} GHz", ch)
        self.capture_channel.setCurrentIndex(self.capture_channel.findData(6))
        radio_form.addRow("Primary channel", self.capture_channel)
        self.limit_bssid = QCheckBox("Save only packets from one access point")
        self.limit_bssid.toggled.connect(self.update_ap_filter)
        radio_form.addRow("AP filter", self.limit_bssid)
        self.capture_bssid = QComboBox()
        self.capture_bssid.setMinimumWidth(290)
        self.capture_bssid.addItem("Waiting for A9000 survey…", None)
        self.capture_bssid.setEnabled(False)
        self.capture_bssid.currentIndexChanged.connect(self.select_capture_ap)
        radio_form.addRow("Access point", self.capture_bssid)
        self.ap_filter_hint = QLabel("AP filter off · BSSID does not limit capture")
        self.ap_filter_hint.setObjectName("helpText")
        radio_form.addRow("", self.ap_filter_hint)
        self.capture_client = QLineEdit()
        self.capture_client.setPlaceholderText("Optional phone/client MAC · leave empty for everyone")
        radio_form.addRow("Client filter", self.capture_client)

        file_group = QGroupBox("RECORDING")
        file_form = QFormLayout(file_group)
        file_form.setSpacing(10)
        settings.addWidget(file_group, 1)
        self.capture_scope = QComboBox()
        self.capture_scope.addItems(["All frames", "Connection frames"])
        file_form.addRow("Frame scope", self.capture_scope)
        self.capture_seconds = QSpinBox()
        self.capture_seconds.setRange(0, 86_400)
        self.capture_seconds.setValue(90)
        self.capture_seconds.setSuffix(" s (0 = until Stop)")
        file_form.addRow("Duration", self.capture_seconds)
        file_controls = QHBoxLayout()
        self.capture_output = QLineEdit()
        self.capture_output.setText(str(self.default_capture_path()))
        file_controls.addWidget(self.capture_output)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self.browse_capture)
        file_controls.addWidget(browse)
        file_form.addRow("Save as PCAP", file_controls)
        tip = QLabel("All frames preserves surrounding traffic and context. "
                     "Connection frames keeps management packets and EAPOL.")
        tip.setObjectName("helpText")
        tip.setWordWrap(True)
        file_form.addRow("", tip)
        card_layout.addLayout(settings)
        actions = QHBoxLayout()
        self.capture_start = QPushButton("Start passive capture")
        self.capture_start.setObjectName("primaryButton")
        self.capture_start.setEnabled(False)
        self.capture_start.clicked.connect(self.start_capture)
        actions.addWidget(self.capture_start)
        self.capture_stop = QPushButton("Stop and save PCAP")
        self.capture_stop.setEnabled(False)
        self.capture_stop.clicked.connect(lambda: self.radio.submit("stop"))
        actions.addWidget(self.capture_stop)
        actions.addStretch()
        card_layout.addLayout(actions)
        layout.addWidget(card)
        self.capture_status = QLabel("Waiting for A9000…")
        self.capture_status.setWordWrap(True)
        layout.addWidget(self.capture_status)
        event_title = QLabel("Observed connection events")
        event_title.setObjectName("subtitle")
        layout.addWidget(event_title)
        self.capture_log = QTextEdit()
        self.capture_log.setReadOnly(True)
        self.capture_log.setPlaceholderText("Observed connection events appear here. "
                                            "Open the saved PCAP in Wireshark for full packet details.")
        layout.addWidget(self.capture_log, 1)
        note = QLabel("Filters apply to saved packets after reception. For a complete channel "
                      "recording, leave the AP and client filters off. "
                      "Channel changes are paused during capture.")
        note.setObjectName("helpText")
        note.setWordWrap(True)
        layout.addWidget(note)
        return tab

    def update_ap_filter(self, checked):
        self.capture_bssid.setEnabled(checked and self.capture_bssid.count() > 1)
        self.ap_filter_hint.setText(
            ("AP filter on · only this AP's packets are saved" if self.capture_bssid.currentData()
             else "AP filter on · choose an access point above") if checked
            else "AP filter off · BSSID does not limit capture")

    def select_capture_ap(self):
        bssid = self.capture_bssid.currentData()
        self.update_ap_filter(self.limit_bssid.isChecked())
        if bssid:
            network = next((n for n in self.last_a9000_networks if n.bssid == bssid), None)
            if network:
                index = self.capture_channel.findData(int(network.channel))
                if index >= 0:
                    self.capture_channel.setCurrentIndex(index)

    def refresh_ap_choices(self, networks):
        previous = self.capture_bssid.currentData()
        previous_label = self.capture_bssid.currentText()
        unique = {n.bssid: n for n in networks if self.capture_channel.findData(
            int(n.channel)) >= 0}
        self.capture_bssid.blockSignals(True)
        self.capture_bssid.clear()
        self.capture_bssid.addItem("Choose an AP (SSID · BSSID)", None)
        for bssid, n in sorted(unique.items(), key=lambda item: (
                item[1].ssid.casefold(), int(item[1].channel), item[0])):
            self.capture_bssid.addItem(f"{n.ssid}  ·  {bssid}  ·  ch {n.channel}", bssid)
        if previous and previous not in unique:
            self.capture_bssid.addItem(
                f"{previous_label.removesuffix('  (previously seen)')}  (previously seen)",
                previous)
        if not unique and not previous:
            self.capture_bssid.setItemText(0, "No APs seen yet · wait for next survey")
        index = self.capture_bssid.findData(previous)
        self.capture_bssid.setCurrentIndex(index if index >= 0 else 0)
        self.capture_bssid.blockSignals(False)
        self.update_ap_filter(self.limit_bssid.isChecked())

    @staticmethod
    def default_capture_path():
        return Path.cwd() / f"a9000_{datetime.now():%Y%m%d_%H%M%S}.pcap"

    def browse_capture(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save monitor capture",
                                              self.capture_output.text(), "PCAP (*.pcap)")
        if path:
            self.capture_output.setText(path)

    def start_capture(self):
        try:
            channel = self.capture_channel.currentData()
            output = Path(self.capture_output.text().strip()).expanduser()
            if not str(output).lower().endswith(".pcap"):
                raise ValueError("Choose a filename ending in .pcap")
            if output.exists():
                raise FileExistsError(f"A file already exists at {output}; choose a new filename")
            if not output.parent.is_dir():
                raise ValueError("The output directory does not exist")
            bssid = self.capture_bssid.currentData() if self.limit_bssid.isChecked() else ""
            if self.limit_bssid.isChecked() and not bssid:
                raise ValueError("Wait for a survey and select an access point to enable its filter")
            if bssid and self.ap_channels.get(bssid) != channel:
                raise ValueError(f"Selected AP was seen on channel {self.ap_channels[bssid]}; "
                                 "select that channel or turn off the AP filter")
            client = normalize_mac(self.capture_client.text()) if self.capture_client.text().strip() else ""
            scope = self.capture_scope.currentText()
            options = CaptureOptions(channel, output, self.capture_seconds.value(), scope, bssid, client)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Capture settings", str(exc))
            return
        self.capture_start.setEnabled(False)
        self.capture_status.setText(f"Switching A9000 to channel {channel}...")
        self.radio.submit("capture", options)

    def set_status_badge(self, label, state):
        self.status_pill.setText(label)
        self.status_pill.setProperty("state", state)
        self.status_pill.style().unpolish(self.status_pill)
        self.status_pill.style().polish(self.status_pill)

    def monitor_message(self, name, value):
        if name == "ready":
            self.radio_ready = bool(value)
            if value:
                self.set_status_badge("MONITOR READY", "ready")
            elif self.status_pill.text() != "ERROR":
                self.set_status_badge("STOPPED", "stopped")
            self.capture_start.setEnabled(self.radio_ready and not self.capturing)
            if not value:
                self.capture_stop.setEnabled(False)
        elif name == "status":
            self.statusBar().showMessage(str(value))
            if self.capturing:
                self.capture_status.setText(str(value))
            elif not self.networks:
                self.summary.setText(str(value))
        elif name in ("survey_partial", "networks"):
            if name == "survey_partial":
                combined = {n.bssid: n for n in self.last_a9000_networks}
                combined.update((n.bssid, n) for n in value)
                value = list(combined.values())
            self.last_a9000_networks = value
            self.ap_channels.update((n.bssid, int(n.channel)) for n in value)
            self.refresh_ap_choices(value)
            if self.adapter.currentData() == "a9000":
                self.networks = value
                self.refresh_networks()
        elif name == "capture_started":
            self.capturing = True
            self.set_status_badge("RECORDING", "recording")
            self.capture_start.setEnabled(False)
            self.capture_stop.setEnabled(True)
            self.capture_log.clear()
            self.capture_status.setText(f"Recording {value}")
        elif name == "capture_done":
            self.capturing = False
            self.set_status_badge("MONITOR READY", "ready")
            path, counts = value
            self.capture_start.setEnabled(self.radio_ready)
            self.capture_stop.setEnabled(False)
            self.capture_status.setText(f"Saved {counts['frames']} frames to {path}")
            self.capture_log.append(f"Saved {path} · {counts['frames']} frames · "
                                    f"{counts['eapol']} EAPOL")
            self.capture_output.setText(str(self.default_capture_path()))
        elif name == "statistics":
            self.capture_status.setText(
                f"Recording channel {self.capture_channel.currentData()} · {value['frames']} frames "
                f"({value['management']} management, {value['control']} control, "
                f"{value['data']} data; {value['eapol']} EAPOL)")
        elif name == "event":
            when, event, bssid, channel, rssi = value
            self.capture_log.append(f"{when} · ch {channel} · {event} · "
                                    f"{bssid} · {rssi if rssi is not None else '?'} dBm")
        elif name == "error":
            self.set_status_badge("ERROR", "error")
            self.capture_status.setText(str(value))
            self.statusBar().showMessage(f"A9000: {value}")
            self.capture_start.setEnabled(self.radio_ready and not self.capturing)
            if self.adapter.currentData() == "a9000":
                self.summary.setText(f"A9000 error: {value}. Windows WLAN is available as another source.")

    def change_interval(self):
        seconds = self.interval.currentData()
        if seconds:
            if hasattr(self, "native_timer"):
                self.native_timer.setInterval(max(30, seconds) * 1000)
            self.radio.submit("interval", seconds)

    def change_adapter(self):
        if self.adapter.currentData() == "a9000":
            self.networks = self.last_a9000_networks
            self.refresh_networks()
        elif self.adapter.currentData() and not (self.worker and self.worker.isRunning()):
            self.start_scan(False)

    def auto_native_scan(self):
        if self.adapter.currentData() != "a9000" and not self.capturing:
            self.start_scan(True)

    def start_scan(self, active):
        if self.worker and self.worker.isRunning():
            return
        source = self.adapter.currentData()
        if source == "a9000" and self.interfaces:
            return
        if source != "a9000":
            self.summary.setText("Scanning…" if active else "Reading saved Windows scan results…")
        self.worker = ScanWorker(None if source == "a9000" else source,
                                 active and source != "a9000")
        self.worker.completed.connect(self.scan_complete)
        self.worker.failed.connect(self.scan_failed)
        self.worker.start()

    def scan_failed(self, error):
        self.statusBar().showMessage(error)
        if self.adapter.currentData() != "a9000":
            self.summary.setText(f"Windows Wi-Fi scan failed: {error}")

    def scan_complete(self, result):
        interfaces, selected_guid, networks = result
        self.interfaces = interfaces
        original_source = self.adapter.currentData()
        self.adapter.blockSignals(True)
        self.adapter.clear()
        self.adapter.addItem("A9000 · passive USB monitor", "a9000")
        for guid, name, state in interfaces:
            self.adapter.addItem(name + ("" if state == 1 else " (disconnected)") +
                                 " · Windows WLAN", guid)
        index = self.adapter.findData(original_source or selected_guid)
        if index >= 0:
            self.adapter.setCurrentIndex(index)
        self.adapter.blockSignals(False)
        self.native_networks = networks
        if self.adapter.currentData() != "a9000":
            self.networks = networks
            self.refresh_networks()

    def refresh_networks(self):
        self.populate()
        self.channel_view.set_networks(self.networks)

    def populate(self):
        query = self.filter_text.text().lower().strip()
        self.visible = [n for n in self.networks if query in " ".join(
            (n.ssid, n.bssid, n.band, n.channel, n.advertised_phy,
             n.operating_width, n.security_hint)).lower()]
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for n in self.visible:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [n.ssid, n.bssid, n.band, n.channel, n.frequency_mhz,
                      n.rssi_dbm, n.advertised_phy, n.operating_width,
                      n.security_hint, n.driver_phy]
            for col, value in enumerate(values):
                item = QTableWidgetItem()
                item.setData(Qt.DisplayRole, value)
                if col == 0:
                    item.setData(Qt.UserRole, n)
                self.table.setItem(row, col, item)
        self.table.setSortingEnabled(True)
        source = "A9000 passive survey" if self.adapter.currentData() == "a9000" else "Windows WLAN"
        self.summary.setText(f"{len(self.visible)} BSSIDs shown · {len(self.networks)} found · "
                             f"{datetime.now().strftime('%H:%M:%S')} · {source}")
        self.show_selected()

    def show_selected(self):
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        n = item.data(Qt.UserRole) if item else None
        if n is None:
            self.details.clear()
            self.elements.setRowCount(0)
            self.raw.clear()
            return
        if n.interface == "A9000 passive USB":
            index = self.capture_channel.findData(int(n.channel))
            if index >= 0:
                self.capture_channel.setCurrentIndex(index)
            index = self.capture_bssid.findData(n.bssid)
            if index >= 0:
                self.capture_bssid.setCurrentIndex(index)
        quality = f" · Driver signal quality: {n.signal_quality}%" if n.signal_quality >= 0 else ""
        lines = [f"SSID: {n.ssid}", f"BSSID: {n.bssid}", f"Interface: {n.interface}",
                 f"Received on: {n.band}, channel {n.channel}, {n.frequency_mhz:g} MHz",
                 f"RSSI: {n.rssi_dbm} dBm{quality}",
                 f"Advertised PHY: {n.advertised_phy}", f"Driver-reported BSS PHY: {n.driver_phy}",
                 f"Operating width (when decoded): {n.operating_width}",
                 f"Security: {n.security_hint}",
                 f"Beacon interval: {n.beacon_interval_ms:.2f} ms",
                 f"Read at: {n.observed_at}", f"IE count: {len(n.elements)}"]
        if n.warning:
            lines.append(f"Decoder warning: {n.warning}")
        if n.interface == "A9000 passive USB":
            lines.append("\nSurvey entry from an over-the-air beacon or probe response. "
                         "Use Capture for complete raw frames in a Wireshark PCAP.")
        else:
            lines.append("\nInformation elements can be merged by Windows; these are not full raw packets.")
        self.details.setPlainText("\n".join(lines))
        self.elements.setRowCount(len(n.elements))
        for i, element in enumerate(n.elements):
            for col, value in enumerate((str(element.number), element.name, element.hex_data)):
                self.elements.setItem(i, col, QTableWidgetItem(value))
        self.raw.setPlainText(n.ie_hex or "No IE bytes reported by the driver.")

    def export_json(self):
        if not self.networks:
            QMessageBox.information(self, "Nothing to export", "Scan for nearby networks first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export BSS snapshot", "wifi_snapshot.json", "JSON (*.json)")
        if path:
            try:
                Path(path).write_text(json.dumps([n.export() for n in self.networks],
                                                indent=2, ensure_ascii=False), encoding="utf-8")
                self.statusBar().showMessage(f"Exported {len(self.networks)} entries to {path}")
            except OSError as exc:
                QMessageBox.warning(self, "Export failed", str(exc))

    def export_csv(self):
        if not self.networks:
            QMessageBox.information(self, "Nothing to export", "Scan for nearby networks first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export BSS snapshot", "wifi_snapshot.csv", "CSV (*.csv)")
        if path:
            try:
                fields = [k for k in self.networks[0].export() if k != "elements"]
                with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fields)
                    writer.writeheader()
                    for n in self.networks:
                        writer.writerow({key: value for key, value in n.export().items() if key in fields})
                self.statusBar().showMessage(f"Exported {len(self.networks)} entries to {path}")
            except OSError as exc:
                QMessageBox.warning(self, "Export failed", str(exc))

    def closeEvent(self, event):
        self.native_timer.stop()
        self.radio.stop()
        if self.radio.isRunning() and not self.radio.wait(5000):
            event.ignore()
            QTimer.singleShot(500, self.close)
            return
        if self.worker and self.worker.isRunning() and not self.worker.wait(5000):
            event.ignore()
            QTimer.singleShot(500, self.close)
            return
        event.accept()


def main():
    application = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(application.exec())


if __name__ == "__main__":
    main()
