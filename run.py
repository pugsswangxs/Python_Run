import os
import sys
import json
import subprocess
import time
from pathlib import Path

from PyQt6.QtWidgets import (QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem,
                             QSplitter, QTabWidget, QToolBar, QComboBox, QPushButton,
                             QFileDialog, QMessageBox, QMenu, QDialog, QVBoxLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView,
                             QTextEdit, QLabel, QWidget, QStyle, QStatusBar, QInputDialog)
from PyQt6.QtGui import (QAction, QIcon, QTextCursor, QSyntaxHighlighter, QTextCharFormat,
                         QColor, QFont, QTextOption, QDrag)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QRegularExpression, QSize, QMimeData


# ------------------------------ 修复核心：重写QTreeWidget子类处理拖拽事件 ------------------------------
class DragableTreeWidget(QTreeWidget):
    """重写QTreeWidget，实现内部拖拽事件捕获（替代不存在的itemDragXXX信号）"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent  # 保存主窗口引用，用于调用主窗口方法
        # 启用拖拽基础功能
        self.setDragEnabled(True)
        self.setDragDropMode(QTreeWidget.DragDropMode.InternalMove)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)

    def startDrag(self, supported_actions):
        """拖拽开始时调用（替代itemDragStartEvent）"""
        if self.parent_window:
            self.parent_window.on_item_drag_start(self.selectedItems())
        super().startDrag(supported_actions)

    def dragEnterEvent(self, event):
        """拖拽进入时调用（区分内部/外部拖拽）"""
        # 内部拖拽（来自自身）：交给主窗口处理
        if event.source() == self:
            if self.parent_window:
                self.parent_window.on_item_drag_enter(event, self.itemAt(event.position().toPoint()))
        # 外部拖拽（来自文件管理器）：保留原有逻辑
        else:
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
            else:
                event.ignore()

    def dragMoveEvent(self, event):
        """拖拽移动时调用（区分内部/外部拖拽）"""
        if event.source() == self:
            if self.parent_window:
                self.parent_window.on_item_drag_move(event, self.itemAt(event.position().toPoint()))
        else:
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
            else:
                event.ignore()

    def dropEvent(self, event):
        """拖拽结束时调用（区分内部/外部拖拽）"""
        if event.source() == self:
            # 内部拖拽：交给主窗口处理
            if self.parent_window:
                self.parent_window.on_item_drop(event, self.itemAt(event.position().toPoint()))
        else:
            # 外部拖拽：保留原有加载文件夹/文件逻辑
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
                for url in event.mimeData().urls():
                    path = url.toLocalFile()
                    if not os.path.exists(path):
                        continue
                    if os.path.isdir(path):
                        self.parent_window.add_root_node(path)
                        if path in self.parent_window.root_nodes:
                            root_item = self.parent_window.root_nodes[path]
                            while root_item.childCount() > 0:
                                root_item.removeChild(root_item.child(0))
                            self.parent_window.load_folder_contents(root_item, apply_filter=True)
                    elif os.path.isfile(path) and path.endswith('.py'):
                        parent_item = None
                        if self.topLevelItemCount() > 0:
                            parent_item = self.topLevelItem(0)
                        if not parent_item:
                            temp_dir = os.path.dirname(path)
                            self.parent_window.add_root_node(temp_dir)
                            parent_item = self.topLevelItem(0)
                            while parent_item.childCount() > 0:
                                parent_item.removeChild(parent_item.child(0))
                            self.parent_window.load_folder_contents(parent_item, apply_filter=True)
                        self.parent_window.add_file_to_tree(parent_item, path)
                event.accept()
            else:
                event.ignore()


# 配置管理类 - 移除隐藏项目的持久化存储
class ConfigManager:
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.config = {
            "python_paths": [],
            "last_selected_index": 0
        }
        self.load_config()

    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
            except:
                pass

    def save_config(self):
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=4)

    def get_python_paths(self):
        return self.config.get("python_paths", [])

    def get_last_selected_index(self):
        return self.config.get("last_selected_index", 0)

    def set_python_paths(self, paths):
        self.config["python_paths"] = paths
        self.save_config()

    def set_last_selected_index(self, index):
        self.config["last_selected_index"] = index
        self.save_config()


# Python路径管理对话框
class PythonPathDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Python路径管理")
        self.setModal(True)
        self.resize(600, 400)

        self.config = parent.config if parent else ConfigManager()
        self.init_ui()
        self.load_paths()

    def init_ui(self):
        layout = QVBoxLayout()

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["序号", "路径", "是否可用"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("添加")
        self.edit_btn = QPushButton("修改")
        self.delete_btn = QPushButton("删除")
        self.close_btn = QPushButton("关闭")

        for btn in [self.add_btn, self.edit_btn, self.delete_btn, self.close_btn]:
            btn.setMinimumSize(80, 30)

        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.delete_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.close_btn)

        layout.addWidget(self.table)
        layout.addLayout(btn_layout)
        self.setLayout(layout)

        self.add_btn.clicked.connect(self.add_path)
        self.edit_btn.clicked.connect(self.edit_path)
        self.delete_btn.clicked.connect(self.delete_path)
        self.close_btn.clicked.connect(self.accept)

    def load_paths(self):
        paths = self.config.get_python_paths()
        self.table.setRowCount(len(paths))

        for i, path in enumerate(paths):
            self.table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            self.table.setItem(i, 1, QTableWidgetItem(path))

            is_available = os.path.exists(path) and os.access(path, os.X_OK)
            item = QTableWidgetItem("是" if is_available else "否")
            item.setForeground(QColor("green") if is_available else QColor("red"))
            self.table.setItem(i, 2, item)

    def add_path(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择Python解释器", "", "可执行文件 (*.exe);;所有文件 (*)"
        )
        if file_path:
            paths = self.config.get_python_paths()
            if file_path not in paths:
                paths.append(file_path)
                self.config.set_python_paths(paths)
                self.load_paths()

    def edit_path(self):
        current_row = self.table.currentRow()
        if current_row < 0:
            return

        old_path = self.config.get_python_paths()[current_row]
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择Python解释器", old_path, "可执行文件 (*.exe);;所有文件 (*)"
        )
        if file_path:
            paths = self.config.get_python_paths()
            paths[current_row] = file_path
            self.config.set_python_paths(paths)
            self.load_paths()

    def delete_path(self):
        current_row = self.table.currentRow()
        if current_row < 0:
            return

        paths = self.config.get_python_paths()
        if current_row < len(paths):
            paths.pop(current_row)
            self.config.set_python_paths(paths)
            self.load_paths()


# 代码编辑器类
class CodeEditor(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighter = PythonHighlighter(self.document())
        self.setFont(QFont("Consolas", 10))
        self.setTabStopDistance(40)

    def set_content(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.setText(f.read())
        except Exception as e:
            self.setText(f"无法读取文件: {str(e)}")


# Python语法高亮
class PythonHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)

        self.highlighting_rules = []

        # 关键字格式
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569CD6"))
        keyword_format.setFontWeight(QFont.Weight.Bold)

        keywords = [
            "and", "as", "assert", "break", "class", "continue", "def", "del",
            "elif", "else", "except", "False", "finally", "for", "from", "global",
            "if", "import", "in", "is", "lambda", "None", "nonlocal", "not", "or",
            "pass", "raise", "return", "True", "try", "while", "with", "yield"
        ]

        for word in keywords:
            pattern = QRegularExpression(f"\\b{word}\\b")
            self.highlighting_rules.append((pattern, keyword_format))

        # 字符串格式
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#CE9178"))
        self.highlighting_rules.append((QRegularExpression("\".*\""), string_format))
        self.highlighting_rules.append((QRegularExpression("'.*'"), string_format))

        # 注释格式
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6A9955"))
        self.highlighting_rules.append((QRegularExpression("#[^\n]*"), comment_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            match_iterator = pattern.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)


# 日志输出高亮
class LogHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)

        self.highlighting_rules = []

        # 错误信息格式
        error_format = QTextCharFormat()
        error_format.setForeground(QColor("red"))
        error_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((QRegularExpression("(?i)error|exception|fail|traceback"), error_format))

        # 警告信息格式
        warning_format = QTextCharFormat()
        warning_format.setForeground(QColor("orange"))
        self.highlighting_rules.append((QRegularExpression("(?i)warning|deprecation"), warning_format))

        # 成功信息格式
        success_format = QTextCharFormat()
        success_format.setForeground(QColor("green"))
        self.highlighting_rules.append((QRegularExpression("(?i)success|complete|done|finished"), success_format))

        # 时间戳格式
        time_format = QTextCharFormat()
        time_format.setForeground(QColor("gray"))
        self.highlighting_rules.append((QRegularExpression("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}"), time_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            match_iterator = pattern.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)


# 目录加载线程
class DirectoryLoader(QThread):
    update_signal = pyqtSignal(object, list, list)  # 父项, 文件夹列表, 文件列表
    error_signal = pyqtSignal(object, str)  # 父项, 错误信息

    def __init__(self, parent_item, folder_path, hidden_items, apply_filter):
        super().__init__()
        self.parent_item = parent_item
        self.folder_path = folder_path
        self.hidden_items = hidden_items
        self.apply_filter = apply_filter

    def run(self):
        try:
            if not os.path.exists(self.folder_path):
                self.error_signal.emit(self.parent_item, "目录不存在")
                return

            if not os.path.isdir(self.folder_path):
                self.error_signal.emit(self.parent_item, "不是有效目录")
                return

            entries = os.listdir(self.folder_path)
            if not entries:
                self.error_signal.emit(self.parent_item, "空目录")
                return

            folders = []
            files = []

            for entry in entries:
                full_path = os.path.join(self.folder_path, entry)
                abs_path = os.path.abspath(full_path)

                # 应用过滤时跳过隐藏项目
                if self.apply_filter and abs_path in self.hidden_items:
                    continue

                # 跳过隐藏文件（以点开头）
                if entry.startswith('.'):
                    continue

                try:
                    if os.path.isdir(full_path):
                        # 检查文件夹是否包含Python文件
                        has_py_files = False
                        for f in os.listdir(full_path):
                            f_path = os.path.join(full_path, f)
                            if os.path.isfile(f_path) and f.endswith('.py'):
                                has_py_files = True
                                break
                        folders.append((entry, full_path, has_py_files))
                    elif os.path.isfile(full_path) and full_path.endswith('.py'):
                        files.append((entry, full_path))
                except Exception as e:
                    # 单个文件/文件夹错误不影响整体加载
                    continue

            # 排序
            folders.sort(key=lambda x: x[0].lower())
            files.sort(key=lambda x: x[0].lower())

            self.update_signal.emit(self.parent_item, folders, files)

        except PermissionError:
            self.error_signal.emit(self.parent_item, "权限不足")
        except Exception as e:
            self.error_signal.emit(self.parent_item, f"加载错误: {str(e)}")


# 脚本执行线程（增强：添加子进程跟踪与强制终止）
class ScriptThread(QThread):
    output_signal = pyqtSignal(str, str)
    finished_signal = pyqtSignal()

    def __init__(self, python_path, script_path, parent=None):
        super().__init__(parent)
        self.python_path = python_path
        self.script_path = script_path
        self.is_running = True
        self.process = None  # 跟踪subprocess子进程对象

    def run(self):
        try:
            cmd = [
                self.python_path,
                "-c",
                f"import os, sys; script = r'{self.script_path}'; "
                f"os.chdir(os.path.dirname(os.path.abspath(script))); "
                f"exec(open(script, encoding='utf-8').read())"
            ]

            exec_info = f"执行时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            exec_info += f"Python解释器: {self.python_path}\n"
            exec_info += f"脚本路径: {self.script_path}\n"
            exec_info += "-" * 50 + "\n"
            self.output_signal.emit(exec_info, "info")

            # 保存process对象用于后续终止
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )

            while self.is_running:
                output = self.process.stdout.readline()
                if output:
                    self.output_signal.emit(output, "stdout")
                else:
                    break

            # 读取剩余输出
            output, error = self.process.communicate()
            if output:
                self.output_signal.emit(output, "stdout")
            if error:
                self.output_signal.emit(error, "stderr")

            # 区分正常完成与强制停止
            if not self.is_running:
                self.output_signal.emit("\n⚠️ 脚本已被强制停止\n", "stderr")
            else:
                self.output_signal.emit("\n✅ 执行完成\n", "info")

        except Exception as e:
            self.output_signal.emit(f"❌ 执行错误: {str(e)}\n", "stderr")
        finally:
            self.finished_signal.emit()

    def stop(self):
        # 先停止线程循环，再强制终止子进程（彻底停止任务）
        self.is_running = False
        if self.process and self.process.poll() is None:  # 检查进程是否仍在运行
            self.process.terminate()  # 发送终止信号
            try:
                self.process.wait(timeout=1)  # 等待进程退出
            except subprocess.TimeoutExpired:
                self.process.kill()  # 超时则强制杀死进程


# 自定义文本编辑框
class ColoredTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 9))
        self.highlighter = LogHighlighter(self.document())
        self.setWordWrapMode(QTextOption.WrapMode.WordWrap)

    def append_with_color(self, text, color=None):
        if color:
            self.setTextColor(color)
        self.append(text)
        self.moveCursor(QTextCursor.MoveOperation.End)


# 主窗口类（使用重写的DragableTreeWidget）
class ScriptManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python脚本管理器")
        self.resize(1200, 800)
        self.icon_path = Path(__file__).parent / "resources" / "icons"

        self.icons = {}
        self.load_icons()
        try:
            self.setWindowIcon(QIcon(str(self.icon_path / "python.svg")))
        except:
            pass

        self.config = ConfigManager()
        self.current_python_index = self.config.get_last_selected_index()
        self.script_threads = []
        self.execution_count = 0
        self.root_nodes = {}
        self.updating_check_state = False  # 防止信号循环的标志
        self.loaders = {}  # 用于跟踪目录加载线程

        # 使用实例变量存储隐藏项目，而非持久化存储
        self.hidden_items = set()  # 仅在当前会话中有效
        # 跟踪当前运行状态（用于控制停止按钮启用/禁用）
        self.is_task_running = False
        # 跟踪拖拽的源节点（内部拖拽用）
        self.dragged_items = []  # 存储拖拽的多个节点路径和类型

        self.init_ui()
        self.load_python_paths()

    def load_icons(self):
        try:
            self.icons = {
                "settings": QIcon(str(self.icon_path / "settings.svg")),
                "folder": QIcon(str(self.icon_path / "folder-heart.svg")),
                "run": QIcon(str(self.icon_path / "play-circle.svg")),
                "clear": QIcon(str(self.icon_path / "delete_all.svg")),
                "delete": QIcon(str(self.icon_path / "delete.svg")),
                "hide": QIcon(str(self.icon_path / "hide.svg")),
                "stop": QIcon(str(self.icon_path / "stop-circle.svg")),  # 停止按钮图标
                "folder_item": QIcon(str(self.icon_path / "folder_special-copy.svg")),
                "python_file": QIcon(str(self.icon_path / "file-code.svg")),
                "run_script": QIcon(str(self.icon_path / "playarrow.svg")),
                "edit": QIcon(str(self.icon_path / "edit.svg")),
                "explorer": QIcon(str(self.icon_path / "FolderOpen.svg")),
                "add_file": QIcon.fromTheme("document-new"),  # 添加文件图标
                "add_folder": QIcon.fromTheme("folder-new")  # 添加文件夹图标
            }
        except Exception as e:
            QMessageBox.warning(self, "图标加载警告", f"无法加载本地图标：{str(e)}")
            self.icons = {
                "settings": QIcon.fromTheme("preferences-system"),
                "folder": QIcon.fromTheme("folder-open"),
                "run": QIcon.fromTheme("system-run"),
                "clear": QIcon.fromTheme("edit-clear"),
                "delete": QIcon.fromTheme("edit-delete"),
                "hide": QIcon.fromTheme("view-hidden"),
                "stop": QIcon.fromTheme("process-stop"),  # 系统默认停止图标
                "folder_item": self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon),
                "python_file": self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon),
                "run_script": QIcon.fromTheme("system-run"),
                "edit": QIcon.fromTheme("document-edit"),
                "explorer": QIcon.fromTheme("folder-special"),
                "add_file": self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon),  # 系统默认文件图标
                "add_folder": self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)  # 系统默认文件夹图标
            }

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ------------------------------ 关键修改：使用重写的DragableTreeWidget ------------------------------
        self.tree_widget = DragableTreeWidget(parent=self)  # 传入主窗口引用
        self.tree_widget.setHeaderLabel("脚本结构")
        self.tree_widget.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.tree_widget.itemExpanded.connect(self.on_item_expanded)
        self.tree_widget.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.tree_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.show_context_menu)
        self.tree_widget.itemChanged.connect(self.on_item_changed)

        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)

        self.single_log_tab = ColoredTextEdit()
        self.tab_widget.addTab(self.single_log_tab, "单脚本日志")

        splitter.addWidget(self.tree_widget)
        splitter.addWidget(self.tab_widget)
        splitter.setSizes([400, 800])

        main_layout.addWidget(splitter)

        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("就绪")

        self.create_toolbar()

    def on_item_changed(self, item, column):
        if self.updating_check_state or column != 0:
            return

        self.updating_check_state = True

        try:
            current_state = item.checkState(0)
            self.update_child_check_states(item, current_state)
            self.update_parent_check_state(item)
        finally:
            self.updating_check_state = False

    def update_child_check_states(self, parent_item, state):
        for i in range(parent_item.childCount()):
            child = parent_item.child(i)
            if child.text(0) != "加载中...":
                child.setCheckState(0, state)
                if child.childCount() > 0:
                    self.update_child_check_states(child, state)

    def update_parent_check_state(self, item):
        parent = item.parent()
        if not parent:
            return

        checked_count = 0
        total_count = 0

        for i in range(parent.childCount()):
            child = parent.child(i)
            if child.text(0) != "加载中...":
                total_count += 1
                if child.checkState(0) == Qt.CheckState.Checked:
                    checked_count += 1

        if checked_count == 0:
            parent.setCheckState(0, Qt.CheckState.Unchecked)
        elif checked_count == total_count:
            parent.setCheckState(0, Qt.CheckState.Checked)
        else:
            parent.setCheckState(0, Qt.CheckState.PartiallyChecked)

        self.update_parent_check_state(parent)

    # ------------------------------ 内部拖拽事件处理（主窗口方法，由DragableTreeWidget调用） ------------------------------
    def on_item_drag_start(self, selected_items):
        """拖拽开始：记录选中的源节点信息（由DragableTreeWidget的startDrag调用）"""
        self.dragged_items = []  # 清空历史拖拽记录
        for item in selected_items:
            item_path = item.data(0, Qt.ItemDataRole.UserRole)
            if not item_path or not os.path.exists(item_path):
                continue  # 跳过无效节点（如"加载中..."）

            # 记录节点类型（文件/文件夹）和路径
            self.dragged_items.append({
                "path": item_path,
                "is_file": os.path.isfile(item_path),
                "is_folder": os.path.isdir(item_path)
            })

    def on_item_drag_enter(self, event, target_item):
        """拖拽进入节点：判断是否允许放置（由DragableTreeWidget的dragEnterEvent调用）"""
        if not target_item:
            event.ignore()
            return

        target_path = target_item.data(0, Qt.ItemDataRole.UserRole)
        # 目标必须是文件夹且存在
        if not target_path or not os.path.isdir(target_path):
            event.ignore()
            return

        # 检查所有源节点是否满足：1. 不是目标节点本身 2. 不是目标节点的子节点（避免循环）
        for src in self.dragged_items:
            src_path = src["path"]
            # 禁止拖拽到自身
            if os.path.abspath(src_path) == os.path.abspath(target_path):
                event.ignore()
                return
            # 禁止拖拽到自身的子目录（避免循环移动）
            if src["is_folder"] and target_path.startswith(src_path + os.sep):
                event.ignore()
                return

        # 允许放置：设置拖拽指示器为"移动"
        event.setDropAction(Qt.DropAction.MoveAction)
        event.accept()

    def on_item_drag_move(self, event, target_item):
        """拖拽移动：同enter逻辑（由DragableTreeWidget的dragMoveEvent调用）"""
        self.on_item_drag_enter(event, target_item)

    def on_item_drop(self, event, target_item):
        """拖拽结束：执行真实文件移动+树结构同步（由DragableTreeWidget的dropEvent调用）"""
        if not target_item:
            event.ignore()
            return

        target_path = target_item.data(0, Qt.ItemDataRole.UserRole)
        # 最终验证目标合法性
        if not target_path or not os.path.isdir(target_path):
            QMessageBox.warning(self, "无效目标", "只能将文件/文件夹拖到其他文件夹中")
            event.ignore()
            return

        # 收集需要重新加载的文件夹（源父目录+目标目录）
        folders_to_reload = set()
        move_success_count = 0
        move_failed_count = 0

        # 遍历所有源节点执行移动
        for src in self.dragged_items:
            src_path = src["path"]
            src_name = os.path.basename(src_path)
            dest_path = os.path.join(target_path, src_name)  # 目标路径 = 目标文件夹 + 源文件名

            # 1. 检查目标路径是否已存在
            if os.path.exists(dest_path):
                QMessageBox.warning(
                    self, "移动失败",
                    f"目标路径已存在：\n{dest_path}\n\n跳过该项目的移动"
                )
                move_failed_count += 1
                continue

            try:
                # 2. 执行真实文件系统移动（跨磁盘兼容）
                import shutil
                shutil.move(src_path, dest_path)
                move_success_count += 1

                # 3. 记录需要重新加载的文件夹：源节点的父目录（移除已移动项）+ 目标目录（显示新添加项）
                src_parent_path = os.path.dirname(src_path)
                folders_to_reload.add(src_parent_path)
                folders_to_reload.add(target_path)

            except PermissionError:
                QMessageBox.critical(
                    self, "移动失败",
                    f"权限不足，无法移动：\n{src_path}\n\n请检查文件是否被其他程序占用"
                )
                move_failed_count += 1
            except Exception as e:
                QMessageBox.critical(
                    self, "移动失败",
                    f"移动{src_name}时发生错误：\n{str(e)}"
                )
                move_failed_count += 1

        # 4. 重新加载相关文件夹，同步树结构
        for folder_path in folders_to_reload:
            folder_item = self._find_tree_item_by_path(folder_path)
            if folder_item:
                self.reload_directory(folder_item)

        # 5. 显示移动结果
        result_msg = f"移动完成！\n成功：{move_success_count} 项\n失败：{move_failed_count} 项"
        self.statusBar.showMessage(result_msg, 5000)  # 状态栏显示5秒
        if move_failed_count > 0:
            QMessageBox.information(self, "移动结果", result_msg)

        event.setDropAction(Qt.DropAction.MoveAction)
        event.accept()

    # ------------------------------ 新增功能：删除文件/文件夹 ------------------------------
    def delete_item(self, path, tree_item):
        """删除文件或文件夹 - 与系统同步"""
        # 显示确认对话框
        item_type = "文件" if os.path.isfile(path) else "文件夹"
        reply = QMessageBox.question(
            self,
            f"确认删除",
            f"确定要删除{item_type} '{os.path.basename(path)}'吗？\n此操作不可撤销！",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            # 执行删除操作
            if os.path.isfile(path):
                os.remove(path)
            else:
                import shutil
                shutil.rmtree(path)

            # 从树结构中移除该项目
            parent = tree_item.parent()
            if parent:
                parent.removeChild(tree_item)
                self.update_parent_check_state(parent)
                # 重新加载父文件夹以确保显示正确
                self.reload_directory(parent)
            else:
                index = self.tree_widget.indexOfTopLevelItem(tree_item)
                if index >= 0:
                    self.tree_widget.takeTopLevelItem(index)
                    folder_path = tree_item.data(0, Qt.ItemDataRole.UserRole)
                    if folder_path in self.root_nodes:
                        del self.root_nodes[folder_path]

            self.statusBar.showMessage(f"{item_type}已删除")
        except Exception as e:
            QMessageBox.critical(self, "删除失败", f"无法删除{item_type}：{str(e)}")

    # ------------------------------ 新增功能：重命名文件/文件夹 ------------------------------
    def rename_item(self, path, tree_item):
        """重命名文件或文件夹 - 与系统同步"""
        item_type = "文件" if os.path.isfile(path) else "文件夹"
        current_name = os.path.basename(path)
        parent_dir = os.path.dirname(path)

        # 弹窗输入新名称
        new_name, ok = QInputDialog.getText(
            self,
            f"重命名{item_type}",
            f"请输入新的{item_type}名称：",
            text=current_name
        )

        if not ok or not new_name.strip() or new_name == current_name:
            return  # 取消、空名称或与原名称相同时退出
        new_name = new_name.strip()

        # 处理文件后缀（确保Python文件保持.py后缀）
        if os.path.isfile(path) and path.endswith('.py') and not new_name.endswith('.py'):
            new_name += '.py'

        # 拼接新路径并检查冲突
        new_path = os.path.join(parent_dir, new_name)
        if os.path.exists(new_path):
            QMessageBox.warning(self, "名称冲突", f"{item_type}已存在：{new_path}")
            return

        try:
            # 执行重命名操作
            os.rename(path, new_path)

            # 更新树节点显示名称和数据
            tree_item.setText(0, new_name)
            tree_item.setData(0, Qt.ItemDataRole.UserRole, new_path)

            # 如果是根文件夹，更新root_nodes字典
            if not tree_item.parent() and path in self.root_nodes:
                del self.root_nodes[path]
                self.root_nodes[new_path] = tree_item

            self.statusBar.showMessage(f"{item_type}已重命名")

            # 重新加载父文件夹以确保显示正确
            parent = tree_item.parent()
            if parent:
                self.reload_directory(parent)
        except Exception as e:
            QMessageBox.critical(self, "重命名失败", f"无法重命名{item_type}：{str(e)}")

    # ------------------------------ 原有功能保留 ------------------------------
    def add_file_to_tree(self, parent_item, file_path):
        # 检查当前会话的隐藏项目
        if os.path.abspath(file_path) in self.hidden_items:
            return

        if not os.path.isfile(file_path) or not file_path.endswith('.py'):
            return

        for i in range(parent_item.childCount()):
            child = parent_item.child(i)
            if child.data(0, Qt.ItemDataRole.UserRole) == file_path:
                return

        child_item = QTreeWidgetItem(parent_item)
        child_item.setText(0, os.path.basename(file_path))
        child_item.setData(0, Qt.ItemDataRole.UserRole, file_path)
        child_item.setIcon(0, self.icons["python_file"])
        child_item.setCheckState(0, Qt.CheckState.Unchecked)
        child_item.setFlags(child_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)

        parent_item.setExpanded(True)

    def create_toolbar(self):
        toolbar = QToolBar("主工具栏")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)

        toolbar.addWidget(QLabel(" Python路径: "))
        self.python_combo = QComboBox()
        self.python_combo.setMinimumWidth(300)
        self.python_combo.setEditable(True)
        toolbar.addWidget(self.python_combo)

        self.set_python_btn = QAction(self.icons["settings"], "设置Python路径", self)
        self.set_python_btn.triggered.connect(self.show_python_path_dialog)
        toolbar.addAction(self.set_python_btn)

        self.browse_btn = QAction(self.icons["folder"], "浏览文件夹", self)
        self.browse_btn.triggered.connect(self.browse_folder)
        toolbar.addAction(self.browse_btn)

        toolbar.addSeparator()

        self.execute_btn = QAction(self.icons["run"], "批量执行", self)
        self.execute_btn.triggered.connect(self.execute_selected_scripts)
        toolbar.addAction(self.execute_btn)

        # 立即停止按钮
        self.stop_btn = QAction(self.icons["stop"], "立即停止", self)
        self.stop_btn.triggered.connect(self.stop_all_tasks)
        self.stop_btn.setEnabled(False)  # 默认禁用
        toolbar.addAction(self.stop_btn)

        toolbar.addSeparator()

        self.clear_single_log_btn = QAction(self.icons["clear"], "清空单脚本日志", self)
        self.clear_single_log_btn.triggered.connect(self.clear_single_log)
        toolbar.addAction(self.clear_single_log_btn)

        self.clear_all_results_btn = QAction(self.icons["delete"], "清除所有结果栏", self)
        self.clear_all_results_btn.triggered.connect(self.clear_all_results)
        toolbar.addAction(self.clear_all_results_btn)

    def load_python_paths(self):
        self.python_combo.clear()
        paths = self.config.get_python_paths()
        for path in paths:
            self.python_combo.addItem(path)

        if paths:
            index = min(self.current_python_index, len(paths) - 1)
            self.python_combo.setCurrentIndex(index)

    def show_python_path_dialog(self):
        dialog = PythonPathDialog(self)
        dialog.exec()
        self.load_python_paths()

    def browse_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "选择文件夹")
        if folder_path:
            self.add_root_node(folder_path)
            if folder_path in self.root_nodes:
                root_item = self.root_nodes[folder_path]
                while root_item.childCount() > 0:
                    root_item.removeChild(root_item.child(0))
                self.load_folder_contents(root_item, apply_filter=True)

    def add_root_node(self, folder_path):
        if folder_path in self.root_nodes:
            return

        root_item = QTreeWidgetItem(self.tree_widget)
        root_item.setText(0, os.path.basename(folder_path))
        root_item.setData(0, Qt.ItemDataRole.UserRole, folder_path)
        root_item.setIcon(0, self.icons["folder_item"])
        root_item.setCheckState(0, Qt.CheckState.Unchecked)

        dummy_item = QTreeWidgetItem(root_item)
        dummy_item.setText(0, "加载中...")

        self.root_nodes[folder_path] = root_item
        self.tree_widget.addTopLevelItem(root_item)

    def on_item_expanded(self, item):
        if item.childCount() == 1 and item.child(0).text(0) == "加载中...":
            item.removeChild(item.child(0))
            self.load_folder_contents(item, apply_filter=True)

    def on_item_double_clicked(self, item, column):
        file_path = item.data(0, Qt.ItemDataRole.UserRole)
        if file_path and os.path.isfile(file_path) and file_path.endswith('.py'):
            self.execute_single_script(file_path)

    def show_context_menu(self, position):
        item = self.tree_widget.itemAt(position)
        if not item:
            return

        file_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not file_path:
            return

        menu = QMenu()
        is_root_folder = not item.parent()  # 判断是否为主文件夹（无父项）
        is_directory = os.path.isdir(file_path)  # 判断是否为文件夹

        # 1. 文件类型菜单（仅Python文件显示）
        if os.path.isfile(file_path) and file_path.endswith('.py'):
            execute_action = QAction("执行脚本", self)
            execute_action.triggered.connect(lambda: self.execute_single_script(file_path))
            menu.addAction(execute_action)

            edit_action = QAction("编辑", self)
            edit_action.triggered.connect(lambda: self.open_editor(file_path))
            menu.addAction(edit_action)

            # 新增：重命名菜单项
            rename_action = QAction("重命名", self)
            rename_action.triggered.connect(lambda: self.rename_item(file_path, item))
            menu.addAction(rename_action)

            # 新增：删除菜单项
            delete_action = QAction("删除文件", self)
            delete_action.setIcon(self.icons["delete"])
            delete_action.triggered.connect(lambda: self.delete_item(file_path, item))
            menu.addAction(delete_action)

            open_in_explorer_action = QAction("在文件管理器中打开路径", self)
            open_in_explorer_action.triggered.connect(lambda: self.open_in_explorer(file_path))
            menu.addAction(open_in_explorer_action)

            hide_action = QAction("隐藏该文件", self)
            hide_action.setIcon(self.icons["hide"])
            hide_action.triggered.connect(lambda: self.hide_item(file_path, item))
            menu.addAction(hide_action)

            execute_action.setIcon(self.icons["run_script"])
            edit_action.setIcon(self.icons["edit"])
            open_in_explorer_action.setIcon(self.icons["explorer"])

        # 2. 文件夹类型菜单（所有文件夹显示，包含主文件夹和子文件夹）
        elif is_directory:
            # 添加文件选项（所有文件夹通用）
            add_file_action = QAction("添加Python文件", self)
            add_file_action.setIcon(self.icons["python_file"])
            add_file_action.triggered.connect(lambda: self.add_new_item(file_path, is_file=True))
            menu.addAction(add_file_action)

            # 添加文件夹选项（所有文件夹通用）
            add_folder_action = QAction("添加子文件夹", self)
            add_folder_action.setIcon(self.icons["folder_item"])
            add_folder_action.triggered.connect(lambda: self.add_new_item(file_path, is_file=False))
            menu.addAction(add_folder_action)

            menu.addSeparator()  # 分隔线

            # 新增：重命名菜单项
            rename_action = QAction("重命名", self)
            rename_action.triggered.connect(lambda: self.rename_item(file_path, item))
            menu.addAction(rename_action)

            # 新增：删除菜单项
            delete_action = QAction("删除文件夹", self)
            delete_action.setIcon(self.icons["delete"])
            delete_action.triggered.connect(lambda: self.delete_item(file_path, item))
            menu.addAction(delete_action)

            menu.addSeparator()  # 分隔线

            # 文件夹特有操作（重新加载/关闭根文件夹）
            if is_root_folder:
                # 主文件夹：显示"关闭根文件夹"和"重新加载"，不显示"隐藏"
                close_action = QAction("关闭根文件夹", self)
                close_action.setIcon(self.icons["delete"])
                close_action.triggered.connect(lambda: self.close_root_folder(item))
                menu.addAction(close_action)

                reload_action = QAction("重新加载", self)
                reload_action.setIcon(self.icons["run"])
                reload_action.triggered.connect(lambda: self.reload_directory(item))
                menu.addAction(reload_action)
            else:
                # 子文件夹：显示"重新加载该目录"和"隐藏该文件夹"
                reload_action = QAction("重新加载该目录", self)
                reload_action.setIcon(self.icons["run"])
                reload_action.triggered.connect(lambda: self.reload_directory(item))
                menu.addAction(reload_action)

                hide_action = QAction("隐藏该文件夹", self)
                hide_action.setIcon(self.icons["hide"])
                hide_action.triggered.connect(lambda: self.hide_item(file_path, item))
                menu.addAction(hide_action)

            # 通用：在文件管理器中打开
            open_in_explorer_action = QAction("在文件管理器中打开路径", self)
            open_in_explorer_action.setIcon(self.icons["explorer"])
            open_in_explorer_action.triggered.connect(lambda: self.open_in_explorer(file_path))
            menu.addAction(open_in_explorer_action)

        menu.exec(self.tree_widget.mapToGlobal(position))

    def add_new_item(self, parent_dir, is_file=True):
        """新增文件/文件夹的核心方法"""
        # 1. 弹窗输入名称（带默认后缀）
        item_type = "Python文件" if is_file else "子文件夹"
        default_name = "new_script.py" if is_file else "new_folder"
        name, ok = QInputDialog.getText(
            self,
            f"创建{item_type}",
            f"请输入{item_type}名称：",
            text=default_name
        )

        if not ok or not name.strip():
            return  # 取消或空名称时退出
        name = name.strip()

        # 2. 处理文件后缀（确保Python文件带.py）
        if is_file and not name.endswith('.py'):
            name += '.py'

        # 3. 拼接完整路径并检查冲突
        full_path = os.path.join(parent_dir, name)
        if os.path.exists(full_path):
            QMessageBox.warning(self, "名称冲突", f"{item_type}已存在：{full_path}")
            return

        # 4. 创建文件/文件夹
        try:
            if is_file:
                # 创建Python文件（带默认头部注释）
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write("# 自动创建的Python脚本\n")
            else:
                # 创建文件夹（支持多级创建）
                os.makedirs(full_path, exist_ok=True)
            QMessageBox.information(self, "创建成功", f"{item_type}已创建：{full_path}")
        except Exception as e:
            QMessageBox.critical(self, "创建失败", f"无法创建{item_type}：{str(e)}")
            return

        # 5. 重新加载父文件夹，显示新创建的项目
        parent_item = self._find_tree_item_by_path(parent_dir)
        if parent_item:
            self.reload_directory(parent_item)

    def _find_tree_item_by_path(self, target_path):
        """辅助方法：根据路径查找对应的树节点"""
        # 先检查根节点
        if target_path in self.root_nodes:
            return self.root_nodes[target_path]

        # 递归检查子节点
        def find_item_recursive(parent_item):
            for i in range(parent_item.childCount()):
                child = parent_item.child(i)
                child_path = child.data(0, Qt.ItemDataRole.UserRole)
                if not child_path:
                    continue
                # 路径匹配（绝对路径对比，避免相对路径问题）
                if os.path.abspath(child_path) == os.path.abspath(target_path):
                    return child
                # 递归检查子文件夹
                if os.path.isdir(child_path):
                    found = find_item_recursive(child)
                    if found:
                        return found
            return None

        # 遍历所有根节点查找
        for root_item in self.root_nodes.values():
            found = find_item_recursive(root_item)
            if found:
                return found
        return None

    def hide_item(self, path, tree_item):
        """隐藏文件或文件夹 - 仅在当前会话中生效"""
        self.hidden_items.add(os.path.abspath(path))

        # 从树结构中移除该项目
        parent = tree_item.parent()
        if parent:
            parent.removeChild(tree_item)
            self.update_parent_check_state(parent)
        else:
            index = self.tree_widget.indexOfTopLevelItem(tree_item)
            if index >= 0:
                self.tree_widget.takeTopLevelItem(index)
                folder_path = tree_item.data(0, Qt.ItemDataRole.UserRole)
                if folder_path in self.root_nodes:
                    del self.root_nodes[folder_path]

        item_type = "文件" if os.path.isfile(path) else "文件夹"
        self.statusBar.showMessage(f"{item_type}已隐藏，重新加载上级目录可显示，关闭程序后失效")

    def reload_directory(self, item):
        """重新加载目录（保留选中状态）"""
        checked_paths = self.get_checked_paths(item)

        # 清空现有子节点
        while item.childCount() > 0:
            item.removeChild(item.child(0))

        # 添加加载占位符
        dummy_item = QTreeWidgetItem(item)
        dummy_item.setText(0, "加载中...")

        # 重新加载目录内容
        self.load_folder_contents(item, apply_filter=False)

        # 移除加载占位符（如果还存在）
        if item.childCount() > 0 and item.child(0).text(0) == "加载中...":
            item.removeChild(item.child(0))

        # 恢复选中状态
        self.restore_checked_paths(item, checked_paths)

    def get_checked_paths(self, item):
        """获取节点的选中路径集合"""
        checked_paths = set()

        if item.checkState(0) == Qt.CheckState.Checked:
            item_path = item.data(0, Qt.ItemDataRole.UserRole)
            if item_path:
                checked_paths.add(os.path.abspath(item_path))

        for i in range(item.childCount()):
            child = item.child(i)
            if child.text(0) != "加载中...":
                checked_paths.update(self.get_checked_paths(child))

        return checked_paths

    def restore_checked_paths(self, item, checked_paths):
        """恢复节点的选中状态"""
        item_path = item.data(0, Qt.ItemDataRole.UserRole)
        if item_path and os.path.abspath(item_path) in checked_paths:
            item.setCheckState(0, Qt.CheckState.Checked)
        else:
            item.setCheckState(0, Qt.CheckState.Unchecked)

        for i in range(item.childCount()):
            child = item.child(i)
            if child.text(0) != "加载中...":
                self.restore_checked_paths(child, checked_paths)

    def load_folder_contents(self, parent_item, apply_filter=True):
        """加载文件夹内容（线程安全）"""
        parent_path = parent_item.data(0, Qt.ItemDataRole.UserRole)
        if parent_path in self.loaders:
            self.loaders[parent_path].terminate()
            del self.loaders[parent_path]

        # 移除非"加载中..."的子节点
        for i in reversed(range(parent_item.childCount())):
            child = parent_item.child(i)
            if child.text(0) != "加载中...":
                parent_item.removeChild(child)

        # 添加加载占位符（如果不存在）
        has_loading_placeholder = any(
            child.text(0) == "加载中..." for child in parent_item.takeChildren()
        )
        parent_item.addChildren([QTreeWidgetItem(parent_item, ["加载中..."])])

        # 启动加载线程
        folder_path = parent_item.data(0, Qt.ItemDataRole.UserRole)
        loader = DirectoryLoader(parent_item, folder_path, self.hidden_items, apply_filter)
        loader.update_signal.connect(self.on_directory_load_complete)
        loader.error_signal.connect(self.on_directory_load_error)
        loader.finished.connect(lambda: self.cleanup_loader(parent_path))
        loader.start()

        self.loaders[parent_path] = loader
        self.statusBar.showMessage(f"正在加载目录: {os.path.basename(folder_path)}")

    def on_directory_load_complete(self, parent_item, folders, files):
        """目录加载完成：更新树结构"""
        # 移除加载占位符
        for i in reversed(range(parent_item.childCount())):
            if parent_item.child(i).text(0) == "加载中...":
                parent_item.removeChild(parent_item.child(i))

        # 添加文件夹节点
        for entry, full_path, has_py_files in folders:
            child_item = QTreeWidgetItem(parent_item)
            child_item.setText(0, entry)
            child_item.setData(0, Qt.ItemDataRole.UserRole, full_path)
            child_item.setIcon(0, self.icons["folder_item"])
            child_item.setCheckState(0, Qt.CheckState.Unchecked)
            child_item.setFlags(child_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)

            # 有Python文件的文件夹添加加载占位符
            if has_py_files:
                dummy_item = QTreeWidgetItem(child_item)
                dummy_item.setText(0, "加载中...")

        # 添加Python文件节点
        for entry, full_path in files:
            child_item = QTreeWidgetItem(parent_item)
            child_item.setText(0, entry)
            child_item.setData(0, Qt.ItemDataRole.UserRole, full_path)
            child_item.setIcon(0, self.icons["python_file"])
            child_item.setCheckState(0, Qt.CheckState.Unchecked)
            child_item.setFlags(child_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)

        # 更新状态栏
        folder_name = os.path.basename(parent_item.data(0, Qt.ItemDataRole.UserRole))
        self.statusBar.showMessage(f"目录加载完成: {folder_name}")

    def on_directory_load_error(self, parent_item, error_msg):
        """目录加载错误：显示错误信息"""
        # 移除加载占位符
        for i in reversed(range(parent_item.childCount())):
            if parent_item.child(i).text(0) == "加载中...":
                parent_item.removeChild(parent_item.child(i))

        # 添加错误节点
        error_item = QTreeWidgetItem(parent_item)
        error_item.setText(0, error_msg)
        error_item.setFlags(error_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        error_item.setForeground(0, QColor("red"))

    def cleanup_loader(self, path):
        """清理加载线程"""
        if path in self.loaders:
            del self.loaders[path]

    def execute_single_script(self, script_path):
        """执行单个脚本"""
        python_path = self.python_combo.currentText()
        if not python_path:
            QMessageBox.warning(self, "警告", "请先选择Python解释器")
            return

        self.single_log_tab.clear()
        self._update_task_state(True)  # 更新任务状态为运行中

        thread = ScriptThread(python_path, script_path)
        thread.output_signal.connect(self.handle_single_output)
        thread.finished_signal.connect(lambda: self._on_task_finished("执行完成"))
        thread.start()

        self.script_threads.append(thread)
        self.statusBar.showMessage("正在执行脚本...")

    def handle_single_output(self, text, output_type):
        """处理单个脚本输出"""
        if output_type == "stdout":
            self.single_log_tab.append_with_color(text, QColor("black"))
        elif output_type == "stderr":
            self.single_log_tab.append_with_color(text, QColor("red"))
        elif output_type == "info":
            self.single_log_tab.append_with_color(text, QColor("blue"))

    def execute_selected_scripts(self):
        """执行选中的脚本（批量）"""
        python_path = self.python_combo.currentText()
        if not python_path:
            QMessageBox.warning(self, "警告", "请先选择Python解释器")
            return

        selected_scripts = self.get_selected_scripts()
        if not selected_scripts:
            QMessageBox.warning(self, "警告", "请先选择要执行的脚本")
            return

        self.execution_count += 1
        result_tab = ColoredTextEdit()
        result_tab.setReadOnly(True)
        self.tab_widget.addTab(result_tab, f"第{self.execution_count}次")
        self.tab_widget.setCurrentWidget(result_tab)

        exec_info = f"批量执行开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        exec_info += f"Python解释器: {python_path}\n"
        exec_info += f"执行脚本数量: {len(selected_scripts)}\n"
        exec_info += "-" * 50 + "\n"
        result_tab.append_with_color(exec_info, QColor("blue"))

        self._update_task_state(True)  # 更新任务状态为运行中

        def run_next_script(index=0):
            if index >= len(selected_scripts):
                result_tab.append_with_color("\n所有脚本执行完成\n", QColor("blue"))
                self._on_task_finished("批量执行完成")
                return

            script_path = selected_scripts[index]
            script_info = f"\n执行脚本: {script_path}\n"
            script_info += "-" * 30 + "\n"
            result_tab.append_with_color(script_info, QColor("darkGreen"))

            thread = ScriptThread(python_path, script_path)
            thread.output_signal.connect(
                lambda text, output_type: self.handle_batch_output(result_tab, text, output_type)
            )
            thread.finished_signal.connect(lambda: run_next_script(index + 1))
            thread.start()
            self.script_threads.append(thread)

        run_next_script(0)

    def handle_batch_output(self, text_widget, text, output_type):
        """处理批量脚本输出"""
        if output_type == "stdout":
            text_widget.append_with_color(text, QColor("black"))
        elif output_type == "stderr":
            text_widget.append_with_color(text, QColor("red"))
        elif output_type == "info":
            text_widget.append_with_color(text, QColor("blue"))

    def get_selected_scripts(self):
        """获取选中的Python脚本路径"""
        scripts = []

        def collect_scripts(item):
            if item.childCount() > 0:
                for i in range(item.childCount()):
                    collect_scripts(item.child(i))
            else:
                file_path = item.data(0, Qt.ItemDataRole.UserRole)
                if file_path and os.path.isfile(file_path) and file_path.endswith('.py'):
                    if item.checkState(0) == Qt.CheckState.Checked:
                        scripts.append(file_path)

        for i in range(self.tree_widget.topLevelItemCount()):
            collect_scripts(self.tree_widget.topLevelItem(i))

        return scripts

    def open_editor(self, file_path):
        """打开脚本编辑器"""
        editor_dialog = QDialog(self)
        editor_dialog.setWindowTitle(f"编辑 - {os.path.basename(file_path)}")
        editor_dialog.resize(800, 600)

        layout = QVBoxLayout()
        editor = CodeEditor()
        editor.set_content(file_path)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("保存")
        cancel_btn = QPushButton("取消")

        save_btn.setMinimumSize(80, 30)
        cancel_btn.setMinimumSize(80, 30)

        btn_layout.addStretch()
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)

        layout.addWidget(editor)
        layout.addLayout(btn_layout)

        editor_dialog.setLayout(layout)

        def save_file():
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(editor.toPlainText())
                editor_dialog.accept()
                QMessageBox.information(self, "成功", "文件保存成功")
            except Exception as e:
                QMessageBox.critical(editor_dialog, "错误", f"保存文件失败: {str(e)}")

        save_btn.clicked.connect(save_file)
        cancel_btn.clicked.connect(editor_dialog.reject)

        editor_dialog.exec()

    def open_in_explorer(self, path):
        """在系统文件管理器中打开路径"""
        try:
            if sys.platform == "win32":
                if os.path.isfile(path):
                    real_path = os.path.abspath(path)
                    subprocess.run(f'explorer /select,"{real_path}"', shell=True)
                else:
                    os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            QMessageBox.warning(self, "打开失败", f"无法在文件管理器中打开路径: {str(e)}")

    def close_root_folder(self, item):
        """关闭根文件夹（从树中移除）"""
        folder_path = item.data(0, Qt.ItemDataRole.UserRole)
        if folder_path in self.root_nodes:
            self.root_nodes.pop(folder_path)
            self.tree_widget.takeTopLevelItem(self.tree_widget.indexOfTopLevelItem(item))

    def close_tab(self, index):
        """关闭结果标签页（保留单脚本日志）"""
        if index != 0:
            self.tab_widget.removeTab(index)

    def clear_single_log(self):
        """清空单脚本日志"""
        self.single_log_tab.clear()
        self.statusBar.showMessage("已清空单脚本日志")

    def clear_all_results(self):
        """清除所有批量执行结果标签页"""
        while self.tab_widget.count() > 1:
            self.tab_widget.removeTab(1)

        self.execution_count = 0
        self.statusBar.showMessage("已清除所有结果栏")

    def stop_all_tasks(self):
        """停止所有运行中的脚本任务"""
        if not self.script_threads:
            return

        # 停止所有运行中的线程
        for thread in self.script_threads:
            if thread.isRunning():
                thread.stop()

        # 清空线程列表
        self.script_threads.clear()

        # 更新状态
        self._update_task_state(False)
        self.statusBar.showMessage("所有任务已停止")

    def _update_task_state(self, is_running):
        """更新任务运行状态（控制按钮启用/禁用）"""
        self.is_task_running = is_running
        self.stop_btn.setEnabled(is_running)  # 任务运行时启用停止按钮
        self.execute_btn.setEnabled(not is_running)  # 任务运行时禁用执行按钮

    def _on_task_finished(self, message):
        """任务完成后更新状态"""
        # 过滤已完成的线程
        self.script_threads = [t for t in self.script_threads if t.isRunning()]

        # 如果没有运行中的线程了，更新状态
        if not self.script_threads:
            self._update_task_state(False)

        self.statusBar.showMessage(message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = ScriptManager()
    window.show()
    sys.exit(app.exec())
