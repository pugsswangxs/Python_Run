import os
import sys
import json
import subprocess
import threading
import time
import re
from pathlib import Path

from PyQt6.QtWidgets import (QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem,
                             QSplitter, QTabWidget, QToolBar, QComboBox, QPushButton,
                             QFileDialog, QMessageBox, QMenu, QDialog, QVBoxLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView,
                             QTextEdit, QLabel, QLineEdit, QWidget, QStyle, QSizePolicy,
                             QFrame, QStatusBar)
from PyQt6.QtGui import (QAction, QIcon, QTextCursor, QSyntaxHighlighter, QTextCharFormat,
                         QColor, QFont, QTextOption, QPalette, QPixmap)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QRegularExpression, QSize


# 配置管理类
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
                # 如果配置文件损坏，使用默认配置
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

        # 表格显示Python路径
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["序号", "路径", "是否可用"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        # 按钮布局
        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("添加")
        self.edit_btn = QPushButton("修改")
        self.delete_btn = QPushButton("删除")
        self.close_btn = QPushButton("关闭")

        # 设置按钮样式
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

        # 连接信号
        self.add_btn.clicked.connect(self.add_path)
        self.edit_btn.clicked.connect(self.edit_path)
        self.delete_btn.clicked.connect(self.delete_path)
        self.close_btn.clicked.connect(self.accept)

    def load_paths(self):
        paths = self.config.get_python_paths()
        self.table.setRowCount(len(paths))

        for i, path in enumerate(paths):
            # 序号
            self.table.setItem(i, 0, QTableWidgetItem(str(i + 1)))

            # 路径
            self.table.setItem(i, 1, QTableWidgetItem(path))

            # 是否可用
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
        self.setTabStopDistance(40)  # 设置制表符宽度

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

        # 路径格式
        path_format = QTextCharFormat()
        path_format.setForeground(QColor("blue"))
        self.highlighting_rules.append(
            (QRegularExpression("[A-Za-z]:\\\\(?:[^\\\\]+\\\\)*[^\\\\]+|/(?:[^/]+/)*[^/]+"), path_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            match_iterator = pattern.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)


# 脚本执行线程
class ScriptThread(QThread):
    output_signal = pyqtSignal(str, str)  # 参数1: 输出内容, 参数2: 类型(stdout/stderr)
    finished_signal = pyqtSignal()

    def __init__(self, python_path, script_path, parent=None):
        super().__init__(parent)
        self.python_path = python_path
        self.script_path = script_path
        self.is_running = True

    def run(self):
        try:
            # 使用指定的Python解释器执行脚本
            # 通过-c参数传递执行代码，先切换到脚本所在目录，然后执行脚本
            cmd = [
                self.python_path,
                "-c",
                f"import os, sys; script = r'{self.script_path}'; "
                f"os.chdir(os.path.dirname(os.path.abspath(script))); "
                f"exec(open(script, encoding='utf-8').read())"
            ]

            # 执行信息
            exec_info = f"执行时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            exec_info += f"Python解释器: {self.python_path}\n"
            exec_info += f"脚本路径: {self.script_path}\n"
            exec_info += "-" * 50 + "\n"
            self.output_signal.emit(exec_info, "info")

            # 执行脚本并捕获输出
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )

            # 实时读取输出
            while self.is_running:
                output = process.stdout.readline()
                if output:
                    self.output_signal.emit(output, "stdout")
                else:
                    break

            # 读取剩余输出和错误
            output, error = process.communicate()
            if output:
                self.output_signal.emit(output, "stdout")
            if error:
                self.output_signal.emit(error, "stderr")

            # 执行完成信息
            self.output_signal.emit("\n执行完成\n", "info")

        except Exception as e:
            self.output_signal.emit(f"执行错误: {str(e)}\n", "stderr")
        finally:
            self.finished_signal.emit()

    def stop(self):
        self.is_running = False


# 自定义文本编辑框，支持不同颜色的输出
class ColoredTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 9))
        self.highlighter = LogHighlighter(self.document())

        # 设置等宽字体和自动换行
        self.setWordWrapMode(QTextOption.WrapMode.WordWrap)

    def append_with_color(self, text, color=None):
        if color:
            self.setTextColor(color)
        self.append(text)
        self.moveCursor(QTextCursor.MoveOperation.End)


# 主窗口类
class ScriptManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python脚本管理器")
        self.resize(1200, 800)

        # 设置窗口图标（如果有的话）
        try:
            self.setWindowIcon(QIcon("icon.png"))
        except:
            pass

        self.config = ConfigManager()
        self.current_python_index = self.config.get_last_selected_index()
        self.script_threads = []
        self.execution_count = 0
        self.root_nodes = {}

        self.init_ui()
        self.load_python_paths()

    def init_ui(self):
        # 创建中心部件和主布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)

        # 创建分割器
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # 左侧树形结构
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabel("脚本结构")
        self.tree_widget.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.tree_widget.itemExpanded.connect(self.on_item_expanded)
        self.tree_widget.itemCollapsed.connect(self.on_item_collapsed)
        self.tree_widget.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.tree_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.show_context_menu)

        # 右侧标签页
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)

        # 单脚本日志标签页
        self.single_log_tab = ColoredTextEdit()
        self.tab_widget.addTab(self.single_log_tab, "单脚本日志")

        splitter.addWidget(self.tree_widget)
        splitter.addWidget(self.tab_widget)
        splitter.setSizes([400, 800])

        main_layout.addWidget(splitter)

        # 创建状态栏
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("就绪")

        # 创建工具栏
        self.create_toolbar()

    def create_toolbar(self):
        toolbar = QToolBar("主工具栏")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)

        # Python路径选择框
        toolbar.addWidget(QLabel(" Python路径: "))
        self.python_combo = QComboBox()
        self.python_combo.setMinimumWidth(300)
        self.python_combo.setEditable(True)
        toolbar.addWidget(self.python_combo)

        # 设置Python路径按钮
        self.set_python_btn = QAction(QIcon.fromTheme("preferences-system"), "设置Python路径", self)
        self.set_python_btn.triggered.connect(self.show_python_path_dialog)
        toolbar.addAction(self.set_python_btn)

        # 浏览按钮
        self.browse_btn = QAction(QIcon.fromTheme("folder-open"), "浏览文件夹", self)
        self.browse_btn.triggered.connect(self.browse_folder)
        toolbar.addAction(self.browse_btn)

        toolbar.addSeparator()

        # 批量执行按钮
        self.execute_btn = QAction(QIcon.fromTheme("system-run"), "批量执行", self)
        self.execute_btn.triggered.connect(self.execute_selected_scripts)
        toolbar.addAction(self.execute_btn)

        toolbar.addSeparator()

        # 清空单脚本日志按钮
        self.clear_single_log_btn = QAction(QIcon.fromTheme("edit-clear"), "清空单脚本日志", self)
        self.clear_single_log_btn.triggered.connect(self.clear_single_log)
        toolbar.addAction(self.clear_single_log_btn)

        # 清除所有结果栏按钮
        self.clear_all_results_btn = QAction(QIcon.fromTheme("edit-delete"), "清除所有结果栏", self)
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

    def add_root_node(self, folder_path):
        # 检查是否已添加
        if folder_path in self.root_nodes:
            return

        # 创建根节点
        root_item = QTreeWidgetItem(self.tree_widget)
        root_item.setText(0, os.path.basename(folder_path))
        root_item.setData(0, Qt.ItemDataRole.UserRole, folder_path)
        root_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
        root_item.setCheckState(0, Qt.CheckState.Unchecked)

        # 添加一个空的子项，以便显示展开箭头
        dummy_item = QTreeWidgetItem(root_item)
        dummy_item.setText(0, "加载中...")

        self.root_nodes[folder_path] = root_item
        self.tree_widget.addTopLevelItem(root_item)

    def on_item_expanded(self, item):
        # 移除虚拟子项并加载实际内容
        if item.childCount() == 1 and item.child(0).text(0) == "加载中...":
            item.removeChild(item.child(0))
            self.load_folder_contents(item)

    def on_item_collapsed(self, item):
        # 折叠时不移除内容，但可以在这里添加其他逻辑
        pass

    def load_folder_contents(self, parent_item):
        folder_path = parent_item.data(0, Qt.ItemDataRole.UserRole)

        try:
            for entry in os.listdir(folder_path):
                full_path = os.path.join(folder_path, entry)

                if os.path.isdir(full_path):
                    # 检查文件夹是否包含.py文件
                    has_py_files = any(f.endswith('.py') for f in os.listdir(full_path)
                                       if os.path.isfile(os.path.join(full_path, f)))

                    if has_py_files:
                        child_item = QTreeWidgetItem(parent_item)
                        child_item.setText(0, entry)
                        child_item.setData(0, Qt.ItemDataRole.UserRole, full_path)
                        child_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
                        child_item.setCheckState(0, Qt.CheckState.Unchecked)

                        # 添加虚拟子项以支持展开
                        dummy_item = QTreeWidgetItem(child_item)
                        dummy_item.setText(0, "加载中...")

                elif os.path.isfile(full_path) and full_path.endswith('.py'):
                    child_item = QTreeWidgetItem(parent_item)
                    child_item.setText(0, entry)
                    child_item.setData(0, Qt.ItemDataRole.UserRole, full_path)
                    child_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                    child_item.setCheckState(0, Qt.CheckState.Unchecked)
                    child_item.setFlags(child_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)

        except PermissionError:
            error_item = QTreeWidgetItem(parent_item)
            error_item.setText(0, "权限不足")
            error_item.setFlags(error_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        except Exception as e:
            error_item = QTreeWidgetItem(parent_item)
            error_item.setText(0, f"加载错误: {str(e)}")
            error_item.setFlags(error_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)

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

        if os.path.isfile(file_path) and file_path.endswith('.py'):
            # 文件右键菜单
            execute_action = QAction("执行脚本", self)
            execute_action.triggered.connect(lambda: self.execute_single_script(file_path))
            menu.addAction(execute_action)

            edit_action = QAction("编辑", self)
            edit_action.triggered.connect(lambda: self.open_editor(file_path))
            menu.addAction(edit_action)

            open_in_explorer_action = QAction("在文件管理器中打开路径", self)
            open_in_explorer_action.triggered.connect(lambda: self.open_in_explorer(file_path))
            menu.addAction(open_in_explorer_action)

        elif os.path.isdir(file_path):
            # 文件夹右键菜单
            if item.parent():  # 子文件夹
                reload_action = QAction("重新加载该目录", self)
                reload_action.triggered.connect(lambda: self.reload_directory(item))
                menu.addAction(reload_action)
            else:  # 根节点
                close_action = QAction("关闭根文件夹", self)
                close_action.triggered.connect(lambda: self.close_root_folder(item))
                menu.addAction(close_action)

                reload_action = QAction("重新加载", self)
                reload_action.triggered.connect(lambda: self.reload_directory(item))
                menu.addAction(reload_action)

            open_in_explorer_action = QAction("在文件管理器中打开路径", self)
            open_in_explorer_action.triggered.connect(lambda: self.open_in_explorer(file_path))
            menu.addAction(open_in_explorer_action)

        menu.exec(self.tree_widget.mapToGlobal(position))

    def execute_single_script(self, script_path):
        python_path = self.python_combo.currentText()
        if not python_path:
            QMessageBox.warning(self, "警告", "请先选择Python解释器")
            return

        # 清空单脚本日志
        self.single_log_tab.clear()

        # 创建并启动执行线程
        thread = ScriptThread(python_path, script_path)
        thread.output_signal.connect(self.handle_single_output)
        thread.finished_signal.connect(lambda: self.statusBar.showMessage("执行完成"))
        thread.start()

        self.script_threads.append(thread)
        self.statusBar.showMessage("正在执行脚本...")

    def handle_single_output(self, text, output_type):
        if output_type == "stdout":
            self.single_log_tab.append_with_color(text, QColor("black"))
        elif output_type == "stderr":
            self.single_log_tab.append_with_color(text, QColor("red"))
        elif output_type == "info":
            self.single_log_tab.append_with_color(text, QColor("blue"))

    def execute_selected_scripts(self):
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

        # 使用递归方式逐个执行脚本
        def run_next_script(index=0):
            if index >= len(selected_scripts):
                result_tab.append_with_color("\n所有脚本执行完成\n", QColor("blue"))
                self.statusBar.showMessage("批量执行完成")
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
        if output_type == "stdout":
            text_widget.append_with_color(text, QColor("black"))
        elif output_type == "stderr":
            text_widget.append_with_color(text, QColor("red"))
        elif output_type == "info":
            text_widget.append_with_color(text, QColor("blue"))

    def get_selected_scripts(self):
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
        editor_dialog = QDialog(self)
        editor_dialog.setWindowTitle(f"编辑 - {os.path.basename(file_path)}")
        editor_dialog.resize(800, 600)

        layout = QVBoxLayout()
        editor = CodeEditor()
        editor.set_content(file_path)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("保存")
        cancel_btn = QPushButton("取消")

        # 设置按钮样式
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
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def reload_directory(self, item):
        # 移除所有子项
        while item.childCount() > 0:
            item.removeChild(item.child(0))

        # 添加虚拟子项
        dummy_item = QTreeWidgetItem(item)
        dummy_item.setText(0, "加载中...")

        # 重新展开以触发加载
        item.setExpanded(True)

    def close_root_folder(self, item):
        folder_path = item.data(0, Qt.ItemDataRole.UserRole)
        if folder_path in self.root_nodes:
            self.root_nodes.pop(folder_path)
            self.tree_widget.takeTopLevelItem(self.tree_widget.indexOfTopLevelItem(item))

    def close_tab(self, index):
        # 不允许关闭单脚本日志标签页
        if index != 0:
            self.tab_widget.removeTab(index)

    def clear_single_log(self):
        self.single_log_tab.clear()
        self.statusBar.showMessage("已清空单脚本日志")

    def clear_all_results(self):
        # 移除所有结果标签页（保留单脚本日志）
        while self.tab_widget.count() > 1:
            self.tab_widget.removeTab(1)

        self.execution_count = 0
        self.statusBar.showMessage("已清除所有结果栏")


# 应用程序入口
if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 设置应用程序样式
    app.setStyle("Fusion")


    # 创建并显示主窗口
    window = ScriptManager()
    window.show()

    sys.exit(app.exec())