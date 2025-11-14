你做得很好，现在我们的代码是这样子的：
import struct
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
from pathlib import Path


class FileDecoderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("文件结构解析工具")
        self.root.geometry("900x600")

        # 变量
        self.input_file = tk.StringVar()
        self.is_processing = False
        self.progress_value = tk.IntVar(value=0)
        self.parsed_blocks = []  # 存储解析后的数据
        self.selected_character = tk.StringVar()  # 选择的角色
        self.info_labels = {}  # 初始化信息标签字典

        self.create_widgets()

    def create_widgets(self):
        """创建界面组件"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 标题
        title_label = ttk.Label(main_frame, text="文件结构解析工具",
                                font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))  # 改为3列

        # 分隔线
        separator = ttk.Separator(main_frame, orient=tk.HORIZONTAL)
        separator.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)  # 改为3列

        # 输入文件区域
        input_frame = ttk.LabelFrame(main_frame, text="文件选择", padding="5")
        input_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)  # 改为3列

        ttk.Label(input_frame, text="选择文件:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        input_entry = ttk.Entry(input_frame, textvariable=self.input_file, width=50)
        input_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5))

        ttk.Button(input_frame, text="浏览",
                   command=self.browse_input_file).grid(row=0, column=2)

        # 控制按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)  # 改为3列

        self.start_button = ttk.Button(button_frame, text="解析文件",
                                       command=self.start_decoding)
        self.start_button.grid(row=0, column=0, padx=(0, 10))

        ttk.Button(button_frame, text="清空信息",
                   command=self.clear_info).grid(row=0, column=1, padx=(0, 10))

        # 进度条
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)  # 改为3列

        ttk.Label(progress_frame, text="进度:").grid(row=0, column=0, sticky=tk.W)
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_value,
                                            maximum=100, length=600)
        self.progress_bar.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(5, 0))

        # 状态显示
        self.status_label = ttk.Label(main_frame, text="就绪")
        self.status_label.grid(row=5, column=0, columnspan=3, sticky=tk.W, pady=(5, 10))  # 改为3列

        # 分隔线
        separator2 = ttk.Separator(main_frame, orient=tk.HORIZONTAL)
        separator2.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)  # 改为3列

        # 角色选择区域
        character_frame = ttk.LabelFrame(main_frame, text="选择角色", padding="5")
        character_frame.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)  # 改为3列

        ttk.Label(character_frame, text="选择武将:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.character_combo = ttk.Combobox(character_frame, textvariable=self.selected_character,
                                            state="readonly", width=50)
        self.character_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5))
        self.character_combo.bind('<<ComboboxSelected>>', self.on_character_selected)

        # 角色信息显示区域 - 改为三列布局
        info_frame = ttk.LabelFrame(main_frame, text="角色信息", padding="5")
        info_frame.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)  # 改为3列

        # 创建三列信息框架
        left_info_frame = ttk.Frame(info_frame)
        left_info_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))

        middle_info_frame = ttk.Frame(info_frame)
        middle_info_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))

        right_info_frame = ttk.Frame(info_frame)
        right_info_frame.grid(row=0, column=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 左侧信息 (0-13)
        self.create_info_fields(left_info_frame, 0)
        # 中间信息 (14-27)
        self.create_info_fields(middle_info_frame, 14)
        # 右侧信息 (28-41)
        self.create_info_fields(right_info_frame, 28)

        # 配置网格权重
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(8, weight=1)
        input_frame.columnconfigure(1, weight=1)
        progress_frame.columnconfigure(1, weight=1)
        character_frame.columnconfigure(1, weight=1)
        info_frame.columnconfigure(0, weight=1)
        info_frame.columnconfigure(1, weight=1)
        info_frame.columnconfigure(2, weight=1)  # 添加第三列的权重
        info_frame.rowconfigure(0, weight=1)

        # 调整窗口大小以适应三列布局
        self.root.geometry("1200x700")

    def create_info_fields(self, parent, start_row):
        """创建信息字段"""
        # 基本信息
        fields = [
            ("序号", "index"),
            ("姓名", "name"),
            ("身份", "identity"),
            ("归属", "belonging"),
            ("位置", "position"),
            ("等级", "level"),
            ("经验", "exp"),
            ("最大体力", "max_hp"),
            ("现体力", "current_hp"),
            ("体成长", "hp_growth"),
            ("撤退体力", "escape_hp"),
            ("武力", "strength"),
            ("武成长", "strength_growth"),
            ("智力", "intelligence"),
            ("智成长", "intelligence_growth"),
            ("陆战", "land_battle"),
            ("水战", "water_battle"),
            ("林战", "forest_battle"),
            ("陆战成长", "land_growth"),
            ("水战成长", "water_growth"),
            ("林战成长", "forest_growth"),
            ("解锁特技等级", "skill_unlock_level"),
            ("武器", "weapon"),
            ("特技", "skill"),
            ("专属锦囊1", "special_item1"),
            ("专属锦囊2", "special_item2"),
            ("大招", "special_attack1"),
            ("中招", "special_attack2"),
            ("小招", "special_attack3"),
            ("大招概率", "special_attack1_chance"),
            ("中招概率", "special_attack2_chance"),
            ("小招概率", "special_attack3_chance"),
            ("陆吼", "land_shout"),
            ("水吼", "water_shout"),
            ("林吼", "forest_shout"),
            ("友好度_刘", "relation_liu"),
            ("友好度_孙", "relation_sun"),
            ("友好度_曹", "relation_cao"),
            ("友好度_董", "relation_dong"),
            ("友好度_张", "relation_zhang"),
            ("友好度_龙", "relation_long"),
            ("友好度_孟", "relation_meng"),
            ("无意义字段", "relation_guo")
        ]

        # 创建标签和值显示
        for i, (label_text, key) in enumerate(fields[start_row:start_row + 14]):
            row = i % 14
            ttk.Label(parent, text=label_text + ":").grid(row=row, column=0, sticky=tk.W, pady=2)
            value_label = ttk.Label(parent, text="", foreground="blue")
            value_label.grid(row=row, column=1, sticky=tk.W, pady=2, padx=(5, 0))
            self.info_labels[key] = value_label

    def browse_input_file(self):
        """浏览输入文件"""
        filename = filedialog.askopenfilename(
            title="选择输入文件",
            filetypes=[("DAT文件", "*.dat"), ("所有文件", "*.*")]
        )
        if filename:
            self.input_file.set(filename)

    def start_decoding(self):
        """开始解码过程"""
        if self.is_processing:
            return

        # 验证输入
        if not self.input_file.get():
            messagebox.showerror("错误", "请选择输入文件！")
            return

        if not os.path.exists(self.input_file.get()):
            messagebox.showerror("错误", "输入文件不存在！")
            return

        # 在后台线程中执行解码
        self.is_processing = True
        self.start_button.config(state=tk.DISABLED)
        self.progress_value.set(0)
        self.status_label.config(text="开始处理...")

        thread = threading.Thread(target=self.decode_in_thread)
        thread.daemon = True
        thread.start()

    def decode_in_thread(self):
        """在后台线程中执行解码"""
        try:
            success = self.decode_file()

            # 在主线程中更新UI
            self.root.after(0, self.on_decoding_complete, success)

        except Exception as e:
            self.root.after(0, self.on_decoding_error, str(e))

    def on_decoding_complete(self, success):
        """解码完成回调"""
        self.is_processing = False
        self.start_button.config(state=tk.NORMAL)

        if success:
            # 更新角色下拉菜单
            self.update_character_combo()

            messagebox.showinfo("完成", "文件解析完成！")
        else:
            messagebox.showerror("错误", "文件解析失败！")

    def on_decoding_error(self, error_msg):
        """解码错误回调"""
        self.is_processing = False
        self.start_button.config(state=tk.NORMAL)
        messagebox.showerror("错误", f"发生错误: {error_msg}")

    def update_character_combo(self):
        """更新角色下拉菜单"""
        if not self.parsed_blocks:
            return

        # 提取所有角色姓名，按序号排列
        character_names = []
        for block in sorted(self.parsed_blocks, key=lambda x: x['index']):
            name = block.get('name', '')
            if name and name not in character_names:
                character_names.append(name)

        # 更新下拉菜单
        self.character_combo['values'] = character_names

        # 如果有角色，选择第一个
        if character_names:
            self.selected_character.set(character_names[0])
            self.on_character_selected()

    def on_character_selected(self, event=None):
        """当选择角色时显示详细信息"""
        selected_name = self.selected_character.get()
        if not selected_name or not self.parsed_blocks:
            return

        # 查找对应的角色数据
        selected_block = None
        for block in self.parsed_blocks:
            if block.get('name') == selected_name:
                selected_block = block
                break

        if selected_block:
            self.display_character_info(selected_block)

    def display_character_info(self, block):
        """显示角色信息"""
        # 基本信息
        self.info_labels['index'].config(text=str(block.get('index', '')))
        self.info_labels['name'].config(text=block.get('name', ''))
        self.info_labels['identity'].config(text=block.get('identity', ''))
        self.info_labels['belonging'].config(text=block.get('belonging', ''))
        self.info_labels['position'].config(text=block.get('position', ''))
        self.info_labels['level'].config(text=str(block.get('level', '')))
        self.info_labels['exp'].config(text=str(block.get('exp', '')))
        self.info_labels['max_hp'].config(text=str(block.get('max_hp', '')))
        self.info_labels['current_hp'].config(text=str(block.get('current_hp', '')))
        self.info_labels['hp_growth'].config(text=str(block.get('hp_growth', '')))
        self.info_labels['escape_hp'].config(text=str(block.get('escape_hp', '')))
        self.info_labels['strength'].config(text=str(block.get('strength', '')))
        self.info_labels['strength_growth'].config(text=str(block.get('strength_growth', '')))
        self.info_labels['intelligence'].config(text=str(block.get('intelligence', '')))
        self.info_labels['intelligence_growth'].config(text=str(block.get('intelligence_growth', '')))

        # 战斗信息
        self.info_labels['land_battle'].config(text=str(block.get('land_battle', '')))
        self.info_labels['water_battle'].config(text=str(block.get('water_battle', '')))
        self.info_labels['forest_battle'].config(text=str(block.get('forest_battle', '')))
        self.info_labels['land_growth'].config(text=str(block.get('land_growth', '')))
        self.info_labels['water_growth'].config(text=str(block.get('water_growth', '')))
        self.info_labels['forest_growth'].config(text=str(block.get('forest_growth', '')))

        # 特技和武器
        self.info_labels['skill_unlock_level'].config(text=str(block.get('skill_unlock_level', '')))
        self.info_labels['weapon'].config(text=block.get('weapon', ''))
        self.info_labels['skill'].config(text=block.get('skill', ''))

        # 锦囊和招式
        self.info_labels['special_item1'].config(text=block.get('special_item1', ''))
        self.info_labels['special_item2'].config(text=block.get('special_item2', ''))
        self.info_labels['special_attack1'].config(text=block.get('special_attack1', ''))
        self.info_labels['special_attack2'].config(text=block.get('special_attack2', ''))
        self.info_labels['special_attack3'].config(text=block.get('special_attack3', ''))

        # 概率和吼叫
        self.info_labels['special_attack1_chance'].config(text=str(block.get('special_attack1_chance', '')))
        self.info_labels['special_attack2_chance'].config(text=str(block.get('special_attack2_chance', '')))
        self.info_labels['special_attack3_chance'].config(text=str(block.get('special_attack3_chance', '')))
        self.info_labels['land_shout'].config(text=str(block.get('land_shout', '')))
        self.info_labels['water_shout'].config(text=str(block.get('water_shout', '')))
        self.info_labels['forest_shout'].config(text=str(block.get('forest_shout', '')))

        # 友好度
        relations = block.get('relations', [])
        if len(relations) >= 8:
            self.info_labels['relation_liu'].config(text=str(relations[0]))
            self.info_labels['relation_sun'].config(text=str(relations[1]))
            self.info_labels['relation_cao'].config(text=str(relations[2]))
            self.info_labels['relation_dong'].config(text=str(relations[3]))
            self.info_labels['relation_zhang'].config(text=str(relations[4]))
            self.info_labels['relation_long'].config(text=str(relations[5]))
            self.info_labels['relation_meng'].config(text=str(relations[6]))
            self.info_labels['relation_guo'].config(text=str(relations[7]))

    def clear_info(self):
        """清空信息"""
        # 清空所有信息标签
        for label in self.info_labels.values():
            label.config(text="")

        # 清空下拉菜单
        self.character_combo.set("")
        self.character_combo['values'] = []

        # 重置状态
        self.status_label.config(text="就绪")
        self.progress_value.set(0)

    def update_progress(self, value):
        """更新进度条"""
        self.progress_value.set(value)

    def update_status(self, text):
        """更新状态文本"""
        self.status_label.config(text=text)

    def decode_file(self):
        """
        使用GBK编码解码文件，并按168字节块解析结构
        """
        try:
            # 更新状态
            self.root.after(0, self.update_status, f"正在读取文件: {self.input_file.get()}")

            # 以二进制模式读取文件
            with open(self.input_file.get(), 'rb') as f:
                raw_data = f.read()

            # 更新状态
            self.root.after(0, self.update_status, f"成功读取文件: {self.input_file.get()}")
            self.root.after(0, self.update_progress, 10)

            file_size = len(raw_data)
            total_blocks = file_size // 168

            self.root.after(0, self.update_status, f"文件大小: {file_size} 字节，预计块数: {total_blocks}")
            self.root.after(0, self.update_progress, 20)

            # 解析结果
            self.parsed_blocks = []

            # 按168字节块解析
            for block_idx in range(0, total_blocks):
                block_start = block_idx * 168
                block_end = block_start + 168

                if block_end > len(raw_data):
                    break

                block_data = raw_data[block_start:block_end]
                parsed_block = self.parse_block(block_data, block_idx)
                self.parsed_blocks.append(parsed_block)

                # 更新进度
                if block_idx % 10 == 0:  # 每10个块更新一次进度，避免过于频繁的更新
                    progress = 20 + (block_idx / total_blocks) * 60
                    self.root.after(0, self.update_progress, int(progress))
                    self.root.after(0, self.update_status, f"正在解析数据块... ({block_idx + 1}/{total_blocks})")

            self.root.after(0, self.update_status, "解析完成！")
            self.root.after(0, self.update_progress, 100)

            return True

        except FileNotFoundError:
            error_msg = f"错误: 找不到文件 {self.input_file.get()}"
            self.root.after(0, self.update_status, error_msg)
            return False
        except Exception as e:
            error_msg = f"处理文件时发生错误: {e}"
            self.root.after(0, self.update_status, error_msg)
            return False

    # 以下是原有的解析函数，保持不变
    def parse_special_value(self, data):
        """解析特殊数值（最大体力、武力等）"""
        value = struct.unpack('<I', data)[0]

        # 特殊位置值处理
        if value == 0xFFFFFFFF:
            return "本队"
        elif value == 0xFFFFFFFE:
            return "聚贤庄"
        elif value == 0xFFFFFFFD:
            return "医馆(死亡)"
        elif (value & 0xFFFFFF00) == 0x00000000:
            return f"驻守城池(代码:{value & 0xFF})"

        if value > 0x7FFFFFFF:
            unsigned_value = (1 << 32) - value
            return unsigned_value
        else:
            return value

    def get_weapon_name(self, weapon_code):
        """根据武器代码获取武器名称"""
        weapons = [
            "梳子", "鱼钩", "碎石片", "橡皮筋", "牙签", "鸡毛", "镰刀", "芋叶",
            "弹弓", "布币", "不求人", "筷子", "桃木剑", "菜刀", "竹竿", "锅铲",
            "回力标", "小斧头", "七星剑", "古锭刀", "大斧", "落月弓", "湘竹扇",
            "齐眉棍", "霹雳斧", "青虹剑", "大关刀", "狼牙棒", "五色扇", "麒麟弓",
            "屠龙刀", "倚天剑", "水镜扇", "打狗棒", "养由弓", "伏龙斧", "金箍棒",
            "后羿弓", "夸父斧", "芭蕉扇", "干将剑", "楼兰刀"
        ]

        if weapon_code == 0xFF:
            return "无"
        elif 0x00 <= weapon_code <= 0x2A:
            return weapons[weapon_code]
        else:
            return f"未知武器({weapon_code:02X})"

    def get_skill_info(self, skill_value):
        """根据特技数值获取特技名称和解释"""
        skills = {
            0x00: ("体健", "体力回复速度加倍"),
            0x01: ("勤学", "经验值成长速度加倍"),
            0x02: ("聪颖", "节省使用计谋时体力的消耗"),
            0x03: ("诈财", "派驻在城里时，可使过路费增加"),
            0x04: ("税吏", "派驻在城里时，可使城池税收增加"),
            0x05: ("屯田", "派驻在城里时，可减少士兵军饷支出"),
            0x06: ("福将", "跟在主公身边时，可增加主公幸运度"),
            0x07: ("礼官", "走到建有献帝像的己方城池里，可额外增加主公声望"),
            0x08: ("偷窃", "跟在主公身边时，会趁机偷取敌人主公身上的银两"),
            0x09: ("交涉", "跟在主公身边时，走过别人城池时可减少过路费"),
            0x0A: ("还价", "跟在主公身边时，购买物品可享有折扣"),
            0x0B: ("人缘", "跟在主公身边时，在聚贤庄录用人才可享有折扣"),
            0x0C: ("开路", "跟在主公身边时，开路仅需一半费用"),
            0x0D: ("躲箭", "不惧任何等级的箭塔攻击"),
            0x0E: ("制人", "单挑时一上场就先发动武斗技"),
            0x0F: ("先手", "单挑时会抢先攻击数回合，然后敌人才会开始反击"),
            0x10: ("气壮", "单挑时体力上限和体力现值均获得暂时提升"),
            0x11: ("斗狠", "单挑时会战到体力消耗殆尽为止，而且不会阵亡"),
            0x12: ("命硬", "单挑时绝对不会身亡"),
            0x13: ("夺刃", "单挑胜利后，会抢夺对方的武器当胜利品"),
            0x14: ("绊索", "陆战担任主将坐镇后方时可多设陷阱"),
            0x15: ("漩涡", "水战担任主将坐镇后方时可多设陷阱"),
            0x16: ("泥坑", "林战担任主将坐镇后方时可多设陷阱"),
            0x17: ("陆吼", "陆战上场时容易发动吼叫技"),
            0x18: ("水吼", "水战上场时容易发动吼叫技"),
            0x19: ("林吼", "林战上场时容易发动吼叫技"),
            0x1A: ("细作", "守城时，会在战争开始后破坏敌方攻城机关"),
            0x1B: ("筑墙", "守城时，会使城墙耐久度提升至最大值"),
            0x1C: ("修墙", "守城时，会保护城墙，使其耐久度下降缓慢"),
            0x1D: ("潜入", "攻城时可在战争开始后破坏敌方守城机关"),
            0x1E: ("破坏", "派兵攻打敌城时，有可能使该城建筑物毁损"),
            0x1F: ("神医", "跟在主公身边时，所有武将体力回复速度加倍"),
            0x20: ("皇恩", "跟在主公身边时，宫廷事件发生好事所得倍增"),
            0x21: ("人望", "派驻在城里时，人口成长速度及税收金额均倍增"),
            0x22: ("教导", "跟在主公身边时，本队所有武将经验值成长增加")
        }

        if skill_value in skills:
            name, desc = skills[skill_value]
            return f"{name}({desc})"
        else:
            return f"未知特技({skill_value:02X})"

    def get_attack_info(self, attack_code):
        """根据招式代码获取招式详细信息"""
        attacks = [
            [0, "青龙岩破", 0, 35, 8],
            [1, "乘龙吞云", 0, 34, 8],
            [2, "潜龙出水", 0, 33, 8],
            [3, "神龙摆尾", 0, 32, 8],
            [4, "飞龙翔空", 0, 31, 8],
            [5, "万虎咆啸", 1, 30, 15],
            [6, "猛虎出栏", 1, 29, 15],
            [7, "饿虎扑羊", 1, 28, 15],
            [8, "纵虎跃溪", 1, 27, 15],
            [9, "黑虎偷心", 1, 26, 15],
            [10, "星火燎原", 2, 25, 22],
            [11, "星移斗转", 2, 24, 22],
            [12, "星离雨散", 2, 23, 22],
            [13, "星落平野", 2, 22, 22],
            [14, "星光曳地", 2, 21, 22],
            [15, "奔雷驰电", 3, 20, 29],
            [16, "振雷流风", 3, 19, 29],
            [17, "云雷狂降", 3, 18, 29],
            [18, "五雷轰顶", 3, 17, 29],
            [19, "迅雷疾摧", 3, 16, 29],
            [20, "霸王举鼎", 4, 15, 36],
            [21, "恶来拔石", 4, 14, 36],
            [22, "碎裂连空", 4, 13, 36],
            [23, "石破天惊", 4, 12, 36],
            [24, "天摇地动", 4, 11, 36],
            [25, "极焰炽热", 5, 20, 3],
            [26, "烈焰轰天", 5, 19, 3],
            [27, "恶焰焚魄", 5, 18, 3],
            [28, "奔焰疾捷", 5, 17, 3],
            [29, "赤焰燃烧", 5, 16, 3],
            [30, "风驰电掣", 6, 15, 9],
            [31, "风号雪舞", 6, 14, 9],
            [32, "风流云散", 6, 13, 9],
            [33, "风扫落叶", 6, 12, 9],
            [34, "风声鹤唳", 6, 11, 9],
            [35, "瞬闪刃斩", 7, 10, 15],
            [36, "失空斗斩", 7, 9, 15],
            [37, "皇天六斩", 7, 8, 15],
            [38, "刚斧旋斩", 7, 7, 15],
            [39, "破岩飞斩", 7, 6, 15],
            [40, "苍狼搏兔", 8, 5, 21],
            [41, "恶狼逐虎", 8, 4, 21],
            [42, "奔狼驰日", 8, 3, 21],
            [43, "巨狼破石", 8, 2, 21],
            [44, "狂狼啸月", 8, 1, 21],
            [45, "灵鹊报喜", 9, 1, 5],
            [46, "新莺出谷", 9, 1, 4],
            [47, "乳燕归巢", 9, 1, 3],
            [48, "孤鸟哀鸣", 9, 1, 2],
            [49, "迷途昏鸦", 9, 1, 1],
            [50, "笨鸟慢飞", 9, 0, 5],
            [51, "黄雀啾啾", 9, 0, 4],
            [52, "小鸡展翅", 9, 0, 3],
            [53, "空中蹓鸟", 9, 0, 2],
            [54, "小鸟依人", 9, 0, 1]
        ]

        if attack_code == 0xFF:
            return "无"
        elif 0 <= attack_code <= 54:
            attack = attacks[attack_code]
            min_damage = attack[3]
            max_damage = attack[3] + attack[4]
            return f"{attack[1]}(动画:{attack[2]:02d},伤害:{min_damage}-{max_damage})"
        else:
            return f"未知招式({attack_code:02X})"

    def parse_single_byte_item(self, data, item_type):
        """解析单字节物品（锦囊）"""
        if len(data) < 1:
            return "无"

        value = data[0]
        if value == 0xFF:
            return "无"
        else:
            return f"{value:02X}号{item_type}"

    def parse_block(self, block_data, block_index):
        """解析单个168字节块"""
        block = {
            'index': block_index,
            'name': '',
            'identity': '',
            'belonging': '',
            'position': '',
            'skill_unlock_level': 0,
            'weapon': '',
            'skill': '',
            'level': 0,
            'exp': 0,
            'max_hp': 0,
            'current_hp': 0,
            'hp_growth': 0,
            'escape_hp': 0,
            'strength': 0,
            'strength_growth': 0,
            'intelligence': 0,
            'intelligence_growth': 0,
            'land_battle': 0,
            'water_battle': 0,
            'forest_battle': 0,
            'land_growth': 0,
            'water_growth': 0,
            'forest_growth': 0,
            'special_item1': '',
            'special_item2': '',
            'special_attack1': '',
            'special_attack2': '',
            'special_attack3': '',
            'special_attack1_chance': 0,
            'special_attack2_chance': 0,
            'special_attack3_chance': 0,
            'land_shout': 0,
            'water_shout': 0,
            'forest_shout': 0,
            'relations': []
        }

        # 前8字节: 姓名 (GBK解码)
        name_bytes = block_data[0:8]
        block['name'] = self.decode_gbk_string(name_bytes)

        # 第13-16字节: 身份
        identity_bytes = block_data[12:16]
        if len(identity_bytes) >= 4:
            identity_value = struct.unpack('<I', identity_bytes)[0]
            block['identity'] = "主公" if identity_value == 1 else "武将"

        # 第29-32字节: 归属
        belonging_bytes = block_data[28:32]
        if len(belonging_bytes) >= 4:
            belonging_value = struct.unpack('<I', belonging_bytes)[0]
            allegiance_map = {
                0: "刘备", 1: "孙权", 2: "曹操", 3: "董卓", 4: "张角",
                5: "龙翠公主", 6: "孟获", 7: "郭汜", 8: "张梁", 9: "张宝",
                10: "祝融夫人", 11: "王元", 12: "聚贤庄", 13: "不登场"
            }
            block['belonging'] = allegiance_map.get(belonging_value, f"未知({belonging_value})")

        # 第33-36字节: 位置
        position_bytes = block_data[32:36]
        if len(position_bytes) >= 4:
            position_value = struct.unpack('<I', position_bytes)[0]
            if position_value == 0xFFFFFFFF:
                block['position'] = "本队"
            elif position_value == 0xFFFFFFFE:
                block['position'] = "聚贤庄"
            elif position_value == 0xFFFFFFFD:
                block['position'] = "医馆(死亡)"
            elif (position_value & 0xFFFFFF00) == 0x00000000:
                city_code = position_value & 0xFF
                block['position'] = f"驻守城池(代码:{city_code})"
            else:
                block['position'] = f"未知位置({position_value:08X})"

        # 第37-40字节: 解锁特技的等级
        skill_unlock_bytes = block_data[36:40]
        if len(skill_unlock_bytes) >= 4:
            block['skill_unlock_level'] = struct.unpack('<I', skill_unlock_bytes)[0]

        # 第41-44字节: 武器
        weapon_bytes = block_data[40:44]
        if len(weapon_bytes) >= 1:
            weapon_code = weapon_bytes[0]
            block['weapon'] = self.get_weapon_name(weapon_code)

        # 第45-48字节: 特技
        skill_bytes = block_data[44:48]
        if len(skill_bytes) >= 4:
            skill_value = struct.unpack('<I', skill_bytes)[0]
            skill_code = skill_value & 0xFF
            block['skill'] = self.get_skill_info(skill_code)

        # 第49-52字节: 等级
        level_bytes = block_data[48:52]
        if len(level_bytes) >= 4:
            block['level'] = struct.unpack('<I', level_bytes)[0]

        # 第53-56字节: 经验
        exp_bytes = block_data[52:56]
        if len(exp_bytes) >= 4:
            block['exp'] = struct.unpack('<I', exp_bytes)[0]

        # 第61-64字节: 最大体力
        max_hp_bytes = block_data[60:64]
        if len(max_hp_bytes) >= 4:
            block['max_hp'] = self.parse_special_value(max_hp_bytes)

        # 第65-68字节: 现体力
        current_hp_bytes = block_data[64:68]
        if len(current_hp_bytes) >= 4:
            block['current_hp'] = self.parse_special_value(current_hp_bytes)

        # 第69-72字节: 体成长
        hp_growth_bytes = block_data[68:72]
        if len(hp_growth_bytes) >= 4:
            block['hp_growth'] = struct.unpack('<I', hp_growth_bytes)[0]

        # 第73-76字节: 撤退体力
        escape_hp_bytes = block_data[72:76]
        if len(escape_hp_bytes) >= 4:
            block['escape_hp'] = struct.unpack('<I', escape_hp_bytes)[0]

        # 第77-80字节: 武力
        strength_bytes = block_data[76:80]
        if len(strength_bytes) >= 4:
            block['strength'] = self.parse_special_value(strength_bytes)

        # 第81-84字节: 武成长
        strength_growth_bytes = block_data[80:84]
        if len(strength_growth_bytes) >= 4:
            block['strength_growth'] = struct.unpack('<I', strength_growth_bytes)[0]

        # 第85-88字节: 智力
        intelligence_bytes = block_data[84:88]
        if len(intelligence_bytes) >= 4:
            block['intelligence'] = self.parse_special_value(intelligence_bytes)

        # 第89-92字节: 智成长
        intelligence_growth_bytes = block_data[88:92]
        if len(intelligence_growth_bytes) >= 4:
            block['intelligence_growth'] = struct.unpack('<I', intelligence_growth_bytes)[0]

        # 第93-96字节: 陆战
        land_battle_bytes = block_data[92:96]
        if len(land_battle_bytes) >= 4:
            block['land_battle'] = self.parse_special_value(land_battle_bytes)

        # 第97-100字节: 水战
        water_battle_bytes = block_data[96:100]
        if len(water_battle_bytes) >= 4:
            block['water_battle'] = self.parse_special_value(water_battle_bytes)

        # 第101-104字节: 林战
        forest_battle_bytes = block_data[100:104]
        if len(forest_battle_bytes) >= 4:
            block['forest_battle'] = self.parse_special_value(forest_battle_bytes)

        # 第105-108字节: 陆战成长
        land_growth_bytes = block_data[104:108]
        if len(land_growth_bytes) >= 4:
            block['land_growth'] = struct.unpack('<I', land_growth_bytes)[0]

        # 第109-112字节: 水战成长
        water_growth_bytes = block_data[108:112]
        if len(water_growth_bytes) >= 4:
            block['water_growth'] = struct.unpack('<I', water_growth_bytes)[0]

        # 第113-116字节: 林战成长
        forest_growth_bytes = block_data[112:116]
        if len(forest_growth_bytes) >= 4:
            block['forest_growth'] = struct.unpack('<I', forest_growth_bytes)[0]

        # 第117-120字节: 专属锦囊1
        special_item1_bytes = block_data[116:120]
        block['special_item1'] = self.parse_single_byte_item(special_item1_bytes, "锦囊")

        # 第121-124字节: 专属锦囊2
        special_item2_bytes = block_data[120:124]
        block['special_item2'] = self.parse_single_byte_item(special_item2_bytes, "锦囊")

        # 第125-128字节: 大招
        special_attack1_bytes = block_data[124:128]
        if len(special_attack1_bytes) >= 1:
            attack_code = special_attack1_bytes[0]
            block['special_attack1'] = self.get_attack_info(attack_code)

        # 第129-132字节: 中招
        special_attack2_bytes = block_data[128:132]
        if len(special_attack2_bytes) >= 1:
            attack_code = special_attack2_bytes[0]
            block['special_attack2'] = self.get_attack_info(attack_code)

        # 第133-136字节: 小招
        special_attack3_bytes = block_data[132:136]
        if len(special_attack3_bytes) >= 1:
            attack_code = special_attack3_bytes[0]
            block['special_attack3'] = self.get_attack_info(attack_code)

        # 第137-140字节: 大招概率
        special_attack1_chance_bytes = block_data[136:140]
        if len(special_attack1_chance_bytes) >= 4:
            block['special_attack1_chance'] = struct.unpack('<I', special_attack1_chance_bytes)[0]

        # 第141-144字节: 中招概率
        special_attack2_chance_bytes = block_data[140:144]
        if len(special_attack2_chance_bytes) >= 4:
            block['special_attack2_chance'] = struct.unpack('<I', special_attack2_chance_bytes)[0]

        # 第145-148字节: 小招概率
        special_attack3_chance_bytes = block_data[144:148]
        if len(special_attack3_chance_bytes) >= 4:
            block['special_attack3_chance'] = struct.unpack('<I', special_attack3_chance_bytes)[0]

        # 第149-152字节: 陆吼
        land_shout_bytes = block_data[148:152]
        if len(land_shout_bytes) >= 4:
            block['land_shout'] = struct.unpack('<I', land_shout_bytes)[0]

        # 第153-156字节: 水吼
        water_shout_bytes = block_data[152:156]
        if len(water_shout_bytes) >= 4:
            block['water_shout'] = struct.unpack('<I', water_shout_bytes)[0]

        # 第157-160字节: 林吼
        forest_shout_bytes = block_data[156:160]
        if len(forest_shout_bytes) >= 4:
            block['forest_shout'] = struct.unpack('<I', forest_shout_bytes)[0]

        # 最后8字节: 友好度
        relations_bytes = block_data[160:168]
        block['relations'] = list(relations_bytes)

        return block

    def decode_gbk_string(self, byte_data):
        """解码GBK字符串"""
        clean_bytes = bytearray()
        for i in range(0, len(byte_data)):
            if byte_data[i] != 0:
                clean_bytes.append(byte_data[i])

        if not clean_bytes:
            return ""

        try:
            text = clean_bytes.decode('gbk', errors='ignore')
            return text.strip()
        except:
            try:
                text = clean_bytes.decode('gb2312', errors='ignore')
                return text.strip()
            except:
                return ""


def main():
    """主函数"""
    root = tk.Tk()
    app = FileDecoderApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
