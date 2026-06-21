#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
极简命令行云盘日志检索器 - CloudLog
适用于开发者、数据分析师和项目助理快速查询共享文件访问日志
"""

import os
import sys
import json
import csv
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from collections import OrderedDict

# ============================================================
# 配置
# ============================================================
APP_DIR = Path(__file__).resolve().parent
LOG_DIR = APP_DIR / "cloud_logs"
TEMPLATE_DIR = APP_DIR / "templates"
LOG_FILE = LOG_DIR / "audit_log.jsonl"

# 支持的操作动作
ACTIONS = ["上传", "下载", "删除", "分享", "查看", "编辑", "移动", "复制", "重命名", "外链访问"]

# 模拟的文件路径目录
FILE_PATHS = [
    "/合同文档/2024Q2/客户A合作协议.pdf",
    "/合同文档/2024Q2/供应商B框架合同.docx",
    "/合同文档/2024Q3/客户C服务合同.pdf",
    "/合同文档/2024Q3/保密协议模板.docx",
    "/项目文档/项目Alpha/需求文档V1.2.docx",
    "/项目文档/项目Alpha/测试报告.xlsx",
    "/项目文档/项目Beta/项目计划.md",
    "/项目文档/项目Beta/风险评估.pdf",
    "/数据分析/2024Q2/用户行为分析.csv",
    "/数据分析/2024Q2/销售报表.xlsx",
    "/数据分析/2024Q3/市场调研数据.csv",
    "/数据分析/2024Q3/财务报表_final.xlsx",
    "/共享资源/设计规范/UI组件库.fig",
    "/共享资源/设计规范/品牌手册.pdf",
    "/开发文档/API接口文档V2.0.md",
    "/开发文档/数据库设计.sql",
    "/人事行政/2024Q2/员工培训资料.pdf",
    "/人事行政/2024Q3/招聘计划.xlsx",
]

# 模拟的用户
USERS = [
    "张伟(zhangwei)",
    "李娜(lina)",
    "王磊(wanglei)",
    "刘芳(liufang)",
    "陈超(chenchao)",
    "赵敏(zhaomin)",
    "孙浩(sunhao)",
    "周静(zhoujing)",
    "吴磊(wulei)",
    "郑雪(zhengxue)",
]


# ============================================================
# 模拟数据生成
# ============================================================
def generate_mock_logs(count=500):
    """生成模拟的云盘访问日志"""
    import random

    LOG_DIR.mkdir(exist_ok=True)
    LOG_FILE.parent.mkdir(exist_ok=True)

    records = []
    now = datetime.now()

    for i in range(count):
        # 随机时间（过去30天内）
        days_ago = random.randint(0, 30)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        seconds_ago = random.randint(0, 59)
        timestamp = now - timedelta(
            days=days_ago, hours=hours_ago, minutes=minutes_ago, seconds=seconds_ago
        )

        record = {
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "file_path": random.choice(FILE_PATHS),
            "action": random.choice(ACTIONS),
            "user": random.choice(USERS),
            "ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "device": random.choice(["Windows PC", "MacBook", "iPhone", "Android", "Web"]),
        }
        records.append(record)

    # 按时间倒序排列
    records.sort(key=lambda x: x["timestamp"], reverse=True)

    # 写入 JSONL 文件
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return count


# ============================================================
# 日志加载
# ============================================================
def load_logs():
    """加载所有日志记录"""
    if not LOG_FILE.exists():
        print(f"[提示] 日志文件不存在，正在生成模拟数据...")
        count = generate_mock_logs(500)
        print(f"[完成] 已生成 {count} 条模拟日志数据: {LOG_FILE}")

    records = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


# ============================================================
# 核心检索逻辑
# ============================================================
class LogSearcher:
    def __init__(self, records):
        self.records = records

    def search(
        self,
        file_keyword=None,
        user_keyword=None,
        date_from=None,
        date_to=None,
        actions=None,
    ):
        """
        多条件组合检索
        返回匹配结果列表，每条记录附带命中原因
        """
        results = []

        for record in self.records:
            matched = True
            hit_reasons = []

            # 文件关键词匹配
            if file_keyword:
                if file_keyword.lower() in record["file_path"].lower():
                    hit_reasons.append(f"文件包含 '{file_keyword}'")
                else:
                    matched = False

            # 用户关键词匹配
            if user_keyword and matched:
                if user_keyword.lower() in record["user"].lower():
                    hit_reasons.append(f"用户匹配 '{user_keyword}'")
                else:
                    matched = False

            # 日期范围匹配
            if matched and (date_from or date_to):
                try:
                    record_date = datetime.strptime(record["timestamp"], "%Y-%m-%d %H:%M:%S")
                    if date_from and record_date < date_from:
                        matched = False
                    elif date_to and record_date > date_to:
                        matched = False
                    elif matched:
                        date_str = f"{date_from.strftime('%Y-%m-%d') if date_from else '*'} ~ {date_to.strftime('%Y-%m-%d') if date_to else '*'}"
                        hit_reasons.append(f"时间在 {date_str} 内")
                except ValueError:
                    matched = False

            # 动作筛选
            if actions and matched:
                if record["action"] in actions:
                    hit_reasons.append(f"动作为 '{record['action']}'")
                else:
                    matched = False

            if matched:
                result = dict(record)
                result["hit_reasons"] = hit_reasons if hit_reasons else ["全量匹配"]
                results.append(result)

        return results


# ============================================================
# 查询模板管理
# ============================================================
class TemplateManager:
    def __init__(self):
        TEMPLATE_DIR.mkdir(exist_ok=True)
        self.template_file = TEMPLATE_DIR / "templates.json"
        self._load()

    def _load(self):
        if self.template_file.exists():
            with open(self.template_file, "r", encoding="utf-8") as f:
                self.templates = json.load(f)
        else:
            self.templates = {}

    def _save(self):
        with open(self.template_file, "w", encoding="utf-8") as f:
            json.dump(self.templates, f, ensure_ascii=False, indent=2)

    def save(self, name, params):
        """保存查询模板"""
        self.templates[name] = {
            "params": params,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._save()

    def load(self, name):
        """加载查询模板"""
        if name in self.templates:
            return self.templates[name]["params"]
        return None

    def list(self):
        """列出所有模板"""
        return self.templates

    def delete(self, name):
        """删除模板"""
        if name in self.templates:
            del self.templates[name]
            self._save()
            return True
        return False


# ============================================================
# 结果导出
# ============================================================
class Exporter:
    @staticmethod
    def export_text(results, output_path):
        """导出为纯文本格式"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("云盘日志检索报告\n")
            f.write("=" * 80 + "\n\n")

            for i, r in enumerate(results, 1):
                f.write(f"[{i}] 操作时间: {r['timestamp']}\n")
                f.write(f"    文件路径: {r['file_path']}\n")
                f.write(f"    访问动作: {r['action']}\n")
                f.write(f"    操作者:   {r['user']}\n")
                f.write(f"    终端设备: {r['device']} ({r['ip']})\n")
                f.write(f"    命中原因: {', '.join(r['hit_reasons'])}\n")
                f.write("-" * 80 + "\n")

            # 统计信息
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"总记录数: {len(results)}\n")
            if results:
                timestamps = [r["timestamp"] for r in results]
                timestamps_sorted = sorted(timestamps)
                f.write(f"最早访问: {timestamps_sorted[0]}\n")
                f.write(f"最晚访问: {timestamps_sorted[-1]}\n")
            f.write(f"导出时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n")

    @staticmethod
    def export_csv(results, output_path):
        """导出为 CSV 表格格式"""
        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["序号", "操作时间", "文件路径", "访问动作", "操作者", "IP", "设备", "命中原因"])
            for i, r in enumerate(results, 1):
                writer.writerow([
                    i,
                    r["timestamp"],
                    r["file_path"],
                    r["action"],
                    r["user"],
                    r["ip"],
                    r["device"],
                    ", ".join(r["hit_reasons"]),
                ])

            # 统计信息
            writer.writerow([])
            writer.writerow(["统计信息"])
            writer.writerow(["总记录数", len(results)])
            if results:
                timestamps = sorted([r["timestamp"] for r in results])
                writer.writerow(["最早访问", timestamps[0]])
                writer.writerow(["最晚访问", timestamps[-1]])
            writer.writerow(["导出时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])


# ============================================================
# 终端显示格式化
# ============================================================
def display_results(results, max_show=50):
    """在终端以清晰列表展示结果"""
    if not results:
        print("\n[结果] 没有找到匹配的记录。\n")
        return

    total = len(results)
    show_count = min(total, max_show)

    print()
    print("=" * 90)
    print(f"  检索结果: 共 {total} 条记录 (显示前 {show_count} 条)")
    print("=" * 90)

    for i, r in enumerate(results[:show_count], 1):
        # 高亮显示命中原因
        reasons = " | ".join(r["hit_reasons"])
        print()
        print(f"  [{i:>3}] {r['timestamp']}  |  {r['action']:>6}  |  {r['user']}")
        print(f"        文件: {r['file_path']}")
        print(f"        命中: {reasons}")
        print("  " + "-" * 86)

    if total > show_count:
        print(f"\n  [提示] 还有 {total - show_count} 条记录未显示，可使用 --export 导出查看全部")

    # 快速统计
    timestamps = sorted([r["timestamp"] for r in results])
    print()
    print(f"  总记录数: {total}")
    print(f"  最早访问: {timestamps[0]}")
    print(f"  最晚访问: {timestamps[-1]}")
    print()


# ============================================================
# 日期解析辅助
# ============================================================
def parse_date(date_str):
    """解析日期字符串，支持多种格式"""
    formats = [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%Y%m%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    # 支持相对日期，如 "today", "3days", "lastweek"
    now = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    if date_str.lower() == "today":
        return now
    elif date_str.lower() == "yesterday":
        return now - timedelta(days=1)
    elif date_str.lower().endswith("days"):
        try:
            days = int(date_str.lower().replace("days", ""))
            return now - timedelta(days=days)
        except ValueError:
            pass
    elif date_str.lower() == "lastweek":
        return now - timedelta(days=7)
    elif date_str.lower() == "lastmonth":
        return now - timedelta(days=30)

    raise ValueError(f"无法解析日期: {date_str}")


# ============================================================
# 命令行参数解析
# ============================================================
def build_parser():
    parser = argparse.ArgumentParser(
        description="CloudLog - 极简云盘日志检索器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -f "合同"                    # 按文件关键词查
  %(prog)s -u "张伟"                    # 按用户查
  %(prog)s --from 2024-06-01 --to 2024-06-30  # 按时间范围查
  %(prog)s -f "合同" -a 下载,分享        # 追加动作条件
  %(prog)s --save-tpl daily_contract -f "合同" -a 外链访问  # 保存模板
  %(prog)s --tpl daily_contract         # 使用模板
  %(prog)s -f "合同" --export report.csv  # 导出结果
        """,
    )

    # 三大查询方式
    parser.add_argument("-f", "--file", help="文件关键词搜索")
    parser.add_argument("-u", "--user", help="用户关键词搜索")
    parser.add_argument("--from", dest="date_from", help="起始日期 (YYYY-MM-DD, today, 7days)")
    parser.add_argument("--to", dest="date_to", help="结束日期 (YYYY-MM-DD, today)")

    # 动作筛选
    parser.add_argument(
        "-a", "--action",
        help=f"动作条件筛选，多个用逗号分隔。支持: {', '.join(ACTIONS)}",
    )

    # 模板功能
    parser.add_argument("--tpl", metavar="NAME", help="使用已保存的查询模板")
    parser.add_argument("--save-tpl", metavar="NAME", help="将当前查询条件保存为模板")
    parser.add_argument("--list-tpl", action="store_true", help="列出所有查询模板")
    parser.add_argument("--del-tpl", metavar="NAME", help="删除指定查询模板")

    # 导出功能
    parser.add_argument("--export", metavar="PATH", help="导出结果到文件 (.txt 或 .csv)")
    parser.add_argument("--limit", type=int, default=50, help="终端显示条数上限 (默认: 50)")

    # 数据管理
    parser.add_argument("--gen-mock", type=int, metavar="N", help="生成 N 条模拟日志数据")
    parser.add_argument("--log-path", action="store_true", help="显示日志文件路径")

    return parser


# ============================================================
# 主程序入口
# ============================================================
def main():
    parser = build_parser()
    args = parser.parse_args()

    # 模板管理 - 列表
    if args.list_tpl:
        tm = TemplateManager()
        tpls = tm.list()
        if not tpls:
            print("\n[信息] 暂无保存的查询模板。\n")
        else:
            print("\n" + "=" * 70)
            print("  已保存的查询模板")
            print("=" * 70)
            for name, data in tpls.items():
                params = data["params"]
                desc_parts = []
                if params.get("file_keyword"):
                    desc_parts.append(f"文件={params['file_keyword']}")
                if params.get("user_keyword"):
                    desc_parts.append(f"用户={params['user_keyword']}")
                if params.get("date_from"):
                    desc_parts.append(f"起始={params['date_from']}")
                if params.get("date_to"):
                    desc_parts.append(f"结束={params['date_to']}")
                if params.get("actions"):
                    desc_parts.append(f"动作={','.join(params['actions'])}")
                desc = " | ".join(desc_parts) if desc_parts else "(空)"
                print(f"  {name:<20}  {desc}")
                print(f"  {'':<20}  创建于: {data['created_at']}")
                print("  " + "-" * 66)
            print()
        return

    # 模板管理 - 删除
    if args.del_tpl:
        tm = TemplateManager()
        if tm.delete(args.del_tpl):
            print(f"\n[成功] 已删除模板 '{args.del_tpl}'\n")
        else:
            print(f"\n[错误] 模板 '{args.del_tpl}' 不存在\n")
        return

    # 生成模拟数据
    if args.gen_mock:
        count = generate_mock_logs(args.gen_mock)
        print(f"\n[完成] 已生成 {count} 条模拟日志数据: {LOG_FILE}\n")
        return

    # 显示日志路径
    if args.log_path:
        print(f"\n{LOG_FILE}\n")
        return

    # 构建查询参数
    params = {
        "file_keyword": None,
        "user_keyword": None,
        "date_from": None,
        "date_to": None,
        "actions": None,
    }

    # 优先使用模板
    if args.tpl:
        tm = TemplateManager()
        tpl_params = tm.load(args.tpl)
        if tpl_params:
            params.update(tpl_params)
            print(f"[信息] 使用模板 '{args.tpl}'")
        else:
            print(f"\n[错误] 模板 '{args.tpl}' 不存在，使用 --list-tpl 查看可用模板\n")
            sys.exit(1)

    # 命令行参数覆盖模板
    if args.file:
        params["file_keyword"] = args.file
    if args.user:
        params["user_keyword"] = args.user
    if args.date_from:
        try:
            params["date_from"] = parse_date(args.date_from)
        except ValueError as e:
            print(f"\n[错误] {e}\n")
            sys.exit(1)
    if args.date_to:
        try:
            params["date_to"] = parse_date(args.date_to)
            # 如果结束日期和起始日期相同，设置为当天末尾
            if params["date_from"] and params["date_to"].date() == params["date_from"].date():
                params["date_to"] = params["date_to"].replace(hour=23, minute=59, second=59)
        except ValueError as e:
            print(f"\n[错误] {e}\n")
            sys.exit(1)
    if args.action:
        action_list = [a.strip() for a in args.action.split(",")]
        invalid = [a for a in action_list if a not in ACTIONS]
        if invalid:
            print(f"\n[错误] 不支持的动作: {', '.join(invalid)}")
            print(f"       支持的动作: {', '.join(ACTIONS)}\n")
            sys.exit(1)
        params["actions"] = action_list

    # 保存模板
    if args.save_tpl:
        tm = TemplateManager()
        # 保存时转换日期为字符串
        save_params = dict(params)
        if save_params["date_from"]:
            save_params["date_from"] = save_params["date_from"].strftime("%Y-%m-%d")
        if save_params["date_to"]:
            save_params["date_to"] = save_params["date_to"].strftime("%Y-%m-%d")
        tm.save(args.save_tpl, save_params)
        print(f"\n[成功] 已保存模板 '{args.save_tpl}'\n")

    # 如果没有任何查询条件，显示帮助
    if not any([v for v in params.values()]):
        parser.print_help()
        return

    # 执行查询
    print("[信息] 正在加载日志数据...")
    records = load_logs()
    print(f"[信息] 已加载 {len(records)} 条日志记录")

    searcher = LogSearcher(records)
    results = searcher.search(**params)

    # 显示查询条件摘要
    print()
    cond_parts = []
    if params["file_keyword"]:
        cond_parts.append(f"文件='{params['file_keyword']}'")
    if params["user_keyword"]:
        cond_parts.append(f"用户='{params['user_keyword']}'")
    if params["date_from"] or params["date_to"]:
        df = params["date_from"].strftime("%Y-%m-%d") if params["date_from"] else "*"
        dt = params["date_to"].strftime("%Y-%m-%d") if params["date_to"] else "*"
        cond_parts.append(f"时间={df} ~ {dt}")
    if params["actions"]:
        cond_parts.append(f"动作=[{', '.join(params['actions'])}]")
    print(f"[检索条件] {' + '.join(cond_parts)}")

    # 显示结果
    display_results(results, max_show=args.limit)

    # 导出
    if args.export:
        output_path = Path(args.export)
        suffix = output_path.suffix.lower()

        if suffix == ".csv":
            Exporter.export_csv(results, output_path)
            fmt = "CSV 表格"
        else:
            if suffix != ".txt":
                output_path = output_path.with_suffix(".txt")
            Exporter.export_text(results, output_path)
            fmt = "纯文本"

        print(f"[导出] 已保存 {fmt} 格式: {output_path.resolve()}\n")


if __name__ == "__main__":
    main()
