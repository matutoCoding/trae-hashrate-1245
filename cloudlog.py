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
from collections import OrderedDict, Counter

# ============================================================
# 配置
# ============================================================
APP_DIR = Path(__file__).resolve().parent
LOG_DIR = APP_DIR / "cloud_logs"
TEMPLATE_DIR = APP_DIR / "templates"
LOG_FILE = LOG_DIR / "audit_log.jsonl"

# 标准字段名（内部统一使用）
STANDARD_FIELDS = ["timestamp", "file_path", "action", "user", "ip", "device"]

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
def generate_mock_logs(count=500, output_path=None):
    """生成模拟的云盘访问日志"""
    import random

    if output_path is None:
        output_path = LOG_FILE
    Path(output_path).parent.mkdir(exist_ok=True)

    records = []
    now = datetime.now()

    for i in range(count):
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

    records.sort(key=lambda x: x["timestamp"], reverse=True)

    suffix = Path(output_path).suffix.lower()
    if suffix == ".csv":
        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=STANDARD_FIELDS)
            writer.writeheader()
            for record in records:
                writer.writerow(record)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return count


# ============================================================
# 日志加载（支持 CSV / JSONL + 字段映射）
# ============================================================
def parse_field_mapping(map_str):
    """解析字段映射字符串，如 '时间=timestamp,路径=file_path'"""
    mapping = {}
    if not map_str:
        return mapping
    for pair in map_str.split(","):
        pair = pair.strip()
        if "=" in pair:
            src, dst = pair.split("=", 1)
            src = src.strip()
            dst = dst.strip()
            if dst in STANDARD_FIELDS:
                mapping[src] = dst
            else:
                print(f"[警告] 忽略未知目标字段 '{dst}'，标准字段: {', '.join(STANDARD_FIELDS)}")
    return mapping


def normalize_record(record, field_mapping):
    """将记录字段名标准化为内部统一格式"""
    normalized = {}
    for key, value in record.items():
        if key in field_mapping:
            normalized[field_mapping[key]] = value
        elif key in STANDARD_FIELDS:
            normalized[key] = value
        else:
            normalized[key] = value
    # 确保所有标准字段都存在（填充默认值）
    for field in STANDARD_FIELDS:
        if field not in normalized:
            normalized[field] = ""
    return normalized


def load_logs(input_path=None, field_mapping=None):
    """加载日志记录，支持 CSV 和 JSONL 格式，支持字段映射"""
    # 如果未指定路径，使用默认路径
    if input_path is None:
        input_path = LOG_FILE
        # 默认路径不存在则生成模拟数据
        if not Path(input_path).exists():
            print(f"[提示] 日志文件不存在，正在生成模拟数据...")
            count = generate_mock_logs(500, input_path)
            print(f"[完成] 已生成 {count} 条模拟日志数据: {input_path}")

    path = Path(input_path)
    if not path.exists():
        print(f"\n[错误] 日志文件不存在: {path}\n")
        sys.exit(1)

    suffix = path.suffix.lower()
    records = []

    if suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(normalize_record(dict(row), field_mapping or {}))
    elif suffix in (".jsonl", ".json", ".log"):
        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, list):
                        for item in obj:
                            records.append(normalize_record(item, field_mapping or {}))
                    elif isinstance(obj, dict):
                        records.append(normalize_record(obj, field_mapping or {}))
                except json.JSONDecodeError as e:
                    print(f"[警告] 跳过第 {line_num} 行，JSON 解析失败: {e}")
    else:
        # 尝试按 JSONL 读取，失败则按 CSV
        try:
            with open(path, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()
                if first_line.startswith("{") or first_line.startswith("["):
                    # JSONL 格式
                    if first_line:
                        try:
                            obj = json.loads(first_line)
                            if isinstance(obj, list):
                                for item in obj:
                                    records.append(normalize_record(item, field_mapping or {}))
                            else:
                                records.append(normalize_record(obj, field_mapping or {}))
                        except json.JSONDecodeError:
                            pass
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            if isinstance(obj, list):
                                for item in obj:
                                    records.append(normalize_record(item, field_mapping or {}))
                            else:
                                records.append(normalize_record(obj, field_mapping or {}))
                        except json.JSONDecodeError:
                            pass
                else:
                    # CSV 格式
                    with open(path, "r", encoding="utf-8-sig", newline="") as f2:
                        reader = csv.DictReader(f2)
                        for row in reader:
                            records.append(normalize_record(dict(row), field_mapping or {}))
        except Exception as e:
            print(f"\n[错误] 无法识别文件格式，请使用 .csv 或 .jsonl 后缀: {e}\n")
            sys.exit(1)

    return records


# ============================================================
# 日期解析辅助（含自然日修复）
# ============================================================
def parse_date(date_str, end_of_day=False):
    """
    解析日期字符串，支持多种格式
    end_of_day=True 时返回当天 23:59:59（用于结束日期按自然日包含全天）
    """
    formats = [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%Y%m%d",
    ]
    parsed = None
    for fmt in formats:
        try:
            parsed = datetime.strptime(date_str, fmt)
            break
        except ValueError:
            continue

    if parsed is None:
        # 支持相对日期，如 "today", "3days", "lastweek"
        now = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        if date_str.lower() == "today":
            parsed = now
        elif date_str.lower() == "yesterday":
            parsed = now - timedelta(days=1)
        elif date_str.lower().endswith("days"):
            try:
                days = int(date_str.lower().replace("days", ""))
                parsed = now - timedelta(days=days)
            except ValueError:
                pass
        elif date_str.lower() == "lastweek":
            parsed = now - timedelta(days=7)
        elif date_str.lower() == "lastmonth":
            parsed = now - timedelta(days=30)

    if parsed is None:
        raise ValueError(f"无法解析日期: {date_str}")

    if end_of_day:
        parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=0)

    return parsed


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
                if file_keyword.lower() in str(record.get("file_path", "")).lower():
                    hit_reasons.append(f"文件包含 '{file_keyword}'")
                else:
                    matched = False

            # 用户关键词匹配
            if user_keyword and matched:
                if user_keyword.lower() in str(record.get("user", "")).lower():
                    hit_reasons.append(f"用户匹配 '{user_keyword}'")
                else:
                    matched = False

            # 日期范围匹配
            if matched and (date_from or date_to):
                try:
                    ts = record.get("timestamp", "")
                    if ts:
                        # 尝试多种时间格式
                        record_date = None
                        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
                            try:
                                record_date = datetime.strptime(ts, fmt)
                                break
                            except ValueError:
                                continue
                        if record_date is None:
                            matched = False
                        else:
                            if date_from and record_date < date_from:
                                matched = False
                            elif date_to and record_date > date_to:
                                matched = False
                            elif matched:
                                df = date_from.strftime("%Y-%m-%d") if date_from else "*"
                                dt = date_to.strftime("%Y-%m-%d") if date_to else "*"
                                hit_reasons.append(f"时间在 {df} ~ {dt} 内")
                    else:
                        matched = False
                except Exception:
                    matched = False

            # 动作筛选
            if actions and matched:
                if record.get("action", "") in actions:
                    hit_reasons.append(f"动作为 '{record['action']}'")
                else:
                    matched = False

            if matched:
                result = dict(record)
                result["hit_reasons"] = hit_reasons if hit_reasons else ["全量匹配"]
                results.append(result)

        return results

    @staticmethod
    def sort_results(results, sort_by="timestamp", sort_order="desc"):
        """
        对结果排序
        sort_by: timestamp | file_path | user | action
        sort_order: asc | desc
        """
        if not results:
            return results

        reverse = (sort_order == "desc")

        def sort_key(r):
            val = r.get(sort_by, "")
            if sort_by == "timestamp":
                try:
                    return datetime.strptime(val, "%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    return datetime.min
            return (val or "").lower()

        return sorted(results, key=sort_key, reverse=reverse)

    @staticmethod
    def paginate(results, skip=0, head=None):
        """分页：跳过前 skip 条，取前 head 条"""
        start = max(0, skip)
        if head is None or head <= 0:
            return results[start:]
        return results[start : start + head]


# ============================================================
# 统计汇总
# ============================================================
def build_summary(results):
    """构建统计汇总：总数、最早/最晚时间、按动作分组、按操作者分组"""
    summary = {
        "total": len(results),
        "earliest": None,
        "latest": None,
        "by_action": Counter(),
        "by_user": Counter(),
    }
    if results:
        timestamps = []
        for r in results:
            ts = r.get("timestamp", "")
            if ts:
                timestamps.append(ts)
            if r.get("action"):
                summary["by_action"][r["action"]] += 1
            if r.get("user"):
                summary["by_user"][r["user"]] += 1
        if timestamps:
            sorted_ts = sorted(timestamps)
            summary["earliest"] = sorted_ts[0]
            summary["latest"] = sorted_ts[-1]
    return summary


# ============================================================
# 查询模板管理（增强版：保存完整参数）
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
        """保存查询模板（含完整参数：日期、动作、排序、分页、导出格式等）"""
        self.templates[name] = {
            "params": params,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._save()

    def load(self, name):
        """加载查询模板"""
        if name in self.templates:
            return dict(self.templates[name]["params"])
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
# 结果导出（增强版：含分组汇总）
# ============================================================
class Exporter:
    @staticmethod
    def _format_summary_text(summary):
        lines = []
        lines.append("总记录数: {}".format(summary["total"]))
        if summary["earliest"]:
            lines.append("最早访问: {}".format(summary["earliest"]))
        if summary["latest"]:
            lines.append("最晚访问: {}".format(summary["latest"]))
        lines.append("")
        if summary["by_action"]:
            lines.append("按动作统计:")
            for action, cnt in summary["by_action"].most_common():
                lines.append("  {:<8}  {} 条".format(action, cnt))
            lines.append("")
        if summary["by_user"]:
            lines.append("按操作者统计:")
            for user, cnt in summary["by_user"].most_common():
                lines.append("  {:<20}  {} 条".format(user, cnt))
        return lines

    @staticmethod
    def export_text(results, output_path, summary=None):
        """导出为纯文本格式（含分组汇总）"""
        if summary is None:
            summary = build_summary(results)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("云盘日志检索报告\n")
            f.write("=" * 80 + "\n\n")

            for i, r in enumerate(results, 1):
                f.write("[{}] 操作时间: {}\n".format(i, r.get("timestamp", "")))
                f.write("    文件路径: {}\n".format(r.get("file_path", "")))
                f.write("    访问动作: {}\n".format(r.get("action", "")))
                f.write("    操作者:   {}\n".format(r.get("user", "")))
                device = r.get("device", "")
                ip = r.get("ip", "")
                if device or ip:
                    f.write("    终端设备: {} ({})\n".format(device, ip))
                f.write("    命中原因: {}\n".format(", ".join(r.get("hit_reasons", []))))
                f.write("-" * 80 + "\n")

            # 统计信息
            f.write("\n" + "=" * 80 + "\n")
            f.write("【统计汇总】\n")
            f.write("=" * 80 + "\n")
            for line in Exporter._format_summary_text(summary):
                f.write(line + "\n")
            f.write("\n导出时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 80 + "\n")

    @staticmethod
    def export_csv(results, output_path, summary=None):
        """导出为 CSV 表格格式（含分组汇总）"""
        if summary is None:
            summary = build_summary(results)
        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["序号", "操作时间", "文件路径", "访问动作", "操作者", "IP", "设备", "命中原因"])
            for i, r in enumerate(results, 1):
                writer.writerow([
                    i,
                    r.get("timestamp", ""),
                    r.get("file_path", ""),
                    r.get("action", ""),
                    r.get("user", ""),
                    r.get("ip", ""),
                    r.get("device", ""),
                    ", ".join(r.get("hit_reasons", [])),
                ])

            # 统计信息
            writer.writerow([])
            writer.writerow(["===== 统计汇总 ====="])
            writer.writerow(["总记录数", summary["total"]])
            if summary["earliest"]:
                writer.writerow(["最早访问", summary["earliest"]])
            if summary["latest"]:
                writer.writerow(["最晚访问", summary["latest"]])
            writer.writerow([])
            if summary["by_action"]:
                writer.writerow(["按动作统计"])
                writer.writerow(["动作", "数量"])
                for action, cnt in summary["by_action"].most_common():
                    writer.writerow([action, cnt])
                writer.writerow([])
            if summary["by_user"]:
                writer.writerow(["按操作者统计"])
                writer.writerow(["操作者", "数量"])
                for user, cnt in summary["by_user"].most_common():
                    writer.writerow([user, cnt])
            writer.writerow([])
            writer.writerow(["导出时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])


# ============================================================
# 终端显示格式化（增强版：排序/分页/汇总）
# ============================================================
def display_results(results, max_show=50, summary=None):
    """在终端以清晰列表展示结果（含分组汇总）"""
    if summary is None:
        summary = build_summary(results)

    if not results:
        print("\n[结果] 没有找到匹配的记录。\n")
        return

    total = len(results)
    show_count = min(total, max_show)

    print()
    print("=" * 90)
    print("  检索结果: 共 {} 条记录 (显示前 {} 条)".format(total, show_count))
    print("=" * 90)

    for i, r in enumerate(results[:show_count], 1):
        reasons = " | ".join(r.get("hit_reasons", []))
        print()
        print("  [{:>3}] {}  |  {:>6}  |  {}".format(
            i, r.get("timestamp", ""), r.get("action", ""), r.get("user", "")
        ))
        print("        文件: {}".format(r.get("file_path", "")))
        print("        命中: {}".format(reasons))
        print("  " + "-" * 86)

    if total > show_count:
        print("\n  [提示] 还有 {} 条记录未显示，可使用 --skip {} --head {} 查看下一页，或 --export 导出全部".format(
            total - show_count, show_count, max_show
        ))

    # 统计汇总
    print()
    print("  " + "=" * 86)
    print("  【统计汇总】")
    print("  " + "=" * 86)
    print("  总记录数: {}".format(summary["total"]))
    if summary["earliest"]:
        print("  最早访问: {}".format(summary["earliest"]))
    if summary["latest"]:
        print("  最晚访问: {}".format(summary["latest"]))
    if summary["by_action"]:
        print()
        print("  按动作统计:")
        for action, cnt in summary["by_action"].most_common():
            print("    {:<8}  {} 条".format(action, cnt))
    if summary["by_user"]:
        print()
        print("  按操作者统计 (Top 5):")
        for user, cnt in summary["by_user"].most_common(5):
            print("    {:<20}  {} 条".format(user, cnt))
        if len(summary["by_user"]) > 5:
            print("    ... 共 {} 位操作者，详见导出文件".format(len(summary["by_user"])))
    print()


# ============================================================
# 命令行参数解析
# ============================================================
def build_parser():
    parser = argparse.ArgumentParser(
        description="CloudLog - 极简云盘日志检索器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基础查询
  %(prog)s -f "合同"                          # 按文件关键词查
  %(prog)s -u "张伟"                          # 按用户查
  %(prog)s --from 2024-06-01 --to 2024-06-30  # 按时间范围查
  %(prog)s -f "合同" -a 下载,分享              # 追加动作条件

  # 自定义日志文件 + 字段映射
  %(prog)s -i audit.csv -m "时间=timestamp,路径=file_path,操作=action,用户=user" -f "合同"

  # 排序和分页
  %(prog)s -f "合同" --sort file_path --order asc  # 按文件路径排序
  %(prog)s -f "合同" --skip 20 --head 10           # 跳过20条，取10条（分页）

  # 模板（保存完整查询+排序+导出设置，一键复用）
  %(prog)s --save-tpl daily_contract -f "合同" -a 外链访问 --sort timestamp --export report.csv
  %(prog)s --tpl daily_contract                    # 执行模板（含导出）
  %(prog)s --list-tpl                              # 列出所有模板

  # 导出（含分组统计）
  %(prog)s -f "合同" --export report.txt
  %(prog)s -f "合同" --export report.csv
        """,
    )

    # 数据源
    parser.add_argument("-i", "--input", metavar="PATH", help="指定本地日志文件路径（支持 .csv / .jsonl）")
    parser.add_argument(
        "-m", "--map", dest="field_map", metavar="MAP",
        help="字段映射，格式: '源字段=标准字段,...'  标准字段: timestamp,file_path,action,user,ip,device",
    )

    # 三大查询方式
    parser.add_argument("-f", "--file", help="文件关键词搜索")
    parser.add_argument("-u", "--user", help="用户关键词搜索")
    parser.add_argument("--from", dest="date_from", help="起始日期 (YYYY-MM-DD, today, 7days)")
    parser.add_argument("--to", dest="date_to", help="结束日期 (YYYY-MM-DD, today)，按自然日包含全天")

    # 动作筛选
    parser.add_argument(
        "-a", "--action",
        help="动作条件筛选，多个用逗号分隔。支持: {}".format(", ".join(ACTIONS)),
    )

    # 排序
    parser.add_argument(
        "--sort", dest="sort_by", default="timestamp",
        choices=["timestamp", "file_path", "user", "action"],
        help="排序字段 (默认: timestamp)",
    )
    parser.add_argument(
        "--order", default="desc", choices=["asc", "desc"],
        help="排序方向: asc=升序, desc=降序 (默认: desc)",
    )

    # 分页
    parser.add_argument("--skip", type=int, default=0, help="跳过前 N 条记录 (默认: 0)")
    parser.add_argument("--head", type=int, default=None, help="只取前 N 条记录（默认全部）")

    # 模板功能（增强）
    parser.add_argument("--tpl", metavar="NAME", help="使用已保存的查询模板（完整复用所有参数，含导出）")
    parser.add_argument("--save-tpl", metavar="NAME", help="将当前完整查询条件保存为模板（含日期/动作/排序/导出）")
    parser.add_argument("--list-tpl", action="store_true", help="列出所有查询模板")
    parser.add_argument("--del-tpl", metavar="NAME", help="删除指定查询模板")

    # 导出功能
    parser.add_argument("--export", metavar="PATH", help="导出结果到文件 (.txt 或 .csv)，含分组统计")
    parser.add_argument("--limit", type=int, default=50, help="终端显示条数上限 (默认: 50)")

    # 数据管理
    parser.add_argument("--gen-mock", type=int, metavar="N", help="生成 N 条模拟日志数据")
    parser.add_argument("--gen-mock-csv", type=int, metavar="N", help="生成 N 条模拟日志（CSV 格式）")
    parser.add_argument("--log-path", action="store_true", help="显示默认日志文件路径")

    return parser


# ============================================================
# 模板描述辅助
# ============================================================
def describe_template_params(params):
    """将模板参数转换为可读描述"""
    parts = []
    if params.get("file_keyword"):
        parts.append('文件="{}"'.format(params["file_keyword"]))
    if params.get("user_keyword"):
        parts.append('用户="{}"'.format(params["user_keyword"]))
    if params.get("date_from") or params.get("date_to"):
        df = params.get("date_from") or "*"
        dt = params.get("date_to") or "*"
        parts.append("时间={}~{}".format(df, dt))
    if params.get("actions"):
        parts.append("动作=[{}]".format(",".join(params["actions"])))
    if params.get("sort_by"):
        parts.append("排序={}:{}".format(params["sort_by"], params.get("sort_order", "desc")))
    if params.get("skip"):
        parts.append("跳过={}".format(params["skip"]))
    if params.get("head"):
        parts.append("取前={}".format(params["head"]))
    if params.get("export_path"):
        parts.append("导出={}".format(params["export_path"]))
    return " | ".join(parts) if parts else "(空)"


# ============================================================
# 主程序入口
# ============================================================
def main():
    parser = build_parser()
    args = parser.parse_args()

    # ===== 纯管理命令，不执行查询 =====
    if args.list_tpl:
        tm = TemplateManager()
        tpls = tm.list()
        if not tpls:
            print("\n[信息] 暂无保存的查询模板。\n")
        else:
            print("\n" + "=" * 80)
            print("  已保存的查询模板")
            print("=" * 80)
            for name, data in sorted(tpls.items()):
                desc = describe_template_params(data["params"])
                print("  {:<22}  {}".format(name, desc))
                print("  {:<22}  创建于: {}".format("", data["created_at"]))
                print("  " + "-" * 76)
            print()
        return

    if args.del_tpl:
        tm = TemplateManager()
        if tm.delete(args.del_tpl):
            print("\n[成功] 已删除模板 '{}'\n".format(args.del_tpl))
        else:
            print("\n[错误] 模板 '{}' 不存在\n".format(args.del_tpl))
        return

    if args.gen_mock:
        count = generate_mock_logs(args.gen_mock)
        print("\n[完成] 已生成 {} 条模拟日志数据 (JSONL): {}\n".format(count, LOG_FILE))
        return

    if args.gen_mock_csv:
        csv_path = LOG_DIR / "audit_log.csv"
        count = generate_mock_logs(args.gen_mock_csv, csv_path)
        print("\n[完成] 已生成 {} 条模拟日志数据 (CSV): {}\n".format(count, csv_path))
        return

    if args.log_path:
        print("\n{}\n".format(LOG_FILE))
        return

    # ===== 构建完整参数集 =====
    params = {
        "file_keyword": None,
        "user_keyword": None,
        "date_from": None,
        "date_to": None,
        "actions": None,
        "sort_by": "timestamp",
        "sort_order": "desc",
        "skip": 0,
        "head": None,
        "input_path": None,
        "field_map": None,
        "export_path": None,
        "limit": 50,
    }

    # 优先使用模板（完整覆盖所有参数）
    tpl_used = None
    if args.tpl:
        tm = TemplateManager()
        tpl_params = tm.load(args.tpl)
        if tpl_params:
            params.update(tpl_params)
            tpl_used = args.tpl
            print("[信息] 使用模板 '{}'".format(args.tpl))
        else:
            print("\n[错误] 模板 '{}' 不存在，使用 --list-tpl 查看可用模板\n".format(args.tpl))
            sys.exit(1)

    # 命令行参数覆盖模板
    if args.input:
        params["input_path"] = args.input
    if args.field_map:
        params["field_map"] = args.field_map
    if args.file:
        params["file_keyword"] = args.file
    if args.user:
        params["user_keyword"] = args.user

    if args.date_from:
        try:
            params["date_from"] = parse_date(args.date_from, end_of_day=False)
        except ValueError as e:
            print("\n[错误] {}\n".format(e))
            sys.exit(1)

    if args.date_to:
        try:
            # 结束日期按自然日包含当天所有记录（23:59:59）
            params["date_to"] = parse_date(args.date_to, end_of_day=True)
        except ValueError as e:
            print("\n[错误] {}\n".format(e))
            sys.exit(1)

    if args.action:
        action_list = [a.strip() for a in args.action.split(",")]
        invalid = [a for a in action_list if a not in ACTIONS]
        if invalid:
            print("\n[错误] 不支持的动作: {}".format(", ".join(invalid)))
            print("       支持的动作: {}\n".format(", ".join(ACTIONS)))
            sys.exit(1)
        params["actions"] = action_list

    if args.sort_by:
        params["sort_by"] = args.sort_by
    if args.order:
        params["sort_order"] = args.order
    if args.skip:
        params["skip"] = args.skip
    if args.head is not None:
        params["head"] = args.head
    if args.export:
        params["export_path"] = args.export
    if args.limit:
        params["limit"] = args.limit

    # 保存模板（保存完整参数集）
    if args.save_tpl:
        tm = TemplateManager()
        save_params = dict(params)
        # 日期转为字符串存储
        if isinstance(save_params["date_from"], datetime):
            save_params["date_from"] = save_params["date_from"].strftime("%Y-%m-%d")
        if isinstance(save_params["date_to"], datetime):
            save_params["date_to"] = save_params["date_to"].strftime("%Y-%m-%d")
        tm.save(args.save_tpl, save_params)
        print("\n[成功] 已保存模板 '{}'（含完整查询/排序/导出参数）\n".format(args.save_tpl))

    # 如果没有任何查询条件，显示帮助
    has_query = any([
        params["file_keyword"],
        params["user_keyword"],
        params["date_from"],
        params["date_to"],
        params["actions"],
    ])
    if not has_query:
        parser.print_help()
        return

    # ===== 加载日志 =====
    print("[信息] 正在加载日志数据...")
    field_mapping = parse_field_mapping(params["field_map"])
    if params["input_path"]:
        print("[信息] 读取文件: {}".format(params["input_path"]))
        if field_mapping:
            print("[信息] 字段映射: {}".format(field_mapping))
    records = load_logs(params["input_path"], field_mapping)
    print("[信息] 已加载 {} 条日志记录".format(len(records)))

    # ===== 执行查询 =====
    searcher = LogSearcher(records)

    # 模板中的日期需要从字符串转回 datetime
    search_date_from = params["date_from"]
    search_date_to = params["date_to"]
    if isinstance(search_date_from, str):
        try:
            search_date_from = parse_date(search_date_from, end_of_day=False)
        except ValueError:
            search_date_from = None
    if isinstance(search_date_to, str):
        try:
            search_date_to = parse_date(search_date_to, end_of_day=True)
        except ValueError:
            search_date_to = None

    results = searcher.search(
        file_keyword=params["file_keyword"],
        user_keyword=params["user_keyword"],
        date_from=search_date_from,
        date_to=search_date_to,
        actions=params["actions"],
    )

    # 排序
    results = searcher.sort_results(results, params["sort_by"], params["sort_order"])

    # 分页（skip + head）
    results = searcher.paginate(results, params["skip"], params["head"])

    # 统计汇总
    summary = build_summary(results)

    # ===== 显示查询条件摘要 =====
    print()
    cond_parts = []
    if params["file_keyword"]:
        cond_parts.append('文件="{}"'.format(params["file_keyword"]))
    if params["user_keyword"]:
        cond_parts.append('用户="{}"'.format(params["user_keyword"]))
    if search_date_from or search_date_to:
        df = search_date_from.strftime("%Y-%m-%d") if search_date_from else "*"
        dt = search_date_to.strftime("%Y-%m-%d") if search_date_to else "*"
        cond_parts.append("时间={}~{}".format(df, dt))
    if params["actions"]:
        cond_parts.append("动作=[{}]".format(", ".join(params["actions"])))
    sort_desc = "{}:{}".format(params["sort_by"], params["sort_order"])
    cond_parts.append("排序={}".format(sort_desc))
    if params["skip"] or params["head"]:
        cond_parts.append("分页=skip {} head {}".format(params["skip"], params["head"] or "ALL"))
    print("[检索条件] {}".format(" + ".join(cond_parts)))

    # ===== 显示结果 =====
    display_results(results, max_show=params["limit"], summary=summary)

    # ===== 导出 =====
    export_path = params["export_path"]
    if export_path:
        output_path = Path(export_path)
        suffix = output_path.suffix.lower()

        if suffix == ".csv":
            Exporter.export_csv(results, output_path, summary)
            fmt = "CSV 表格"
        else:
            if suffix != ".txt":
                output_path = output_path.with_suffix(".txt")
            Exporter.export_text(results, output_path, summary)
            fmt = "纯文本"

        print("[导出] 已保存 {} 格式: {}\n".format(fmt, output_path.resolve()))


if __name__ == "__main__":
    main()
