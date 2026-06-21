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

# 高风险动作（风险视图）
RISK_ACTIONS = ["外链访问", "分享", "删除"]

# 夜间操作时间段（风险视图，00:00 - 06:00）
NIGHT_HOUR_START = 0
NIGHT_HOUR_END = 6

# 支持的时间格式（排序和匹配都用）
TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
)

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
# 统一时间解析（支持 ISO T 格式与普通格式混排）
# ============================================================
def parse_timestamp(ts_str):
    """
    解析任意支持格式的时间字符串，返回 datetime 对象
    失败则返回 None
    """
    if not ts_str:
        return None
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def is_night_operation(ts_str):
    """判断是否为夜间操作（00:00-06:00）"""
    dt = parse_timestamp(ts_str)
    if dt is None:
        return False
    return NIGHT_HOUR_START <= dt.hour < NIGHT_HOUR_END


# ============================================================
# 模拟数据生成
# ============================================================
def generate_mock_logs(count=500, output_path=None):
    """生成模拟的云盘访问日志（含 ISO T 格式时间混合）"""
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
        ts = now - timedelta(
            days=days_ago, hours=hours_ago, minutes=minutes_ago, seconds=seconds_ago
        )

        # 30% 概率使用 ISO T 格式，模拟真实混合数据
        if random.random() < 0.3:
            timestamp = ts.strftime("%Y-%m-%dT%H:%M:%S")
        else:
            timestamp = ts.strftime("%Y-%m-%d %H:%M:%S")

        record = {
            "timestamp": timestamp,
            "file_path": random.choice(FILE_PATHS),
            "action": random.choice(ACTIONS),
            "user": random.choice(USERS),
            "ip": "192.168.{}.{}".format(random.randint(1, 255), random.randint(1, 255)),
            "device": random.choice(["Windows PC", "MacBook", "iPhone", "Android", "Web"]),
        }
        records.append(record)

    # 按统一解析后的时间排序
    records.sort(key=lambda r: parse_timestamp(r["timestamp"]) or datetime.min, reverse=True)

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
                print("[警告] 忽略未知目标字段 '{}'，标准字段: {}".format(dst, ", ".join(STANDARD_FIELDS)))
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
    for field in STANDARD_FIELDS:
        if field not in normalized:
            normalized[field] = ""
    return normalized


def load_logs(input_path=None, field_mapping=None):
    """加载日志记录，支持 CSV 和 JSONL 格式"""
    if input_path is None:
        input_path = LOG_FILE
        if not Path(input_path).exists():
            print("[提示] 日志文件不存在，正在生成模拟数据...")
            count = generate_mock_logs(500, input_path)
            print("[完成] 已生成 {} 条模拟日志数据: {}".format(count, input_path))

    path = Path(input_path)
    if not path.exists():
        print("\n[错误] 日志文件不存在: {}\n".format(path))
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
                    print("[警告] 跳过第 {} 行，JSON 解析失败: {}".format(line_num, e))
    else:
        try:
            with open(path, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()
                if first_line.startswith("{") or first_line.startswith("["):
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
                    with open(path, "r", encoding="utf-8-sig", newline="") as f2:
                        reader = csv.DictReader(f2)
                        for row in reader:
                            records.append(normalize_record(dict(row), field_mapping or {}))
        except Exception as e:
            print("\n[错误] 无法识别文件格式，请使用 .csv 或 .jsonl 后缀: {}\n".format(e))
            sys.exit(1)

    return records


# ============================================================
# 日期解析辅助（保存相对日期原样，不立即计算）
# ============================================================
RELATIVE_DATE_KEYWORDS = ("today", "yesterday", "lastweek", "lastmonth")


def is_relative_date(date_str):
    """判断是否为相对日期（需要执行时再计算）"""
    if not isinstance(date_str, str):
        return False
    s = date_str.lower().strip()
    if s in RELATIVE_DATE_KEYWORDS:
        return True
    if s.endswith("days") and s[:-4].isdigit():
        return True
    return False


def parse_date(date_str, end_of_day=False):
    """
    解析日期字符串，支持多种格式
    - 如果是相对日期（today/7days 等），按当前时间动态计算
    - end_of_day=True 时返回当天 23:59:59
    """
    if not isinstance(date_str, str):
        return None

    # 先尝试相对日期
    s = date_str.lower().strip()
    now = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    parsed = None

    if s == "today":
        parsed = now
    elif s == "yesterday":
        parsed = now - timedelta(days=1)
    elif s == "lastweek":
        parsed = now - timedelta(days=7)
    elif s == "lastmonth":
        parsed = now - timedelta(days=30)
    elif s.endswith("days"):
        try:
            days = int(s[:-4])
            parsed = now - timedelta(days=days)
        except ValueError:
            pass

    # 再尝试绝对日期
    if parsed is None:
        formats = ["%Y-%m-%d", "%Y/%m/%d", "%Y%m%d"]
        for fmt in formats:
            try:
                parsed = datetime.strptime(date_str, fmt)
                break
            except ValueError:
                continue

    if parsed is None:
        raise ValueError("无法解析日期: {}".format(date_str))

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
        risk_only=False,
    ):
        """
        多条件组合检索
        - file_keyword/user_keyword 支持逗号分隔多值（批量审计）
        - risk_only=True 只返回风险记录（外链/分享/删除 + 夜间）
        返回匹配结果列表，每条记录附带命中原因
        """
        # 解析批量关键词
        file_keywords = None
        if file_keyword:
            file_keywords = [k.strip() for k in file_keyword.split(",") if k.strip()]
        user_keywords = None
        if user_keyword:
            user_keywords = [k.strip() for k in user_keyword.split(",") if k.strip()]

        results = []

        for record in self.records:
            matched = True
            hit_reasons = []

            # 文件关键词匹配（支持多值，任一命中即可）
            if file_keywords:
                fp = str(record.get("file_path", "")).lower()
                matched_any = False
                for kw in file_keywords:
                    if kw.lower() in fp:
                        hit_reasons.append("文件包含 '{}'".format(kw))
                        matched_any = True
                if not matched_any:
                    matched = False

            # 用户关键词匹配（支持多值，任一命中即可）
            if user_keywords and matched:
                usr = str(record.get("user", "")).lower()
                matched_any = False
                for kw in user_keywords:
                    if kw.lower() in usr:
                        hit_reasons.append("用户匹配 '{}'".format(kw))
                        matched_any = True
                if not matched_any:
                    matched = False

            # 日期范围匹配
            if matched and (date_from or date_to):
                record_date = parse_timestamp(record.get("timestamp", ""))
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
                        hit_reasons.append("时间在 {} ~ {} 内".format(df, dt))

            # 动作筛选
            if actions and matched:
                if record.get("action", "") in actions:
                    hit_reasons.append("动作为 '{}'".format(record["action"]))
                else:
                    matched = False

            # 风险视图过滤
            if risk_only and matched:
                is_risk_action = record.get("action", "") in RISK_ACTIONS
                is_night = is_night_operation(record.get("timestamp", ""))
                if is_risk_action or is_night:
                    risk_tags = []
                    if is_risk_action:
                        risk_tags.append("高风险动作")
                    if is_night:
                        risk_tags.append("夜间操作")
                    hit_reasons.append("风险: " + "+".join(risk_tags))
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
        对结果排序（支持 ISO T 格式与普通格式混排）
        sort_by: timestamp | file_path | user | action
        sort_order: asc | desc
        """
        if not results:
            return results

        reverse = (sort_order == "desc")

        def sort_key(r):
            val = r.get(sort_by, "")
            if sort_by == "timestamp":
                dt = parse_timestamp(val)
                return dt if dt is not None else datetime.min
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
# 批量审计分组：按文件关键词/用户关键词分块
# ============================================================
def build_batch_groups(results, file_keyword=None, user_keyword=None):
    """
    构建批量审计的分块数据
    返回: OrderedDict { group_label: [records...] }
    """
    groups = OrderedDict()

    if file_keyword:
        keywords = [k.strip() for k in file_keyword.split(",") if k.strip()]
        for kw in keywords:
            label = "文件关键词: {}".format(kw)
            matched = [r for r in results if kw.lower() in str(r.get("file_path", "")).lower()]
            if matched:
                groups[label] = matched
    elif user_keyword:
        keywords = [k.strip() for k in user_keyword.split(",") if k.strip()]
        for kw in keywords:
            label = "用户关键词: {}".format(kw)
            matched = [r for r in results if kw.lower() in str(r.get("user", "")).lower()]
            if matched:
                groups[label] = matched
    else:
        if results:
            groups["全部结果"] = results

    return groups


# ============================================================
# 统计汇总（增强版：含高风险统计）
# ============================================================
def build_summary(results, risk_only=False):
    """
    构建统计汇总：
    - 总数、最早/最晚时间
    - 按动作分组、按操作者分组
    - 高风险数量、涉及文件路径列表
    """
    summary = {
        "total": len(results),
        "earliest": None,
        "latest": None,
        "by_action": Counter(),
        "by_user": Counter(),
        "risk_total": 0,
        "risk_by_action": Counter(),
        "risk_files": [],
        "risk_night_count": 0,
    }
    if results:
        timestamps = []
        risk_file_set = set()
        for r in results:
            ts = r.get("timestamp", "")
            if ts:
                timestamps.append(ts)
            if r.get("action"):
                summary["by_action"][r["action"]] += 1
            if r.get("user"):
                summary["by_user"][r["user"]] += 1

            # 风险统计
            is_risk_action = r.get("action", "") in RISK_ACTIONS
            is_night = is_night_operation(ts)
            if is_risk_action or is_night:
                summary["risk_total"] += 1
                if is_risk_action:
                    summary["risk_by_action"][r["action"]] += 1
                if is_night:
                    summary["risk_night_count"] += 1
                if r.get("file_path"):
                    risk_file_set.add(r["file_path"])

        if timestamps:
            # 按统一解析后的时间排序
            sorted_pairs = sorted(
                [(parse_timestamp(t) or datetime.min, t) for t in timestamps],
                key=lambda x: x[0],
            )
            summary["earliest"] = sorted_pairs[0][1]
            summary["latest"] = sorted_pairs[-1][1]

        summary["risk_files"] = sorted(risk_file_set)

    return summary


# ============================================================
# 查询模板管理（增强：相对日期原样保存）
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
        """
        保存查询模板
        - 相对日期（today/7days 等）原样保存为字符串，执行时再动态计算
        - 绝对日期转为字符串保存
        """
        save_p = dict(params)
        # 日期处理：相对日期保留字符串，绝对日期格式化
        for dk in ("date_from", "date_to"):
            if isinstance(save_p.get(dk), datetime):
                save_p[dk] = save_p[dk].strftime("%Y-%m-%d")
            # 相对日期本来就是字符串，不需要转换
        self.templates[name] = {
            "params": save_p,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._save()

    def load(self, name):
        """加载查询模板"""
        if name in self.templates:
            return dict(self.templates[name]["params"])
        return None

    def list(self):
        return self.templates

    def delete(self, name):
        if name in self.templates:
            del self.templates[name]
            self._save()
            return True
        return False


# ============================================================
# 结果导出（增强：批量审计分块 + 风险汇总）
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
            lines.append("")
        if summary["risk_total"] > 0:
            lines.append("【高风险记录】")
            lines.append("  风险总数: {} 条".format(summary["risk_total"]))
            if summary["risk_by_action"]:
                lines.append("  风险动作分布:")
                for a, c in summary["risk_by_action"].most_common():
                    lines.append("    {:<8}  {} 条".format(a, c))
            if summary["risk_night_count"] > 0:
                lines.append("  夜间操作: {} 条".format(summary["risk_night_count"]))
            if summary["risk_files"]:
                lines.append("  涉及文件路径:")
                for fp in summary["risk_files"][:20]:
                    lines.append("    {}".format(fp))
                if len(summary["risk_files"]) > 20:
                    lines.append("    ... 等 {} 个文件".format(len(summary["risk_files"])))
        return lines

    @staticmethod
    def export_text(results, output_path, summary=None, batch_groups=None):
        """导出为纯文本（批量分块 + 风险汇总）"""
        if summary is None:
            summary = build_summary(results)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("云盘日志检索报告\n")
            f.write("=" * 80 + "\n\n")

            if batch_groups and len(batch_groups) > 1:
                # 批量审计分块模式
                for label, group in batch_groups.items():
                    f.write("\n" + "=" * 80 + "\n")
                    f.write("【{}】共 {} 条\n".format(label, len(group)))
                    f.write("=" * 80 + "\n\n")
                    for i, r in enumerate(group, 1):
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
            else:
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

            f.write("\n" + "=" * 80 + "\n")
            f.write("【统计汇总】\n")
            f.write("=" * 80 + "\n")
            for line in Exporter._format_summary_text(summary):
                f.write(line + "\n")
            f.write("\n导出时间: {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("=" * 80 + "\n")

    @staticmethod
    def export_csv(results, output_path, summary=None, batch_groups=None):
        """导出为 CSV（批量分块 + 风险汇总）"""
        if summary is None:
            summary = build_summary(results)
        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)

            if batch_groups and len(batch_groups) > 1:
                for label, group in batch_groups.items():
                    writer.writerow(["===== {} ===== (共 {} 条)".format(label, len(group))])
                    writer.writerow(["序号", "操作时间", "文件路径", "访问动作", "操作者", "IP", "设备", "命中原因"])
                    for i, r in enumerate(group, 1):
                        writer.writerow([
                            i, r.get("timestamp", ""), r.get("file_path", ""),
                            r.get("action", ""), r.get("user", ""),
                            r.get("ip", ""), r.get("device", ""),
                            ", ".join(r.get("hit_reasons", [])),
                        ])
                    writer.writerow([])
            else:
                writer.writerow(["序号", "操作时间", "文件路径", "访问动作", "操作者", "IP", "设备", "命中原因"])
                for i, r in enumerate(results, 1):
                    writer.writerow([
                        i, r.get("timestamp", ""), r.get("file_path", ""),
                        r.get("action", ""), r.get("user", ""),
                        r.get("ip", ""), r.get("device", ""),
                        ", ".join(r.get("hit_reasons", [])),
                    ])

            # 统计汇总
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
            if summary["risk_total"] > 0:
                writer.writerow(["高风险记录统计"])
                writer.writerow(["风险总数", summary["risk_total"]])
                if summary["risk_by_action"]:
                    writer.writerow(["风险动作分布"])
                    for a, c in summary["risk_by_action"].most_common():
                        writer.writerow([a, c])
                if summary["risk_night_count"] > 0:
                    writer.writerow(["夜间操作数", summary["risk_night_count"]])
                if summary["risk_files"]:
                    writer.writerow(["涉及文件"])
                    for fp in summary["risk_files"]:
                        writer.writerow([fp])
            writer.writerow([])
            writer.writerow(["导出时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])


# ============================================================
# 终端显示格式化（增强：批量分块 + 风险汇总）
# ============================================================
def display_results(results, max_show=50, summary=None, batch_groups=None):
    """终端展示（批量分块 + 风险汇总）"""
    if summary is None:
        summary = build_summary(results)

    if not results:
        print("\n[结果] 没有找到匹配的记录。\n")
        return

    total = len(results)
    show_count = min(total, max_show)

    if batch_groups and len(batch_groups) > 1:
        # ===== 批量审计分块模式 =====
        print()
        print("=" * 90)
        print("  【批量审计】共 {} 组，总 {} 条记录 (每组显示前 {} 条)".format(
            len(batch_groups), total, max_show
        ))
        print("=" * 90)

        for label, group in batch_groups.items():
            print()
            print("  " + "=" * 86)
            print("  【{}】共 {} 条".format(label, len(group)))
            print("  " + "=" * 86)

            gs = min(len(group), max_show)
            for i, r in enumerate(group[:gs], 1):
                reasons = " | ".join(r.get("hit_reasons", []))
                print()
                print("  [{:>3}] {}  |  {:>6}  |  {}".format(
                    i, r.get("timestamp", ""), r.get("action", ""), r.get("user", "")
                ))
                print("        文件: {}".format(r.get("file_path", "")))
                print("        命中: {}".format(reasons))

            if len(group) > gs:
                print("\n  ... 本组还有 {} 条，详见导出文件".format(len(group) - gs))
    else:
        # ===== 普通单组模式 =====
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

    # ===== 统计汇总 =====
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
    if summary["risk_total"] > 0:
        print()
        print("  【⚠ 高风险记录】共 {} 条".format(summary["risk_total"]))
        if summary["risk_by_action"]:
            parts = []
            for a, c in summary["risk_by_action"].most_common():
                parts.append("{} {}条".format(a, c))
            print("  风险动作: {}".format(", ".join(parts)))
        if summary["risk_night_count"] > 0:
            print("  夜间操作: {} 条".format(summary["risk_night_count"]))
        if summary["risk_files"]:
            print("  涉及文件 (前5个):")
            for fp in summary["risk_files"][:5]:
                print("    {}".format(fp))
            if len(summary["risk_files"]) > 5:
                print("    ... 共 {} 个文件，详见导出文件".format(len(summary["risk_files"])))
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

  # 批量审计（多关键词分块展示，贴工单方便）
  %(prog)s -f "合同,报表,项目"                 # 多个文件关键词
  %(prog)s -u "张伟,李娜,王磊"                 # 多个用户

  # 风险视图（外链访问+分享+删除+夜间操作）
  %(prog)s --risk                              # 只看高风险记录
  %(prog)s -f "合同" --risk --from "7days"     # 一周内合同文件的风险记录

  # 排序和分页
  %(prog)s -f "合同" --sort file_path --order asc
  %(prog)s -f "合同" --skip 20 --head 10

  # 模板（支持直接写模板名）
  %(prog)s --save-tpl weekly -f "合同" -a "外链访问" --from "7days" --to "today"
  %(prog)s weekly                              # 直接运行模板
  %(prog)s --tpl weekly                        # 或用参数形式

  # 导出
  %(prog)s -f "合同,报表" --export batch.csv
  %(prog)s --risk --export risk_report.txt
        """,
    )

    # 数据源
    parser.add_argument("-i", "--input", metavar="PATH", help="指定本地日志文件路径（支持 .csv / .jsonl）")
    parser.add_argument(
        "-m", "--map", dest="field_map", metavar="MAP",
        help="字段映射，格式: '源字段=标准字段,...'  标准字段: timestamp,file_path,action,user,ip,device",
    )

    # 三大查询方式（支持逗号分隔多值用于批量审计）
    parser.add_argument("-f", "--file", help="文件关键词搜索，多个用逗号分隔（批量审计自动分块）")
    parser.add_argument("-u", "--user", help="用户关键词搜索，多个用逗号分隔（批量审计自动分块）")
    parser.add_argument("--from", dest="date_from", help="起始日期 (YYYY-MM-DD, today, 7days)")
    parser.add_argument("--to", dest="date_to", help="结束日期 (YYYY-MM-DD, today)，按自然日包含全天")

    # 动作筛选
    parser.add_argument(
        "-a", "--action",
        help="动作条件筛选，多个用逗号分隔。支持: {}".format(", ".join(ACTIONS)),
    )

    # 风险视图
    parser.add_argument(
        "--risk", action="store_true",
        help="风险视图：只看高风险记录（外链访问/分享/删除 + 夜间 00:00-06:00），汇总单独列出",
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

    # 模板功能
    parser.add_argument("--tpl", metavar="NAME", help="使用已保存的查询模板")
    parser.add_argument("--save-tpl", metavar="NAME", help="将当前查询条件保存为模板（相对日期动态计算）")
    parser.add_argument("--list-tpl", action="store_true", help="列出所有查询模板")
    parser.add_argument("--del-tpl", metavar="NAME", help="删除指定查询模板")

    # 导出
    parser.add_argument("--export", metavar="PATH", help="导出结果到文件 (.txt 或 .csv)，含批量分块和风险汇总")
    parser.add_argument("--limit", type=int, default=50, help="终端显示条数上限 (默认: 50)")

    # 数据管理
    parser.add_argument("--gen-mock", type=int, metavar="N", help="生成 N 条模拟日志数据（含混合时间格式）")
    parser.add_argument("--gen-mock-csv", type=int, metavar="N", help="生成 N 条模拟日志（CSV 格式）")
    parser.add_argument("--log-path", action="store_true", help="显示默认日志文件路径")

    # 位置参数：直接写模板名即可运行
    parser.add_argument("template_name_pos", nargs="?", default=None, help=argparse.SUPPRESS)

    return parser


# ============================================================
# 模板描述辅助
# ============================================================
def describe_template_params(params):
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
    if params.get("risk_only"):
        parts.append("风险视图")
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

    # ===== 模板简化入口：位置参数直接是模板名 =====
    if args.template_name_pos:
        tm = TemplateManager()
        tpl = tm.load(args.template_name_pos)
        if tpl is not None:
            # 优先走模板路径：把位置参数填到 --tpl 上
            args.tpl = args.template_name_pos
        else:
            # 不是模板名，也没其他参数：提示
            has_other = any([
                args.file, args.user, args.date_from, args.date_to,
                args.action, args.risk, args.export, args.input,
                args.save_tpl, args.list_tpl, args.del_tpl,
                args.gen_mock, args.gen_mock_csv, args.log_path,
            ])
            if not has_other:
                print("\n[错误] '{}' 不是已保存的模板名，使用 --list-tpl 查看可用模板\n".format(
                    args.template_name_pos
                ))
                sys.exit(1)

    # ===== 纯管理命令 =====
    if args.list_tpl:
        tm = TemplateManager()
        tpls = tm.list()
        if not tpls:
            print("\n[信息] 暂无保存的查询模板。\n")
        else:
            print("\n" + "=" * 80)
            print("  已保存的查询模板（直接输入模板名即可运行）")
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
        print("\n[完成] 已生成 {} 条模拟日志数据 (JSONL，含混合时间格式): {}\n".format(count, LOG_FILE))
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
        "risk_only": False,
        "sort_by": "timestamp",
        "sort_order": "desc",
        "skip": 0,
        "head": None,
        "input_path": None,
        "field_map": None,
        "export_path": None,
        "limit": 50,
    }

    # 优先使用模板（完整覆盖参数）
    if args.tpl:
        tm = TemplateManager()
        tpl_params = tm.load(args.tpl)
        if tpl_params:
            params.update(tpl_params)
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
    if args.risk:
        params["risk_only"] = True

    # 日期处理：相对日期保留字符串，绝对日期转 datetime
    if args.date_from:
        if is_relative_date(args.date_from):
            params["date_from"] = args.date_from  # 保留原样
        else:
            try:
                params["date_from"] = parse_date(args.date_from, end_of_day=False)
            except ValueError as e:
                print("\n[错误] {}\n".format(e))
                sys.exit(1)

    if args.date_to:
        if is_relative_date(args.date_to):
            params["date_to"] = args.date_to  # 保留原样
        else:
            try:
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

    # 保存模板（相对日期保持字符串）
    if args.save_tpl:
        tm = TemplateManager()
        tm.save(args.save_tpl, params)
        print("\n[成功] 已保存模板 '{}'（相对日期将在每次执行时动态计算）\n".format(args.save_tpl))

    # 如果没有任何查询条件，显示帮助
    has_query = any([
        params["file_keyword"],
        params["user_keyword"],
        params["date_from"],
        params["date_to"],
        params["actions"],
        params["risk_only"],
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

    # 日期动态计算（模板中的相对日期字符串在这里解析）
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
        risk_only=params["risk_only"],
    )

    # 排序
    results = searcher.sort_results(results, params["sort_by"], params["sort_order"])

    # 分页
    results = searcher.paginate(results, params["skip"], params["head"])

    # 批量审计分组
    batch_groups = build_batch_groups(
        results,
        file_keyword=params["file_keyword"],
        user_keyword=params["user_keyword"],
    )

    # 统计汇总（含风险）
    summary = build_summary(results, risk_only=params["risk_only"])

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
    if params["risk_only"]:
        cond_parts.append("风险视图=开")
    sort_desc = "{}:{}".format(params["sort_by"], params["sort_order"])
    cond_parts.append("排序={}".format(sort_desc))
    if params["skip"] or params["head"]:
        cond_parts.append("分页=skip {} head {}".format(params["skip"], params["head"] or "ALL"))
    print("[检索条件] {}".format(" + ".join(cond_parts)))

    # ===== 显示结果 =====
    display_results(
        results,
        max_show=params["limit"],
        summary=summary,
        batch_groups=batch_groups,
    )

    # ===== 导出 =====
    export_path = params["export_path"]
    if export_path:
        output_path = Path(export_path)
        suffix = output_path.suffix.lower()

        if suffix == ".csv":
            Exporter.export_csv(results, output_path, summary, batch_groups)
            fmt = "CSV 表格"
        else:
            if suffix != ".txt":
                output_path = output_path.with_suffix(".txt")
            Exporter.export_text(results, output_path, summary, batch_groups)
            fmt = "纯文本"

        print("[导出] 已保存 {} 格式: {}\n".format(fmt, output_path.resolve()))


if __name__ == "__main__":
    main()
