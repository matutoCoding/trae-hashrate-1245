#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
极简命令行云盘日志检索器 - CloudLog
"""

import os
import sys
import json
import csv
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from collections import OrderedDict, Counter

APP_DIR = Path(__file__).resolve().parent
LOG_DIR = APP_DIR / "cloud_logs"
TEMPLATE_DIR = APP_DIR / "templates"
RULES_DIR = APP_DIR / "rules"
LOG_FILE = LOG_DIR / "audit_log.jsonl"

STANDARD_FIELDS = ["timestamp", "file_path", "action", "user", "ip", "device"]
ACTIONS = ["上传", "下载", "删除", "分享", "查看", "编辑", "移动", "复制", "重命名", "外链访问"]

RISK_LEVELS = OrderedDict([
    ("high",   {"label": "高风险", "icon": "🔴"}),
    ("medium", {"label": "中风险", "icon": "🟠"}),
    ("low",    {"label": "低风险", "icon": "🟡"}),
])

TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M",
)

GROUP_MODES = ["none", "file", "user", "file+user"]

DEFAULT_RULES = {
    "night_start": 0, "night_end": 6,
    "risk_actions_high": ["删除"],
    "risk_actions_medium": ["外链访问"],
    "risk_actions_low": ["分享"],
    "key_directories": [],
}

FILE_PATHS = [
    "/合同文档/2024Q2/客户A合作协议.pdf", "/合同文档/2024Q2/供应商B框架合同.docx",
    "/合同文档/2024Q3/客户C服务合同.pdf", "/合同文档/2024Q3/保密协议模板.docx",
    "/项目文档/项目Alpha/需求文档V1.2.docx", "/项目文档/项目Alpha/测试报告.xlsx",
    "/项目文档/项目Beta/项目计划.md", "/项目文档/项目Beta/风险评估.pdf",
    "/数据分析/2024Q2/用户行为分析.csv", "/数据分析/2024Q2/销售报表.xlsx",
    "/数据分析/2024Q3/市场调研数据.csv", "/数据分析/2024Q3/财务报表_final.xlsx",
    "/共享资源/设计规范/UI组件库.fig", "/共享资源/设计规范/品牌手册.pdf",
    "/开发文档/API接口文档V2.0.md", "/开发文档/数据库设计.sql",
    "/人事行政/2024Q2/员工培训资料.pdf", "/人事行政/2024Q3/招聘计划.xlsx",
]

USERS = [
    "张伟(zhangwei)", "李娜(lina)", "王磊(wanglei)", "刘芳(liufang)",
    "陈超(chenchao)", "赵敏(zhaomin)", "孙浩(sunhao)", "周静(zhoujing)",
    "吴磊(wulei)", "郑雪(zhengxue)",
]


def parse_timestamp(ts_str):
    if not ts_str:
        return None
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def is_night_operation(ts_str, rules=None):
    r = rules or DEFAULT_RULES
    dt = parse_timestamp(ts_str)
    if dt is None:
        return False
    return r["night_start"] <= dt.hour < r["night_end"]


def assess_risk(record, rules=None):
    r = rules or DEFAULT_RULES
    action = record.get("action", "")
    ts = record.get("timestamp", "")
    is_night = is_night_operation(ts, r)
    fp = str(record.get("file_path", ""))

    is_high = action in r["risk_actions_high"]
    is_med = action in r["risk_actions_medium"]
    is_low = action in r["risk_actions_low"]
    in_key_dir = any(kd.lower() in fp.lower() for kd in r.get("key_directories", []))

    level = None
    reasons = []

    if (is_high and is_night) or (is_med and is_night) or (is_high and in_key_dir):
        level = "high"
        if is_high and is_night:
            reasons.append("夜间+{}".format(action))
        if is_med and is_night:
            reasons.append("夜间+{}".format(action))
        if is_high and in_key_dir:
            reasons.append("重点目录+{}".format(action))
    elif is_high or (is_med and in_key_dir) or (is_low and is_night):
        level = "medium"
        if is_high:
            reasons.append(action)
        if is_med and in_key_dir:
            reasons.append("重点目录+{}".format(action))
        if is_low and is_night:
            reasons.append("夜间+{}".format(action))
    elif is_med or is_low or is_night:
        level = "low"
        if is_med:
            reasons.append(action)
        if is_low:
            reasons.append(action)
        if is_night:
            reasons.append("夜间操作")
        if in_key_dir:
            reasons.append("重点目录")

    return level, "+".join(reasons) if reasons else ""


def load_rules(name=None):
    if name is None:
        return dict(DEFAULT_RULES)
    RULES_DIR.mkdir(exist_ok=True)
    path = RULES_DIR / "{}.json".format(name)
    if not path.exists():
        print("[警告] 规则 '{}' 不存在，使用默认规则".format(name))
        return dict(DEFAULT_RULES)
    with open(path, "r", encoding="utf-8") as f:
        rules = json.load(f)
    for k, v in DEFAULT_RULES.items():
        if k not in rules:
            rules[k] = v
    return rules


def save_rules(name, rules):
    RULES_DIR.mkdir(exist_ok=True)
    path = RULES_DIR / "{}.json".format(name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rules, f, ensure_ascii=False, indent=2)


def list_rules():
    RULES_DIR.mkdir(exist_ok=True)
    return sorted(p.stem for p in RULES_DIR.glob("*.json"))


def describe_rules(rules):
    parts = ["夜间 {}-{}时".format(rules["night_start"], rules["night_end"])]
    if rules.get("risk_actions_high"):
        parts.append("高风险=[{}]".format(",".join(rules["risk_actions_high"])))
    if rules.get("risk_actions_medium"):
        parts.append("中风险=[{}]".format(",".join(rules["risk_actions_medium"])))
    if rules.get("risk_actions_low"):
        parts.append("低风险=[{}]".format(",".join(rules["risk_actions_low"])))
    if rules.get("key_directories"):
        parts.append("重点目录=[{}]".format(",".join(rules["key_directories"])))
    return " | ".join(parts)


def generate_mock_logs(count=500, output_path=None):
    import random
    if output_path is None:
        output_path = LOG_FILE
    Path(output_path).parent.mkdir(exist_ok=True)
    records = []
    now = datetime.now()
    for i in range(count):
        ts = now - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23),
                             minutes=random.randint(0, 59), seconds=random.randint(0, 59))
        timestamp = ts.strftime("%Y-%m-%dT%H:%M:%S") if random.random() < 0.3 else ts.strftime("%Y-%m-%d %H:%M:%S")
        records.append({
            "timestamp": timestamp,
            "file_path": random.choice(FILE_PATHS),
            "action": random.choice(ACTIONS),
            "user": random.choice(USERS),
            "ip": "192.168.{}.{}".format(random.randint(1, 255), random.randint(1, 255)),
            "device": random.choice(["Windows PC", "MacBook", "iPhone", "Android", "Web"]),
        })
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


def parse_field_mapping(map_str):
    mapping = {}
    if not map_str:
        return mapping
    for pair in map_str.split(","):
        pair = pair.strip()
        if "=" in pair:
            src, dst = pair.split("=", 1)
            src, dst = src.strip(), dst.strip()
            if dst in STANDARD_FIELDS:
                mapping[src] = dst
    return mapping


def normalize_record(record, field_mapping):
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
    if input_path is None:
        input_path = LOG_FILE
        if not Path(input_path).exists():
            print("[提示] 日志文件不存在，正在生成模拟数据...")
            count = generate_mock_logs(500, input_path)
            print("[完成] 已生成 {} 条模拟日志: {}".format(count, input_path))
    path = Path(input_path)
    if not path.exists():
        print("\n[错误] 日志文件不存在: {}\n".format(path))
        sys.exit(1)
    suffix = path.suffix.lower()
    records = []
    if suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                records.append(normalize_record(dict(row), field_mapping or {}))
    elif suffix in (".jsonl", ".json", ".log"):
        with open(path, "r", encoding="utf-8") as f:
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
        try:
            with open(path, "r", encoding="utf-8") as f:
                first = f.readline().strip()
            if first.startswith("{") or first.startswith("["):
                with open(path, "r", encoding="utf-8") as f:
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
                    for row in csv.DictReader(f2):
                        records.append(normalize_record(dict(row), field_mapping or {}))
        except Exception as e:
            print("\n[错误] 无法识别文件格式: {}\n".format(e))
            sys.exit(1)
    return records


RELATIVE_DATE_KEYWORDS = ("today", "yesterday", "lastweek", "lastmonth")


def is_relative_date(date_str):
    if not isinstance(date_str, str):
        return False
    s = date_str.lower().strip()
    return s in RELATIVE_DATE_KEYWORDS or (s.endswith("days") and s[:-4].isdigit())


def parse_date(date_str, end_of_day=False):
    if not isinstance(date_str, str):
        return None
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
            parsed = now - timedelta(days=int(s[:-4]))
        except ValueError:
            pass
    if parsed is None:
        for fmt in ["%Y-%m-%d", "%Y/%m/%d", "%Y%m%d"]:
            try:
                parsed = datetime.strptime(date_str, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        raise ValueError("无法解析日期: {}".format(date_str))
    if end_of_day:
        parsed = parsed.replace(hour=23, minute=59, second=59)
    return parsed


class LogSearcher:
    def __init__(self, records, rules=None):
        self.records = records
        self.rules = rules

    def search(self, file_keyword=None, user_keyword=None,
               date_from=None, date_to=None, actions=None, risk_only=False):
        fks = [k.strip() for k in file_keyword.split(",") if k.strip()] if file_keyword else None
        uks = [k.strip() for k in user_keyword.split(",") if k.strip()] if user_keyword else None
        results = []
        for record in self.records:
            matched = True
            hit_reasons = []
            if fks:
                fp = str(record.get("file_path", "")).lower()
                if not any(kw.lower() in fp for kw in fks):
                    matched = False
                else:
                    for kw in fks:
                        if kw.lower() in fp:
                            hit_reasons.append("文件包含 '{}'".format(kw))
            if uks and matched:
                usr = str(record.get("user", "")).lower()
                if not any(kw.lower() in usr for kw in uks):
                    matched = False
                else:
                    for kw in uks:
                        if kw.lower() in usr:
                            hit_reasons.append("用户匹配 '{}'".format(kw))
            if matched and (date_from or date_to):
                rd = parse_timestamp(record.get("timestamp", ""))
                if rd is None:
                    matched = False
                else:
                    if date_from and rd < date_from:
                        matched = False
                    elif date_to and rd > date_to:
                        matched = False
                    elif matched:
                        hit_reasons.append("时间 {}~{}".format(
                            date_from.strftime("%Y-%m-%d") if date_from else "*",
                            date_to.strftime("%Y-%m-%d") if date_to else "*"))
            if actions and matched:
                if record.get("action", "") in actions:
                    hit_reasons.append("动作 '{}'".format(record["action"]))
                else:
                    matched = False
            if risk_only and matched:
                rl, rr = assess_risk(record, self.rules)
                if rl is not None:
                    hit_reasons.append("风险: {}({})".format(RISK_LEVELS[rl]["label"], rr))
                else:
                    matched = False
            if matched:
                result = dict(record)
                result["hit_reasons"] = hit_reasons if hit_reasons else ["全量匹配"]
                rl, rr = assess_risk(result, self.rules)
                result["risk_level"] = rl
                result["risk_reason"] = rr
                results.append(result)
        return results

    @staticmethod
    def sort_results(results, sort_by="timestamp", sort_order="desc"):
        if not results:
            return results
        reverse = sort_order == "desc"

        def sk(r):
            val = r.get(sort_by, "")
            if sort_by == "timestamp":
                dt = parse_timestamp(val)
                return dt if dt is not None else datetime.min
            return (val or "").lower()

        return sorted(results, key=sk, reverse=reverse)

    @staticmethod
    def paginate(results, skip=0, head=None):
        start = max(0, skip)
        if head is None or head <= 0:
            return results[start:]
        return results[start:start + head]


def build_batch_groups(results, file_keyword=None, user_keyword=None, group_mode="auto"):
    groups = OrderedDict()
    if group_mode == "none" or not results:
        if results:
            groups["全部结果"] = results
        return groups
    fks = [k.strip() for k in file_keyword.split(",") if k.strip()] if file_keyword else []
    uks = [k.strip() for k in user_keyword.split(",") if k.strip()] if user_keyword else []
    if group_mode == "auto":
        if len(fks) > 1 and len(uks) > 1:
            group_mode = "file+user"
        elif len(fks) > 1:
            group_mode = "file"
        elif len(uks) > 1:
            group_mode = "user"
        else:
            if results:
                groups["全部结果"] = results
            return groups
    if group_mode == "file":
        for kw in (fks or [""]):
            label = "文件: {}".format(kw) if kw else "全部文件"
            m = [r for r in results if not kw or kw.lower() in str(r.get("file_path", "")).lower()]
            if m:
                groups[label] = m
    elif group_mode == "user":
        for kw in (uks or [""]):
            label = "用户: {}".format(kw) if kw else "全部用户"
            m = [r for r in results if not kw or kw.lower() in str(r.get("user", "")).lower()]
            if m:
                groups[label] = m
    elif group_mode == "file+user":
        for fkw in (fks or [""]):
            for ukw in (uks or [""]):
                parts = []
                if fkw:
                    parts.append("文件={}".format(fkw))
                if ukw:
                    parts.append("用户={}".format(ukw))
                label = " + ".join(parts) if parts else "全部结果"
                m = [r for r in results
                     if (not fkw or fkw.lower() in str(r.get("file_path", "")).lower())
                     and (not ukw or ukw.lower() in str(r.get("user", "")).lower())]
                if m:
                    groups[label] = m
    return groups


def build_summary(results, rules=None):
    r = rules or DEFAULT_RULES
    summary = {
        "total": len(results), "earliest": None, "latest": None,
        "by_action": Counter(), "by_user": Counter(),
        "risk_total": 0, "risk_by_action": Counter(), "risk_by_level": Counter(),
        "risk_files": [], "risk_night_count": 0,
    }
    if results:
        timestamps = []
        risk_file_set = set()
        all_risk_actions = r.get("risk_actions_high", []) + r.get("risk_actions_medium", []) + r.get("risk_actions_low", [])
        for rec in results:
            ts = rec.get("timestamp", "")
            if ts:
                timestamps.append(ts)
            if rec.get("action"):
                summary["by_action"][rec["action"]] += 1
            if rec.get("user"):
                summary["by_user"][rec["user"]] += 1
            rl = rec.get("risk_level")
            if rl is not None:
                summary["risk_total"] += 1
                summary["risk_by_level"][rl] += 1
                if rec.get("action") in all_risk_actions:
                    summary["risk_by_action"][rec["action"]] += 1
                if is_night_operation(ts, r):
                    summary["risk_night_count"] += 1
                if rec.get("file_path"):
                    risk_file_set.add(rec["file_path"])
        if timestamps:
            sp = sorted([(parse_timestamp(t) or datetime.min, t) for t in timestamps], key=lambda x: x[0])
            summary["earliest"] = sp[0][1]
            summary["latest"] = sp[-1][1]
        summary["risk_files"] = sorted(risk_file_set)
    return summary


def generate_conclusion(summary, results, rules=None):
    lines = ["本次审计共检索 {} 条记录".format(summary["total"])]
    if summary["risk_total"] > 0:
        lines.append("发现风险记录 {} 条".format(summary["risk_total"]))
        lp = []
        for lvl, info in RISK_LEVELS.items():
            if lvl in summary["risk_by_level"]:
                lp.append("{} {} {}条".format(info["icon"], info["label"], summary["risk_by_level"][lvl]))
        if lp:
            lines.append("风险等级: {}".format(", ".join(lp)))
    else:
        lines.append("未发现风险记录")
    if summary["risk_total"] > 0 and results:
        ru = Counter()
        for r in results:
            if r.get("risk_level"):
                ru[r.get("user", "")] += 1
        if ru:
            top = ru.most_common(3)
            lines.append("高频风险操作者: {}".format(", ".join("{}({}次)".format(u, c) for u, c in top)))
    if summary["risk_files"]:
        lines.append("重点关注文件:")
        for fp in summary["risk_files"][:3]:
            lines.append("  - {}".format(fp))
    return lines


def compare_summaries(sa, la, sb, lb):
    diff = {
        "label_a": la, "label_b": lb,
        "total_a": sa["total"], "total_b": sb["total"],
        "total_delta": sb["total"] - sa["total"],
        "risk_a": sa["risk_total"], "risk_b": sb["risk_total"],
        "risk_delta": sb["risk_total"] - sa["risk_total"],
        "level_changes": {},
        "new_risk_actions": [], "reduced_risk_actions": [],
        "new_risk_files": [], "reduced_risk_files": [],
        "top_user_changes": [],
    }
    for lvl in RISK_LEVELS:
        ca = sa["risk_by_level"].get(lvl, 0)
        cb = sb["risk_by_level"].get(lvl, 0)
        if ca != cb:
            diff["level_changes"][lvl] = {"a": ca, "b": cb, "delta": cb - ca}
    diff["new_risk_actions"] = sorted(set(sb["risk_by_action"]) - set(sa["risk_by_action"]))
    diff["reduced_risk_actions"] = sorted(set(sa["risk_by_action"]) - set(sb["risk_by_action"]))
    diff["new_risk_files"] = sorted(set(sb["risk_files"]) - set(sa["risk_files"]))
    diff["reduced_risk_files"] = sorted(set(sa["risk_files"]) - set(sb["risk_files"]))
    top_a = [u for u, _ in sa["by_user"].most_common(5)]
    top_b = [u for u, _ in sb["by_user"].most_common(5)]
    diff["top_user_changes"] = sorted(set(top_b) - set(top_a))
    return diff


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
        sp = dict(params)
        for dk in ("date_from", "date_to", "compare_a_from", "compare_a_to", "compare_b_from", "compare_b_to"):
            if isinstance(sp.get(dk), datetime):
                sp[dk] = sp[dk].strftime("%Y-%m-%d")
        self.templates[name] = {"params": sp, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        self._save()

    def load(self, name):
        return dict(self.templates[name]["params"]) if name in self.templates else None

    def list(self):
        return self.templates

    def delete(self, name):
        if name in self.templates:
            del self.templates[name]
            self._save()
            return True
        return False


class Exporter:
    def _report_header(self, params):
        lines = []
        title = params.get("report_title", "")
        if title:
            lines.append("{}".format(title))
            lines.append("=" * len(title))
        biz = params.get("business_line", "")
        if biz:
            lines.append("业务线: {}".format(biz))
        owner = params.get("owner", "")
        if owner:
            lines.append("负责人: {}".format(owner))
        rn = params.get("rules_name", "")
        if rn:
            lines.append("规则集: {}".format(rn))
        if lines:
            lines.append("")
        return lines

    def _format_summary_text(self, summary, rules):
        lines = []
        lines.append("统计摘要")
        lines.append("-" * 40)
        lines.append("总记录数: {}".format(summary["total"]))
        if summary.get("earliest"):
            lines.append("最早时间: {}".format(summary["earliest"]))
        if summary.get("latest"):
            lines.append("最晚时间: {}".format(summary["latest"]))
        if summary["by_action"]:
            lines.append("操作分布:")
            for action, count in summary["by_action"].most_common():
                lines.append("  {}: {}".format(action, count))
        if summary["risk_total"] > 0:
            lines.append("风险记录: {} 条".format(summary["risk_total"]))
            for lvl, info in RISK_LEVELS.items():
                if lvl in summary["risk_by_level"]:
                    lines.append("  {} {}: {} 条".format(info["icon"], info["label"], summary["risk_by_level"][lvl]))
            if summary.get("risk_night_count"):
                lines.append("  夜间风险操作: {} 次".format(summary["risk_night_count"]))
        return lines

    def _format_conclusion_text(self, conclusion):
        return list(conclusion)

    def _format_comparison_text(self, diff):
        lines = []
        if not diff:
            return lines
        lines.append("对比分析: {} vs {}".format(diff["label_a"], diff["label_b"]))
        lines.append("-" * 40)
        td = diff["total_delta"]
        sign = "+" if td > 0 else ""
        lines.append("记录数: {} -> {} ({}{})".format(diff["total_a"], diff["total_b"], sign, td))
        rd = diff["risk_delta"]
        sign = "+" if rd > 0 else ""
        lines.append("风险记录: {} -> {} ({}{})".format(diff["risk_a"], diff["risk_b"], sign, rd))
        for lvl, info in RISK_LEVELS.items():
            if lvl in diff.get("level_changes", {}):
                ch = diff["level_changes"][lvl]
                d = ch["delta"]
                sign = "+" if d > 0 else ""
                lines.append("  {} {}: {} -> {} ({}{})".format(info["icon"], info["label"], ch["a"], ch["b"], sign, d))
        if diff.get("new_risk_actions"):
            lines.append("新增风险操作: {}".format(", ".join(diff["new_risk_actions"])))
        if diff.get("reduced_risk_actions"):
            lines.append("减少风险操作: {}".format(", ".join(diff["reduced_risk_actions"])))
        if diff.get("new_risk_files"):
            lines.append("新增风险文件:")
            for fp in diff["new_risk_files"][:5]:
                lines.append("  + {}".format(fp))
        if diff.get("reduced_risk_files"):
            lines.append("减少风险文件:")
            for fp in diff["reduced_risk_files"][:5]:
                lines.append("  - {}".format(fp))
        if diff.get("top_user_changes"):
            lines.append("新增高频用户: {}".format(", ".join(diff["top_user_changes"])))
        return lines

    def _record_lines(self, r):
        lines = []
        rl = r.get("risk_level")
        tag = ""
        if rl and rl in RISK_LEVELS:
            tag = " [{}{}]".format(RISK_LEVELS[rl]["icon"], RISK_LEVELS[rl]["label"])
        lines.append("  {} {} {} {} {}{} {}".format(
            r.get("timestamp", ""), r.get("user", ""), r.get("action", ""),
            r.get("file_path", ""), r.get("ip", ""), tag,
            r.get("device", "")))
        rr = r.get("risk_reason", "")
        if rr:
            lines.append("    原因: {}".format(rr))
        return lines

    def export_text(self, results, output_path, summary, batch_groups, params, conclusion, comparison_diff, rules):
        lines = self._report_header(params)
        if conclusion:
            lines.extend(self._format_conclusion_text(conclusion))
            lines.append("")
        if comparison_diff:
            lines.extend(self._format_comparison_text(comparison_diff))
            lines.append("")
        lines.extend(self._format_summary_text(summary, rules))
        lines.append("")
        for group_name, group_results in batch_groups.items():
            if len(batch_groups) > 1:
                lines.append("[{}] ({} 条)".format(group_name, len(group_results)))
            for r in group_results:
                lines.extend(self._record_lines(r))
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print("[导出] 文本报告: {}".format(output_path))

    def export_csv(self, results, output_path, summary, batch_groups, params, conclusion, comparison_diff, rules):
        fieldnames = list(STANDARD_FIELDS) + ["risk_level", "risk_reason", "hit_reasons"]
        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in results:
                row = {k: r.get(k, "") for k in fieldnames}
                if isinstance(row.get("hit_reasons"), list):
                    row["hit_reasons"] = "; ".join(row["hit_reasons"])
                writer.writerow(row)
        print("[导出] CSV报告: {}".format(output_path))

    def export_markdown(self, results, output_path, summary, batch_groups, params, conclusion, comparison_diff, rules):
        lines = self._report_header(params)
        if conclusion:
            lines.append("## 审计结论")
            lines.append("")
            for c in conclusion:
                lines.append("- {}".format(c))
            lines.append("")
        if comparison_diff:
            lines.append("## 对比分析")
            lines.append("")
            lines.extend(self._format_comparison_text(comparison_diff))
            lines.append("")
        lines.append("## 统计摘要")
        lines.append("")
        lines.extend(self._format_summary_text(summary, rules))
        lines.append("")
        lines.append("## 风险详情")
        lines.append("")
        for group_name, group_results in batch_groups.items():
            if len(batch_groups) > 1:
                lines.append("### {}".format(group_name))
                lines.append("")
            lines.append("| 时间 | 用户 | 操作 | 文件 | IP | 风险 |")
            lines.append("|------|------|------|------|-----|------|")
            for r in group_results:
                rl = r.get("risk_level", "")
                if rl and rl in RISK_LEVELS:
                    rl = "{} {}".format(RISK_LEVELS[rl]["icon"], RISK_LEVELS[rl]["label"])
                lines.append("| {} | {} | {} | {} | {} | {} |".format(
                    r.get("timestamp", ""), r.get("user", ""), r.get("action", ""),
                    r.get("file_path", ""), r.get("ip", ""), rl))
            lines.append("")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print("[导出] Markdown报告: {}".format(output_path))


def display_results(results, batch_groups, summary, params, conclusion=None, comparison_diff=None):
    print()
    if conclusion:
        print("审计结论")
        print("-" * 40)
        for line in conclusion:
            print(line)
        print()
    if comparison_diff:
        print("对比分析: {} vs {}".format(comparison_diff["label_a"], comparison_diff["label_b"]))
        print("-" * 40)
        td = comparison_diff["total_delta"]
        sign = "+" if td > 0 else ""
        print("记录数: {} -> {} ({}{})".format(comparison_diff["total_a"], comparison_diff["total_b"], sign, td))
        rd = comparison_diff["risk_delta"]
        sign = "+" if rd > 0 else ""
        print("风险记录: {} -> {} ({}{})".format(comparison_diff["risk_a"], comparison_diff["risk_b"], sign, rd))
        for lvl, info in RISK_LEVELS.items():
            if lvl in comparison_diff.get("level_changes", {}):
                ch = comparison_diff["level_changes"][lvl]
                d = ch["delta"]
                sign = "+" if d > 0 else ""
                print("  {} {}: {} -> {} ({}{})".format(info["icon"], info["label"], ch["a"], ch["b"], sign, d))
        if comparison_diff.get("new_risk_actions"):
            print("新增风险操作: {}".format(", ".join(comparison_diff["new_risk_actions"])))
        if comparison_diff.get("new_risk_files"):
            print("新增风险文件: {}".format(", ".join(comparison_diff["new_risk_files"][:5])))
        print()
    print("统计摘要")
    print("-" * 40)
    print("总记录数: {}".format(summary["total"]))
    if summary.get("earliest"):
        print("最早时间: {}".format(summary["earliest"]))
    if summary.get("latest"):
        print("最晚时间: {}".format(summary["latest"]))
    if summary["risk_total"] > 0:
        print("风险记录: {} 条".format(summary["risk_total"]))
        for lvl, info in RISK_LEVELS.items():
            if lvl in summary["risk_by_level"]:
                print("  {} {}: {} 条".format(info["icon"], info["label"], summary["risk_by_level"][lvl]))
    print()
    for group_name, group_results in batch_groups.items():
        if len(batch_groups) > 1:
            print("[{}] ({} 条)".format(group_name, len(group_results)))
        for r in group_results:
            rl = r.get("risk_level")
            tag = ""
            if rl and rl in RISK_LEVELS:
                tag = " [{}{}]".format(RISK_LEVELS[rl]["icon"], RISK_LEVELS[rl]["label"])
            print("  {} {} {} {} {}{} {}".format(
                r.get("timestamp", ""), r.get("user", ""), r.get("action", ""),
                r.get("file_path", ""), r.get("ip", ""), tag, r.get("device", "")))
            rr = r.get("risk_reason", "")
            if rr:
                print("    原因: {}".format(rr))
    print()
    print("共 {} 条结果 ({} 条风险)".format(summary["total"], summary["risk_total"]))


def build_parser():
    parser = argparse.ArgumentParser(description="极简命令行云盘日志检索器 - CloudLog")
    parser.add_argument("template", nargs="?", default=None, help="模板名称(位置参数)")
    parser.add_argument("-f", "--file", dest="file_keyword", help="文件关键词(逗号分隔)")
    parser.add_argument("-u", "--user", dest="user_keyword", help="用户关键词(逗号分隔)")
    parser.add_argument("--from", dest="date_from", help="起始日期")
    parser.add_argument("--to", dest="date_to", help="结束日期")
    parser.add_argument("-a", "--actions", help="操作类型(逗号分隔)")
    parser.add_argument("--risk", action="store_true", help="仅显示风险记录")
    parser.add_argument("--group-by", dest="group_by", choices=["auto", "none", "file", "user", "file+user"], default="auto")
    parser.add_argument("--sort", dest="sort", default="timestamp", help="排序字段")
    parser.add_argument("--order", dest="order", choices=["asc", "desc"], default="desc")
    parser.add_argument("--skip", type=int, default=0)
    parser.add_argument("--head", type=int, default=None)
    parser.add_argument("--export", dest="export", help="导出路径(逗号分隔多格式)")
    parser.add_argument("--limit", type=int, default=None, help="最大返回数")
    parser.add_argument("--tpl", dest="tpl", help="加载模板名称")
    parser.add_argument("--save-tpl", dest="save_tpl", help="保存模板名称")
    parser.add_argument("--list-tpl", dest="list_tpl", action="store_true", help="列出模板")
    parser.add_argument("--del-tpl", dest="del_tpl", help="删除模板")
    parser.add_argument("--gen-mock", dest="gen_mock", type=int, default=None, help="生成模拟日志条数")
    parser.add_argument("--gen-mock-csv", dest="gen_mock_csv", action="store_true", help="生成CSV格式模拟日志")
    parser.add_argument("--log-path", dest="log_path", help="日志文件路径")
    parser.add_argument("--rule", dest="rule", help="规则集名称")
    parser.add_argument("--save-rule", dest="save_rule", help="保存规则集名称")
    parser.add_argument("--list-rules", dest="list_rules", action="store_true", help="列出规则集")
    parser.add_argument("--del-rule", dest="del_rule", help="删除规则集")
    parser.add_argument("--rule-night", dest="rule_night", help="夜间时段 START-END")
    parser.add_argument("--rule-high", dest="rule_high", help="高风险操作(逗号分隔)")
    parser.add_argument("--rule-medium", dest="rule_medium", help="中风险操作(逗号分隔)")
    parser.add_argument("--rule-low", dest="rule_low", help="低风险操作(逗号分隔)")
    parser.add_argument("--rule-dir", dest="rule_dir", help="重点目录(逗号分隔)")
    parser.add_argument("--compare", dest="compare", help="对比模式A时段偏移(如14days)")
    parser.add_argument("--compare-b", dest="compare_b", help="对比模式B时段偏移")
    parser.add_argument("--title", dest="title", help="报告标题")
    parser.add_argument("--biz", dest="biz", help="业务线")
    parser.add_argument("--owner", dest="owner", help="负责人")
    return parser


def describe_template_params(params):
    parts = []
    if params.get("file_keyword"):
        parts.append("文件={}".format(params["file_keyword"]))
    if params.get("user_keyword"):
        parts.append("用户={}".format(params["user_keyword"]))
    if params.get("date_from"):
        parts.append("从={}".format(params["date_from"]))
    if params.get("date_to"):
        parts.append("到={}".format(params["date_to"]))
    if params.get("actions"):
        parts.append("操作={}".format(params["actions"]))
    if params.get("risk"):
        parts.append("仅风险")
    if params.get("sort"):
        parts.append("排序={}".format(params["sort"]))
    if params.get("compare"):
        parts.append("对比={}".format(params["compare"]))
    return " | ".join(parts) if parts else "默认模板"


def main():
    parser = build_parser()
    args = parser.parse_args()

    tpl_mgr = TemplateManager()

    if args.template:
        loaded = tpl_mgr.load(args.template)
        if loaded:
            for k, v in loaded.items():
                if not hasattr(args, k) or getattr(args, k) is None:
                    setattr(args, k, v)
            print("[模板] 已加载模板 '{}'".format(args.template))

    if args.list_rules:
        rules_list = list_rules()
        if rules_list:
            print("已保存的规则集:")
            for name in rules_list:
                r = load_rules(name)
                print("  {}: {}".format(name, describe_rules(r)))
        else:
            print("暂无保存的规则集")
        return

    if args.del_rule:
        RULES_DIR.mkdir(exist_ok=True)
        path = RULES_DIR / "{}.json".format(args.del_rule)
        if path.exists():
            path.unlink()
            print("[删除] 规则集 '{}'".format(args.del_rule))
        else:
            print("[警告] 规则集 '{}' 不存在".format(args.del_rule))
        return

    if args.list_tpl:
        tpls = tpl_mgr.list()
        if tpls:
            print("已保存的模板:")
            for name, data in tpls.items():
                p = data.get("params", {})
                ca = data.get("created_at", "")
                print("  {} ({}): {}".format(name, ca, describe_template_params(p)))
        else:
            print("暂无保存的模板")
        return

    if args.del_tpl:
        if tpl_mgr.delete(args.del_tpl):
            print("[删除] 模板 '{}'".format(args.del_tpl))
        else:
            print("[警告] 模板 '{}' 不存在".format(args.del_tpl))
        return

    log_file = LOG_FILE

    if args.log_path:
        log_file = Path(args.log_path)

    if args.gen_mock is not None:
        out = log_file
        if args.gen_mock_csv:
            out = LOG_DIR / "audit_log.csv"
        count = generate_mock_logs(args.gen_mock or 500, out)
        print("[完成] 已生成 {} 条模拟日志: {}".format(count, out))
        return

    params = {
        "file_keyword": args.file_keyword,
        "user_keyword": args.user_keyword,
        "date_from": args.date_from,
        "date_to": args.date_to,
        "actions": args.actions,
        "risk_only": args.risk,
        "group_by": args.group_by,
        "sort": args.sort,
        "sort_order": args.order,
        "skip": args.skip,
        "head": args.head,
        "limit": args.limit,
        "rules_name": getattr(args, "rule", None),
        "compare": getattr(args, "compare", None),
        "compare_b": getattr(args, "compare_b", None),
        "report_title": getattr(args, "title", None),
        "business_line": getattr(args, "biz", None),
        "owner": getattr(args, "owner", None),
    }

    if args.tpl:
        loaded = tpl_mgr.load(args.tpl)
        if loaded:
            for k, v in loaded.items():
                if k not in params or params[k] is None:
                    params[k] = v
            print("[模板] 已加载模板 '{}'".format(args.tpl))

    def is_explicitly_set(attr_name):
        val = getattr(args, attr_name, None)
        return val is not None and val is not False and val != ""

    rules = load_rules(args.rule)

    if args.tpl and not args.rule:
        loaded = tpl_mgr.load(args.tpl)
        if loaded and "rules" in loaded:
            rules = loaded["rules"]

    if is_explicitly_set("rule_night"):
        parts = args.rule_night.split("-")
        if len(parts) == 2:
            rules["night_start"] = int(parts[0])
            rules["night_end"] = int(parts[1])
    if is_explicitly_set("rule_high"):
        rules["risk_actions_high"] = [a.strip() for a in args.rule_high.split(",") if a.strip()]
    if is_explicitly_set("rule_medium"):
        rules["risk_actions_medium"] = [a.strip() for a in args.rule_medium.split(",") if a.strip()]
    if is_explicitly_set("rule_low"):
        rules["risk_actions_low"] = [a.strip() for a in args.rule_low.split(",") if a.strip()]
    if is_explicitly_set("rule_dir"):
        rules["key_directories"] = [d.strip() for d in args.rule_dir.split(",") if d.strip()]

    if args.save_rule:
        save_rules(args.save_rule, rules)
        print("[保存] 规则集 '{}'".format(args.save_rule))

    if args.save_tpl:
        tpl_mgr.save(args.save_tpl, params)
        print("[保存] 模板 '{}'".format(args.save_tpl))

    records = load_logs(log_file)

    date_from = parse_date(params["date_from"]) if params.get("date_from") else None
    date_to = parse_date(params["date_to"], end_of_day=True) if params.get("date_to") else None
    actions = [a.strip() for a in params["actions"].split(",") if a.strip()] if params.get("actions") else None

    searcher = LogSearcher(records, rules)
    results = searcher.search(
        file_keyword=params.get("file_keyword"),
        user_keyword=params.get("user_keyword"),
        date_from=date_from, date_to=date_to,
        actions=actions, risk_only=params.get("risk_only", False),
    )

    comparison_diff = None

    if args.compare:
        offset_str = args.compare.lower().strip()
        if offset_str.endswith("days"):
            try:
                offset_days = int(offset_str[:-4])
            except ValueError:
                offset_days = 14
        else:
            try:
                offset_days = int(offset_str)
            except ValueError:
                offset_days = 14

        b_from = date_from
        b_to = date_to
        if b_from and b_to:
            span = (b_to - b_from).days + 1
            a_to = b_from - timedelta(days=1)
            a_from = a_to - timedelta(days=span - 1)
        else:
            if b_to:
                a_to = b_to - timedelta(days=offset_days)
            else:
                a_to = datetime.now() - timedelta(days=offset_days)
            a_from = a_to - timedelta(days=offset_days)

        a_results = searcher.search(
            file_keyword=params.get("file_keyword"),
            user_keyword=params.get("user_keyword"),
            date_from=a_from, date_to=a_to,
            actions=actions, risk_only=params.get("risk_only", False),
        )
        sa = build_summary(a_results, rules)
        sb = build_summary(results, rules)
        la = "A期({}~{})".format(a_from.strftime("%Y-%m-%d"), a_to.strftime("%Y-%m-%d"))
        lb = "B期({}~{})".format(
            b_from.strftime("%Y-%m-%d") if b_from else "*",
            b_to.strftime("%Y-%m-%d") if b_to else "*")
        comparison_diff = compare_summaries(sa, la, sb, lb)
        params["compare_a_from"] = a_from
        params["compare_a_to"] = a_to
        params["compare_b_from"] = b_from
        params["compare_b_to"] = b_to

    if params.get("limit"):
        results = results[:params["limit"]]

    results = LogSearcher.sort_results(results, params.get("sort", "timestamp"), params.get("sort_order", "desc"))
    results = LogSearcher.paginate(results, params.get("skip", 0), params.get("head"))

    batch_groups = build_batch_groups(results, params.get("file_keyword"), params.get("user_keyword"), params.get("group_by", "auto"))
    summary = build_summary(results, rules)
    conclusion = generate_conclusion(summary, results, rules)

    display_results(results, batch_groups, summary, params, conclusion, comparison_diff)

    if args.export:
        exporter = Exporter()
        paths = [p.strip() for p in args.export.split(",") if p.strip()]
        for output_path in paths:
            suffix = Path(output_path).suffix.lower()
            if suffix == ".csv":
                exporter.export_csv(results, output_path, summary, batch_groups, params, conclusion, comparison_diff, rules)
            elif suffix == ".md":
                exporter.export_markdown(results, output_path, summary, batch_groups, params, conclusion, comparison_diff, rules)
            else:
                exporter.export_text(results, output_path, summary, batch_groups, params, conclusion, comparison_diff, rules)


if __name__ == "__main__":
    main()
