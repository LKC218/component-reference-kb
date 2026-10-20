"""知识库只读检查、轻量索引生成与检索；使用 Python 3.10 以上标准库。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import unicodedata
from datetime import date
from urllib.parse import parse_qsl, urlsplit, urlunsplit


VERSION = 1
IMAGE_LIMIT = 300 * 1024
PDF_LIMIT = 2 * 1024 * 1024
TEXT_LIMIT = 1024 * 1024
TOTAL_LIMIT = 100 * 1024 * 1024
STATES = {"已核实", "待核实", "已排除"}
KINDS = {"元件网站", "实拍", "图纸", "CAD获取地址"}
METHODS = {"本地资料回收", "在线核对"}
IMAGES = {".jpg", ".jpeg", ".png", ".webp"}
TEXT = {".md", ".json", ".py", ".txt", ".yml", ".yaml", ".toml"}
BLOCKED = {
    ".stp", ".step", ".iges", ".igs", ".3dm", ".dwg", ".dxf",
    ".sldprt", ".sldasm", ".f3d", ".stl", ".obj", ".fbx", ".gltf",
    ".glb", ".blend", ".blend1", ".zip", ".rar", ".7z", ".tar",
    ".gz", ".bz2", ".xz", ".exe", ".dll", ".sqlite", ".db",
}
SKIP = {".git", "本地", ".local", ".venv", "venv", "__pycache__"}
INDEX = Path("索引/资料索引.json")
CATEGORY_RULES = Path("docs/分类规则.json")
COMPONENT_FIELDS = {
    "架构版本", "资料编号", "名称", "品牌", "型号", "硬件版本", "分类",
    "别名", "关联课程", "核对状态", "核对日期", "核对依据", "核对范围",
    "限制", "来源", "出处",
}
SOURCE_FIELDS = {
    "类型", "标题", "网址", "状态", "核对方式", "核对日期", "说明",
    "定位", "格式", "访问要求", "原件指纹", "附件",
}
PRIVATE_PATH = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]|\\\\[A-Za-z0-9]|/(?:Users|home)/")
SECRET = re.compile(r"(?:github_pat_[A-Za-z0-9_]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----)")


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def normalize(value):
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def member(value, allowed):
    return isinstance(value, str) and value in allowed


def valid_date(value):
    try:
        return isinstance(value, str) and date.fromisoformat(value).isoformat() == value
    except (ValueError, TypeError):
        return False


def canonical_url(value):
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"), parsed.query, ""))


def url_error(value):
    if not isinstance(value, str) or not value:
        return "网址不能为空"
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return "网址必须是完整的 HTTP 或 HTTPS 地址"
        if parsed.username or parsed.password:
            return "网址不得包含登录凭证"
        if parsed.hostname in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
            return "正式网址不得指向本机"
        sensitive = {"token", "access_token", "api_key", "apikey", "authorization", "signature", "sig", "x-amz-signature", "x-amz-credential", "x-goog-signature"}
        if any(key.casefold() in sensitive for key, _ in parse_qsl(parsed.query)):
            return "网址包含令牌或签名参数，应改用稳定获取页面"
        if SECRET.search(value):
            return "网址包含疑似凭证"
    except ValueError:
        return "网址格式无效"
    return None


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)


def private_errors(value):
    found = []
    for text in strings(value):
        if PRIVATE_PATH.search(text):
            found.append("正式记录不得包含机器绝对路径")
        if SECRET.search(text):
            found.append("正式记录包含疑似凭证")
        if re.search(r"data:(?:image|application)/[^;]+;base64,", text, re.I):
            found.append("正式记录不得嵌入二进制编码")
    return sorted(set(found))


def geometry_payload(value):
    if isinstance(value, dict):
        mesh_keys = {"vertices", "faces", "indices", "positions", "meshes", "buffers", "bufferviews", "顶点", "面索引", "网格数据"}
        if any(str(key).casefold() in mesh_keys and isinstance(item, (list, dict)) for key, item in value.items()):
            return True
        return any(geometry_payload(item) for item in value.values())
    return isinstance(value, list) and any(geometry_payload(item) for item in value)


def walk_files(root):
    """排除本地工作区；拒绝链接，避免读取仓库之外的文件。"""
    for base, directories, names in os.walk(root, followlinks=False):
        for name in list(directories):
            path = Path(base) / name
            if name in SKIP:
                directories.remove(name)
            elif path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                directories.remove(name)
                yield path, "目录链接不允许进入正式资料"
        for name in names:
            path = Path(base) / name
            if name.endswith((".pyc", ".pyo")):
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                yield path, "文件链接或越界路径不允许进入正式资料"
            else:
                yield path, None


def history_size(root):
    if not (root / ".git").exists():
        return {"状态": "非Git仓库", "字节数": None}
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "count-objects", "-v"],
            capture_output=True, text=True, timeout=10, check=True,
        )
        values = dict(line.split(": ", 1) for line in result.stdout.splitlines() if ": " in line)
        return {"状态": "已统计", "字节数": (int(values["size"]) + int(values["size-pack"])) * 1024}
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return {"状态": "不可用", "字节数": None}


def fingerprint_errors(value):
    if not isinstance(value, dict):
        return ["指纹必须为对象"]
    errors = []
    if type(value.get("字节数")) is not int or value["字节数"] <= 0:
        errors.append("指纹字节数必须为正整数")
    if not isinstance(value.get("SHA256"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["SHA256"]):
        errors.append("SHA256必须为64位小写十六进制")
    return errors


def nonempty(obj, fields):
    return [f"缺少有效字段：{key}" for key in fields if not isinstance(obj.get(key), str) or not obj[key].strip() or "待填写" in obj[key]]


def load_categories(root):
    """分类只从仓库词表读取，缺失或无效时返回错误，不使用默认值。"""
    target = root / CATEGORY_RULES
    if not target.is_file() or target.is_symlink() or not target.resolve().is_relative_to(root):
        return {}, ["分类规则缺失或不是仓库内的普通文件"]
    if target.stat().st_size > TEXT_LIMIT:
        return {}, ["分类规则文件超过文本体积上限"]
    try:
        policy = json.loads(target.read_text(encoding="utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return {}, ["分类规则必须为有效的UTF-8 JSON"]
    if not isinstance(policy, dict) or set(policy) != {"架构版本", "分类"} or type(policy.get("架构版本")) is not int or policy["架构版本"] != VERSION:
        return {}, ["分类规则字段或架构版本无效"]
    entries = policy["分类"]
    if not isinstance(entries, list) or not entries:
        return {}, ["分类词表必须为非空数组"]
    categories, names, errors = {}, set(), []
    for index, entry in enumerate(entries, 1):
        if not isinstance(entry, dict) or set(entry) != {"名称", "定义", "边界"}:
            errors.append(f"分类{index}必须包含名称、定义、边界")
            continue
        issues = nonempty(entry, ["名称", "定义", "边界"])
        name = entry["名称"]
        if isinstance(name, str) and (name != name.strip() or name.rstrip(". ") != name or name in {".", ".."} or re.search(r'[\\/<>:"|?*\x00-\x1f]', name)):
            issues.append("分类名称必须能作为单层目录名称，不能含路径或首尾空白")
        errors.extend(f"分类{index}：{item}" for item in issues)
        if issues:
            continue
        key = normalize(name)
        if key in names:
            errors.append(f"分类{index}：分类名称重复")
        names.add(key)
        categories[name] = entry
    return ({} if errors else categories), errors


def component_path_errors(relative, record, categories):
    if not isinstance(record, dict):
        return []
    errors = []
    category, identifier = record.get("分类"), record.get("资料编号")
    if isinstance(category, str) and category not in categories:
        errors.append("分类未登记，请先核对分类规则词表")
    parts = PurePosixPath(relative).parts
    if len(parts) != 3:
        return errors + ["元件记录必须使用三层路径：元件/分类/资料编号.json"]
    if isinstance(category, str) and parts[1] != category:
        errors.append("目录分类与记录分类不一致")
    if isinstance(identifier, str) and parts[2] != identifier + ".json":
        errors.append("文件名必须与资料编号一致，并使用小写.json扩展名")
    return errors


def string_list(obj, key, require_items=False):
    value = obj.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value) or (require_items and not value):
        return [f"{key}必须为{'非空' if require_items else ''}字符串数组"]
    return []


def source_errors(source, root, references):
    if not isinstance(source, dict):
        return ["来源必须为对象"]
    errors = nonempty(source, ["标题", "说明"])
    if set(source) - SOURCE_FIELDS:
        errors.append("来源存在未定义字段")
    if not member(source.get("类型"), KINDS):
        errors.append("来源类型不在首版收录范围")
    if not member(source.get("状态"), STATES):
        errors.append("来源状态无效")
    if not member(source.get("核对方式"), METHODS):
        errors.append("来源核对方式无效")
    if not valid_date(source.get("核对日期")):
        errors.append("来源核对日期无效")
    problem = url_error(source.get("网址"))
    if problem:
        errors.append(problem)
    if "原件指纹" in source:
        errors.extend(fingerprint_errors(source["原件指纹"]))
    attachment = source.get("附件")
    if attachment is None:
        return errors
    if source.get("类型") == "CAD获取地址":
        errors.append("CAD只能保存获取地址，禁止附件")
    if not isinstance(attachment, dict):
        return errors + ["附件必须为对象或null"]
    errors.extend(fingerprint_errors(attachment))
    errors.extend(nonempty(attachment, ["路径", "公开分发依据"]))
    if attachment.get("可读性已核对") is not True:
        errors.append("附件必须记录实际可读性核对")
    relative = attachment.get("路径", "")
    if not isinstance(relative, str):
        return errors + ["附件路径必须为字符串"]
    parts = PurePosixPath(relative)
    target = root / relative
    if "\\" in relative or parts.is_absolute() or ".." in parts.parts or not parts.parts or parts.parts[0] != "附件" or not target.resolve().is_relative_to(root / "附件"):
        return errors + ["附件路径必须位于仓库附件目录内"]
    references.add(parts.as_posix())
    suffix = target.suffix.lower()
    if suffix not in IMAGES | {".pdf"}:
        errors.append("附件只允许小型图片和PDF，CAD及压缩包禁止")
    if source.get("类型") == "元件网站" or (source.get("类型") == "实拍" and suffix not in IMAGES):
        errors.append("附件格式与来源用途不匹配")
    if not target.is_file() or target.is_symlink():
        return errors + ["附件缺失或为链接"]
    if target.stat().st_size <= PDF_LIMIT:
        payload = target.read_bytes()
        if len(payload) != attachment.get("字节数") or hashlib.sha256(payload).hexdigest() != attachment.get("SHA256"):
            errors.append("附件实际字节数或SHA256不匹配")
    return errors


def component_errors(record, root, references):
    if not isinstance(record, dict):
        return ["元件记录必须为对象"]
    errors = nonempty(record, ["资料编号", "名称", "品牌", "型号", "硬件版本", "分类", "核对依据"])
    if set(record) != COMPONENT_FIELDS:
        errors.append("元件记录字段缺失或存在未定义字段")
    if type(record.get("架构版本")) is not int or record["架构版本"] != VERSION:
        errors.append("架构版本必须为1")
    if not isinstance(record.get("资料编号"), str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,100}", record["资料编号"]):
        errors.append("资料编号只能使用小写字母数字和连字符")
    if not member(record.get("核对状态"), STATES) or not valid_date(record.get("核对日期")):
        errors.append("元件核对状态或日期无效")
    for key in ["别名", "关联课程", "核对范围", "限制"]:
        errors.extend(string_list(record, key, require_items=key in {"核对范围", "限制"}))
    sources = record.get("来源")
    if not isinstance(sources, list) or not sources:
        errors.append("至少需要一条来源")
    else:
        urls = set()
        for index, source in enumerate(sources):
            errors.extend(f"来源{index + 1}：{item}" for item in source_errors(source, root, references))
            if isinstance(source, dict) and not url_error(source.get("网址")):
                key = canonical_url(source["网址"])
                if key in urls:
                    errors.append("同一元件中存在重复网址，应合并定位与说明")
                urls.add(key)
    origins = record.get("出处")
    if not isinstance(origins, list) or not origins:
        errors.append("至少需要一条出处")
    else:
        for origin in origins:
            if not isinstance(origin, dict):
                errors.append("出处必须为对象")
                continue
            errors.extend(nonempty(origin, ["会话编号", "项目标识", "项目相对路径"]))
            relative = origin.get("项目相对路径", "")
            if isinstance(relative, str) and (relative.startswith(("/", "\\")) or ".." in PurePosixPath(relative.replace("\\", "/")).parts):
                errors.append("出处应使用项目内相对路径")
            if not valid_date(origin.get("回收日期")):
                errors.append("出处回收日期无效")
    return errors + private_errors(record)


def website_errors(record):
    if not isinstance(record, dict):
        return ["网站记录必须为对象"]
    errors = nonempty(record, ["名称", "搜索建议", "访问说明"])
    expected = {"架构版本", "名称", "网址", "适用资料类型", "搜索建议", "访问说明", "核对日期", "核对方式"}
    if set(record) != expected or type(record.get("架构版本")) is not int or record["架构版本"] != VERSION:
        errors.append("网站字段或架构版本无效")
    errors.extend(string_list(record, "适用资料类型", require_items=True))
    if isinstance(record.get("适用资料类型"), list) and any(item not in KINDS for item in record["适用资料类型"] if isinstance(item, str)):
        errors.append("网站资料类型无效")
    if not member(record.get("核对方式"), METHODS) or not valid_date(record.get("核对日期")):
        errors.append("网站核对方式或日期无效")
    problem = url_error(record.get("网址"))
    if problem:
        errors.append(problem)
    return errors + private_errors(record)


def scan(root, check_index=True):
    root = root.resolve()
    errors, warnings, records, websites = [], [], [], []
    categories, category_errors = load_categories(root)
    errors.extend(f"{CATEGORY_RULES.as_posix()}：{item}" for item in category_errors)
    references, assets, identities, identifiers, site_urls = set(), {}, {}, {}, set()
    total, count = 0, 0
    for path, issue in sorted(walk_files(root), key=lambda item: item[0].as_posix()):
        relative = path.relative_to(root).as_posix()
        if issue:
            errors.append(f"{relative}：{issue}")
            continue
        size, suffix = path.stat().st_size, path.suffix.lower()
        total += size
        count += 1
        limit = IMAGE_LIMIT if suffix in IMAGES else PDF_LIMIT if suffix == ".pdf" else TEXT_LIMIT
        if suffix in BLOCKED or path.name.startswith(".env") or path.name.endswith(".local.json"):
            errors.append(f"{relative}：禁止CAD本体、压缩包、模型、数据库或本机配置")
            continue
        if suffix not in TEXT | IMAGES | {".pdf"} and path.name not in {".gitignore", ".gitattributes"}:
            errors.append(f"{relative}：未允许的文件类型")
            continue
        if size > limit:
            errors.append(f"{relative}：文件超限，{size} > {limit}字节")
            continue
        payload = path.read_bytes()
        if payload.startswith((b"PK\x03\x04", b"Rar!", b"7z\xbc\xaf\x27\x1c", b"BLENDER", b"glTF")) or b"ISO-10303-21;" in payload[:512]:
            errors.append(f"{relative}：发现压缩包、CAD或模型内容，不能改名绕过")
            continue
        if suffix in IMAGES | {".pdf"}:
            signatures = {".png": payload.startswith(b"\x89PNG\r\n\x1a\n"), ".jpg": payload.startswith(b"\xff\xd8\xff"), ".jpeg": payload.startswith(b"\xff\xd8\xff"), ".webp": payload.startswith(b"RIFF") and payload[8:12] == b"WEBP", ".pdf": payload.startswith(b"%PDF-")}
            if not signatures[suffix]:
                errors.append(f"{relative}：文件内容与扩展名不一致")
            if not relative.startswith("附件/"):
                errors.append(f"{relative}：公开附件必须集中放在附件目录并有来源记录")
            digest = hashlib.sha256(payload).hexdigest()
            if digest in assets:
                errors.append(f"{relative}：附件与{assets[digest]}重复，应共用一份")
            assets[digest] = relative
        else:
            try:
                text = payload.decode("utf-8-sig")
            except UnicodeDecodeError:
                errors.append(f"{relative}：文本必须为UTF-8")
                continue
            if "\x00" in text:
                errors.append(f"{relative}：文本包含二进制内容")
            if suffix in {".md", ".txt", ".yml", ".yaml", ".toml"}:
                errors.extend(f"{relative}：{item}" for item in private_errors(text))
            if suffix != ".json":
                continue
            try:
                record = json.loads(text)
            except (ValueError, RecursionError):
                errors.append(f"{relative}：JSON无效")
                continue
            if geometry_payload(record):
                errors.append(f"{relative}：JSON包含转换网格或模型数组")
            errors.extend(f"{relative}：{item}" for item in private_errors(record))
            if relative.startswith("元件/"):
                issues = component_errors(record, root, references)
                issues.extend(component_path_errors(relative, record, categories))
                errors.extend(f"{relative}：{item}" for item in issues)
                if not issues:
                    identity = tuple(normalize(record[key]) for key in ["品牌", "型号", "硬件版本"])
                    if identity in identities:
                        errors.append(f"{relative}：品牌型号版本与{identities[identity]}重复")
                    identities[identity] = relative
                    if record["资料编号"] in identifiers:
                        errors.append(f"{relative}：资料编号与{identifiers[record['资料编号']]}重复")
                    identifiers[record["资料编号"]] = relative
                    records.append((relative, record))
            elif relative.startswith("网站/"):
                issues = website_errors(record)
                errors.extend(f"{relative}：{item}" for item in issues)
                if not issues:
                    key = canonical_url(record["网址"])
                    if key in site_urls:
                        errors.append(f"{relative}：网站入口重复")
                    site_urls.add(key)
                    websites.append((relative, record))
            elif relative not in {INDEX.as_posix(), CATEGORY_RULES.as_posix()} and not relative.startswith("模板/"):
                errors.append(f"{relative}：JSON应放在元件、网站、模板或指定分类规则路径，禁止存放转换网格")
    for relative in assets.values():
        if relative not in references:
            errors.append(f"{relative}：附件没有对应来源和公开分发依据")
    if total > TOTAL_LIMIT:
        errors.append(f"工作文件合计超限：{total} > {TOTAL_LIMIT}字节")
    history = history_size(root)
    if history["字节数"] is None:
        warnings.append("Git历史对象大小不可用；不能据此声称历史体积合格")
    elif history["字节数"] > TOTAL_LIMIT:
        warnings.append("Git历史对象超过100 MiB，需人工评估；工具不会重写历史")
    index = make_index(records, websites)
    if check_index and not errors:
        target = root / INDEX
        if not target.is_file() or target.read_bytes() != encode(index):
            errors.append("索引缺失或过期，请运行 index --write")
    report = {"通过": not errors, "工作文件数": count, "工作文件字节数": total, "分类数": len(categories), "元件记录数": len(records), "网站记录数": len(websites), "附件数": len(assets), "Git历史": history, "错误": errors, "提示": warnings}
    return report, index, records


def make_index(records, websites):
    return {
        "架构版本": VERSION,
        "元件": [{key: record[key] for key in ["资料编号", "名称", "品牌", "型号", "硬件版本", "分类", "别名", "核对状态"]} | {"记录路径": path} for path, record in records],
        "网站": [{"名称": record["名称"], "网址": record["网址"], "适用资料类型": record["适用资料类型"], "记录路径": path} for path, record in websites],
    }


def atomic_index(root, index):
    target = root / INDEX
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".资料索引-", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encode(index))
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def search(records, query, all_statuses=False):
    query = normalize(query)
    if not query:
        return []
    hits = []
    for path, record in records:
        if not all_statuses and record["核对状态"] != "已核实":
            continue
        fields = [record[key] for key in ["资料编号", "名称", "品牌", "型号", "分类"]] + record["别名"]
        normalized = [normalize(value) for value in fields]
        if query in normalized:
            rank = 0 if query == normalize(record["型号"]) else 1
        elif all(term in " ".join(normalized) for term in query.split()):
            rank = 2
        else:
            continue
        hits.append((rank, record["资料编号"], {"名称": record["名称"], "型号": record["型号"], "硬件版本": record["硬件版本"], "状态": record["核对状态"], "记录路径": path, "限制": record["限制"]}))
    return [value for _, _, value in sorted(hits)[:5]]


def save_report(root, relative, report):
    path = Path(relative)
    target = root / path
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "本地" or target.suffix.lower() != ".json" or not target.resolve().is_relative_to(root / "本地"):
        raise ValueError("报告仅允许写入本地目录内的新JSON路径")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(encode(report))


def main(argv=None):
    parser = argparse.ArgumentParser(description="元件资料检查、索引生成和检索")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="知识库目录")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="只读检查正式资料")
    check.add_argument("--report", help="本地目录中的新JSON报告")
    index = commands.add_parser("index", help="比较或生成派生索引")
    index.add_argument("--write", action="store_true", help="替换派生索引，其他文件不变")
    find = commands.add_parser("search", help="检索完整型号、别名或分类")
    find.add_argument("query")
    find.add_argument("--all-statuses", action="store_true", help="包含待核实与已排除")
    find.add_argument("--json", action="store_true", help="输出JSON")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        parser.error("知识库目录不存在")
    try:
        report, data, records = scan(root, check_index=args.command == "check" or (args.command == "index" and not args.write))
        if args.command == "index" and args.write and report["通过"]:
            atomic_index(root, data)
            print("派生索引已生成；元件和网站事实记录未改动。")
        elif args.command == "search" and report["通过"]:
            hits = search(records, args.query, args.all_statuses)
            if args.json:
                print(json.dumps({"结果": hits}, ensure_ascii=False, indent=2))
            else:
                print("\n".join(f"{item['名称']} | {item['型号']} | {item['硬件版本']} | {item['状态']}\n记录：{item['记录路径']}\n限制：{'；'.join(item['限制'])}" for item in hits) or "未找到匹配资料，请报告缺失，不自动推测型号。")
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        if args.command == "check" and args.report:
            save_report(root, args.report, report)
        return 0 if report["通过"] else 1
    except (OSError, ValueError, TypeError, RecursionError) as error:
        print(f"检查未完成：{type(error).__name__}，请核对文件结构或报告路径。", file=sys.stderr)
        return 2


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    raise SystemExit(main())
