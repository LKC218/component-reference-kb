"""用隔离目录验证真实收录边界，不接触来源工程或联网下载。"""

import base64
import copy
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("kb", Path(__file__).with_name("资料库.py"))
kb = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kb)


def component():
    return {
        "架构版本": 1, "资料编号": "test-switch-v1", "名称": "三档拨动开关",
        "品牌": "测试品牌", "型号": "MTS103", "硬件版本": "V1", "分类": "开关",
        "别名": ["三档光开关"], "关联课程": ["AU-04"], "核对状态": "已核实",
        "核对日期": "2026-10-20", "核对依据": "隔离测试资料",
        "核对范围": ["型号对应"], "限制": ["不是电气适配验收"],
        "来源": [{"类型": "元件网站", "标题": "测试商品页", "网址": "https://example.com/switch", "状态": "已核实", "核对方式": "本地资料回收", "核对日期": "2026-10-20", "说明": "测试记录"}],
        "出处": [{"会话编号": "测试会话", "项目标识": "测试项目", "项目相对路径": "资料/来源.json", "回收日期": "2026-10-20"}],
    }


def website():
    return {
        "架构版本": 1, "名称": "测试资料站", "网址": "https://example.com/",
        "适用资料类型": ["元件网站"], "搜索建议": "按完整型号搜索",
        "访问说明": "隔离测试入口", "核对日期": "2026-10-20",
        "核对方式": "本地资料回收",
    }


class KnowledgeBaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="component-kb-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.policy = {
            "架构版本": 1,
            "分类": [
                {"名称": "开关", "定义": "人工切换接点的开关", "边界": "不包含驱动板"},
                {"名称": "连接器", "定义": "插头插座及壳体端子", "边界": "单件不代表套装"},
            ],
        }
        self.put(kb.CATEGORY_RULES, self.policy)
        self.record = component()
        self.put("元件/开关/test-switch-v1.json", self.record)

    def put(self, relative, value):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value if isinstance(value, bytes) else kb.encode(value))
        return target

    def inspect(self):
        return kb.scan(self.root, check_index=False)[0]

    def test_valid_index_and_alias_search(self):
        report, index, records = kb.scan(self.root, check_index=False)
        self.assertTrue(report["通过"], report)
        kb.atomic_index(self.root, index)
        self.assertTrue(kb.scan(self.root)[0]["通过"])
        self.assertEqual(kb.search(records, "三档光开关")[0]["型号"], "MTS103")
        self.assertEqual(kb.search(records, " mts103 ")[0]["型号"], "MTS103")

    def test_stale_index_detected(self):
        _, index, _ = kb.scan(self.root, check_index=False)
        kb.atomic_index(self.root, index)
        changed = copy.deepcopy(self.record)
        changed["别名"].append("新增别名")
        self.put("元件/开关/test-switch-v1.json", changed)
        self.assertIn("索引缺失或过期", " ".join(kb.scan(self.root)[0]["错误"]))

    def test_valid_website_record_and_index(self):
        self.put("网站/测试资料站.json", website())
        report, index, _ = kb.scan(self.root, check_index=False)
        self.assertTrue(report["通过"], report)
        self.assertEqual(report["网站记录数"], 1)
        self.assertEqual(index["网站"][0]["记录路径"], "网站/测试资料站.json")
        kb.atomic_index(self.root, index)
        self.assertTrue(kb.scan(self.root)[0]["通过"])

    def test_website_filename_must_match_name(self):
        self.put("网站/其他名称.json", website())
        self.assertIn("文件名必须与网站名称一致", " ".join(self.inspect()["错误"]))

    def test_website_path_must_be_two_levels(self):
        self.put("网站/子目录/测试资料站.json", website())
        self.assertIn("网站记录必须使用两层路径", " ".join(self.inspect()["错误"]))

    def test_website_name_cannot_be_a_path(self):
        site = website()
        site["名称"] = "../测试资料站"
        self.put("网站/测试资料站.json", site)
        self.assertIn("网站名称必须能作为单层文件名", " ".join(self.inspect()["错误"]))

    def test_website_json_extension_must_be_lowercase(self):
        self.put("网站/测试资料站.JSON", website())
        self.assertIn("小写.json扩展名", " ".join(self.inspect()["错误"]))

    def test_cad_and_archive_rejected_even_if_ignored(self):
        self.put(".gitignore", b"*.STEP\n*.zip\n")
        self.put("附件/模型.STEP", b"ISO-10303-21;\n")
        self.put("附件/模型.zip", b"PK\x03\x04example")
        errors = " ".join(self.inspect()["错误"])
        self.assertIn("模型.STEP", errors)
        self.assertIn("模型.zip", errors)

    def test_renamed_cad_rejected(self):
        self.put("附件/伪装.txt", b"ISO-10303-21;\nDATA;\n")
        self.assertIn("不能改名绕过", " ".join(self.inspect()["错误"]))

    def test_cad_link_allowed_but_attachment_forbidden(self):
        record = copy.deepcopy(self.record)
        source = record["来源"][0]
        source["类型"] = "CAD获取地址"
        source["网址"] = "https://example.com/official-cad.rar"
        self.put("元件/开关/test-switch-v1.json", record)
        self.assertTrue(self.inspect()["通过"])
        source["附件"] = {}
        self.put("元件/开关/test-switch-v1.json", record)
        self.assertIn("CAD只能保存获取地址", " ".join(self.inspect()["错误"]))

    def test_large_image_and_text_rejected(self):
        self.put("附件/超限.png", b"\x89PNG\r\n\x1a\n" + b"x" * kb.IMAGE_LIMIT)
        self.put("元件/超限.json", b" " * (kb.TEXT_LIMIT + 1))
        errors = " ".join(self.inspect()["错误"])
        self.assertIn("超限.png：文件超限", errors)
        self.assertIn("超限.json：文件超限", errors)

    def test_unreferenced_image_rejected(self):
        self.put("附件/无来源.png", b"\x89PNG\r\n\x1a\nexample")
        self.assertIn("没有对应来源", " ".join(self.inspect()["错误"]))

    def test_attachment_hash_rights_and_readability(self):
        payload = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=")
        self.put("附件/测试.png", payload)
        record = copy.deepcopy(self.record)
        record["来源"][0]["类型"] = "图纸"
        record["来源"][0]["附件"] = {"路径": "附件/测试.png", "字节数": len(payload), "SHA256": hashlib.sha256(payload).hexdigest(), "公开分发依据": "隔离测试生成图", "可读性已核对": True}
        self.put("元件/开关/test-switch-v1.json", record)
        self.assertTrue(self.inspect()["通过"])
        record["来源"][0]["附件"]["SHA256"] = "0" * 64
        record["来源"][0]["附件"]["公开分发依据"] = ""
        record["来源"][0]["附件"]["可读性已核对"] = False
        self.put("元件/开关/test-switch-v1.json", record)
        errors = " ".join(self.inspect()["错误"])
        for expected in ["SHA256不匹配", "公开分发依据", "可读性核对"]:
            self.assertIn(expected, errors)

    def test_identity_duplicate_but_distinct_versions_allowed(self):
        record = copy.deepcopy(self.record)
        record["资料编号"] = "test-switch-other"
        self.put("元件/开关/test-switch-other.json", record)
        self.assertIn("品牌型号版本", " ".join(self.inspect()["错误"]))
        record["硬件版本"] = "V2"
        self.put("元件/开关/test-switch-other.json", record)
        self.assertTrue(self.inspect()["通过"])

    def test_unverified_search_requires_flag(self):
        record = copy.deepcopy(self.record)
        record["核对状态"] = "待核实"
        self.put("元件/开关/test-switch-v1.json", record)
        _, _, records = kb.scan(self.root, check_index=False)
        self.assertEqual(kb.search(records, "MTS103"), [])
        self.assertEqual(len(kb.search(records, "MTS103", True)), 1)

    def test_private_path_signed_url_and_embedded_data_rejected(self):
        record = copy.deepcopy(self.record)
        record["核对依据"] = "本机路径 C:\\Private\\source.pdf"
        record["来源"][0]["网址"] = "https://example.com/file?access_token=example"
        record["限制"] = ["data:image/png;base64,ZXhhbXBsZQ=="]
        self.put("元件/开关/test-switch-v1.json", record)
        errors = " ".join(self.inspect()["错误"])
        for expected in ["绝对路径", "令牌或签名", "二进制编码"]:
            self.assertIn(expected, errors)

    def test_report_cannot_overwrite_or_escape(self):
        kb.save_report(self.root, "本地/检查.json", {"通过": True})
        with self.assertRaises(FileExistsError):
            kb.save_report(self.root, "本地/检查.json", {})
        with self.assertRaises(ValueError):
            kb.save_report(self.root, "../检查.json", {})

    def test_local_downloads_are_not_published_records(self):
        self.put("本地/原件/模型.stp", b"ISO-10303-21;")
        report = self.inspect()
        self.assertTrue(report["通过"])
        self.assertEqual(report["工作文件数"], 2)

    def test_arbitrary_mesh_json_is_not_a_record(self):
        self.put("转换网格.json", {"vertices": [0, 0, 0], "faces": [0]})
        self.assertIn("禁止存放转换网格", " ".join(self.inspect()["错误"]))

    def test_mesh_cannot_hide_in_template(self):
        self.put("模板/伪装.json", {"说明": {"vertices": [0, 1, 2]}})
        self.assertIn("转换网格或模型数组", " ".join(self.inspect()["错误"]))

    def test_document_cannot_publish_machine_path(self):
        self.put("说明.md", "来源位于 C:\\Private\\source.pdf".encode("utf-8"))
        self.assertIn("绝对路径", " ".join(self.inspect()["错误"]))

    def test_duplicate_attachments_rejected(self):
        payload = b"%PDF-1.7\nexample"
        self.put("附件/一.pdf", payload)
        self.put("附件/二.pdf", payload)
        self.assertIn("重复，应共用一份", " ".join(self.inspect()["错误"]))

    def test_total_budget_rejected(self):
        original = kb.TOTAL_LIMIT
        try:
            kb.TOTAL_LIMIT = 10
            self.assertIn("工作文件合计超限", " ".join(self.inspect()["错误"]))
        finally:
            kb.TOTAL_LIMIT = original

    def test_invalid_structure_produces_errors(self):
        self.put("元件/开关/test-switch-v1.json", ["并非元件对象"])
        self.assertFalse(self.inspect()["通过"])

    def test_invalid_state_type_produces_errors(self):
        record = copy.deepcopy(self.record)
        record["核对状态"] = []
        record["来源"][0]["类型"] = {"错误": "对象"}
        self.put("元件/开关/test-switch-v1.json", record)
        self.assertFalse(self.inspect()["通过"])

    def test_unregistered_category_rejected(self):
        record = copy.deepcopy(self.record)
        record["分类"] = "开关类"
        self.put("元件/开关类/test-switch-v1.json", record)
        self.assertIn("分类未登记", " ".join(self.inspect()["错误"]))

    def test_category_must_match_parent_directory(self):
        self.put("元件/连接器/test-switch-v1.json", self.record)
        self.assertIn("目录分类与记录分类不一致", " ".join(self.inspect()["错误"]))

    def test_filename_must_match_record_id(self):
        self.put("元件/开关/随意命名.json", self.record)
        self.assertIn("文件名必须与资料编号一致", " ".join(self.inspect()["错误"]))

    def test_record_depth_is_exactly_three(self):
        for relative in ["元件/test-switch-v1.json", "元件/开关/版本/test-switch-v1.json"]:
            with self.subTest(path=relative):
                self.put(relative, self.record)
                self.assertTrue(any(relative in item and "元件记录必须使用三层路径" in item for item in self.inspect()["错误"]))

    def test_json_extension_must_be_lowercase(self):
        record = copy.deepcopy(self.record)
        record["资料编号"] = "test-uppercase-v1"
        self.put("元件/开关/test-uppercase-v1.JSON", record)
        self.assertIn("小写.json扩展名", " ".join(self.inspect()["错误"]))

    def test_policy_missing_rejected_without_fallback(self):
        (self.root / kb.CATEGORY_RULES).unlink()
        report = self.inspect()
        self.assertIn("分类规则缺失", " ".join(report["错误"]))
        self.assertEqual(report["分类数"], 0)

    def test_invalid_policy_json_rejected(self):
        self.put(kb.CATEGORY_RULES, b"{")
        self.assertIn("分类规则必须为有效", " ".join(self.inspect()["错误"]))

    def test_empty_policy_rejected(self):
        self.put(kb.CATEGORY_RULES, {"架构版本": 1, "分类": []})
        self.assertIn("分类词表必须为非空数组", " ".join(self.inspect()["错误"]))

    def test_duplicate_policy_categories_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy["分类"].append(copy.deepcopy(policy["分类"][0]))
        self.put(kb.CATEGORY_RULES, policy)
        self.assertIn("分类名称重复", " ".join(self.inspect()["错误"]))

    def test_category_definition_and_boundary_required(self):
        for field in ["定义", "边界"]:
            with self.subTest(field=field):
                policy = copy.deepcopy(self.policy)
                policy["分类"][0][field] = ""
                self.put(kb.CATEGORY_RULES, policy)
                self.assertIn("缺少有效字段：" + field, " ".join(self.inspect()["错误"]))

    def test_category_name_cannot_be_a_path(self):
        for name in ["../开关", "开关/其他", "开关\\其他", " 开关", "开关."]:
            with self.subTest(name=name):
                policy = copy.deepcopy(self.policy)
                policy["分类"][0]["名称"] = name
                self.put(kb.CATEGORY_RULES, policy)
                self.assertIn("分类名称必须能作为单层目录名称", " ".join(self.inspect()["错误"]))

    def test_new_registered_category_allowed(self):
        policy = copy.deepcopy(self.policy)
        policy["分类"].append({"名称": "电机", "定义": "电机本体", "边界": "不包含电机驱动板"})
        self.put(kb.CATEGORY_RULES, policy)
        record = copy.deepcopy(self.record)
        record.update({"资料编号": "test-motor-v1", "名称": "测试电机", "型号": "MOTOR1", "分类": "电机"})
        self.put("元件/电机/test-motor-v1.json", record)
        report = self.inspect()
        self.assertTrue(report["通过"], report)
        self.assertEqual(report["分类数"], 3)

    def test_invalid_path_does_not_replace_index(self):
        _, index, _ = kb.scan(self.root, check_index=False)
        kb.atomic_index(self.root, index)
        previous = (self.root / kb.INDEX).read_bytes()
        self.put("元件/连接器/test-switch-v1.json", self.record)
        with redirect_stdout(io.StringIO()):
            result = kb.main(["--root", str(self.root), "index", "--write"])
        self.assertEqual(result, 1)
        self.assertEqual((self.root / kb.INDEX).read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
