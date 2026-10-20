"""用隔离目录验证真实收录边界，不接触来源工程或联网下载。"""

import base64
import copy
import hashlib
import importlib.util
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


class KnowledgeBaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="component-kb-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.record = component()
        self.put("元件/开关/测试.json", self.record)

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
        self.put("元件/开关/测试.json", changed)
        self.assertIn("索引缺失或过期", " ".join(kb.scan(self.root)[0]["错误"]))

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
        self.put("元件/开关/测试.json", record)
        self.assertTrue(self.inspect()["通过"])
        source["附件"] = {}
        self.put("元件/开关/测试.json", record)
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
        self.put("元件/开关/测试.json", record)
        self.assertTrue(self.inspect()["通过"])
        record["来源"][0]["附件"]["SHA256"] = "0" * 64
        record["来源"][0]["附件"]["公开分发依据"] = ""
        record["来源"][0]["附件"]["可读性已核对"] = False
        self.put("元件/开关/测试.json", record)
        errors = " ".join(self.inspect()["错误"])
        for expected in ["SHA256不匹配", "公开分发依据", "可读性核对"]:
            self.assertIn(expected, errors)

    def test_identity_duplicate_but_distinct_versions_allowed(self):
        record = copy.deepcopy(self.record)
        record["资料编号"] = "test-switch-other"
        self.put("元件/开关/另一份.json", record)
        self.assertIn("品牌型号版本", " ".join(self.inspect()["错误"]))
        record["硬件版本"] = "V2"
        self.put("元件/开关/另一份.json", record)
        self.assertTrue(self.inspect()["通过"])

    def test_unverified_search_requires_flag(self):
        record = copy.deepcopy(self.record)
        record["核对状态"] = "待核实"
        self.put("元件/开关/测试.json", record)
        _, _, records = kb.scan(self.root, check_index=False)
        self.assertEqual(kb.search(records, "MTS103"), [])
        self.assertEqual(len(kb.search(records, "MTS103", True)), 1)

    def test_private_path_signed_url_and_embedded_data_rejected(self):
        record = copy.deepcopy(self.record)
        record["核对依据"] = "本机路径 C:\\Private\\source.pdf"
        record["来源"][0]["网址"] = "https://example.com/file?access_token=example"
        record["限制"] = ["data:image/png;base64,ZXhhbXBsZQ=="]
        self.put("元件/开关/测试.json", record)
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
        self.assertEqual(report["工作文件数"], 1)

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
        self.put("元件/开关/测试.json", ["并非元件对象"])
        self.assertFalse(self.inspect()["通过"])

    def test_invalid_state_type_produces_errors(self):
        record = copy.deepcopy(self.record)
        record["核对状态"] = []
        record["来源"][0]["类型"] = {"错误": "对象"}
        self.put("元件/开关/测试.json", record)
        self.assertFalse(self.inspect()["通过"])


if __name__ == "__main__":
    unittest.main()
