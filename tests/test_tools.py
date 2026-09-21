import io
import json
import threading
import unittest
import urllib.error
import urllib.request

from tools import mock_jev, summarize


def request_payload():
    return {
        "model": "jev-1.13.0",
        "state": {"subject": "Synthetic test"},
        "questions": {"category": {
            "type": "choice", "instructions": "Classify synthetic mail",
            "criteria": {"ham": "Legitimate", "spam": "Unsolicited", "phishing": "Impersonation"},
        }},
    }


def record(digit="a", mode="live", decision="spam", baseline="ham"):
    return {
        "schema_version": 1, "timestamp": 100, "message_digest": digit * 32,
        "mode": mode, "status": "ok", "model": "jev-1.13.0",
        "prompt_version": "email-choice-v1", "sample_rate": 0.05,
        "probability_threshold": 0.9, "confidence_threshold": 0.9,
        "requested": True, "latency_ms": 125,
        "baseline": {"verdict": baseline, "provider": "ollama", "configured_model": "test"},
        "jev": {
            "choice": "spam" if decision == "uncertain" else decision,
            "decision": decision, "confidence": 0.99,
            "probabilities": {"ham": 0.005, "spam": 0.99, "phishing": 0.005},
            "input_tokens": 2000,
        },
    }


class MockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mock_jev.create_server(port=0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.server.outcome, self.server.delay = "ham", 0

    def post(self, payload=None, authorization="Bearer mock-only"):
        request = urllib.request.Request(
            self.url + "/v1/systemone",
            data=json.dumps(request_payload() if payload is None else payload).encode(),
            headers={"Authorization": authorization, "Content-Type": "application/json"},
        )
        return urllib.request.urlopen(request, timeout=2)

    def test_health(self):
        with urllib.request.urlopen(self.url + "/health", timeout=2) as response:
            self.assertTrue(json.load(response)["mock"])

    def test_categories(self):
        for category in mock_jev.CATEGORIES:
            with self.subTest(category=category):
                self.server.outcome = category
                with self.post() as response:
                    result = json.load(response)
                answer = result["answers"]["category"]
                self.assertEqual(answer["choice"], category)
                self.assertAlmostEqual(sum(answer["probabilities"].values()), 1)
                self.assertEqual(result["model"], "jev-1.13.0")

    def test_uncertain(self):
        self.server.outcome = "uncertain"
        with self.post() as response:
            self.assertLess(json.load(response)["answers"]["category"]["confidence"], 0.9)

    def test_http_errors(self):
        for code in (400, 429, 500, 529):
            with self.subTest(code=code):
                self.server.outcome = str(code)
                with self.assertRaises(urllib.error.HTTPError) as error:
                    self.post()
                self.assertEqual(error.exception.code, code)
                error.exception.close()

    def test_malformed(self):
        self.server.outcome = "malformed"
        with self.post() as response, self.assertRaises(ValueError):
            json.load(response)

    def test_rejects_real_key(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.post(authorization="Bearer not-a-real-key")
        self.assertEqual(error.exception.code, 401)
        error.exception.close()

    def test_rejects_wrong_contract(self):
        for payload in ([], {}, {"model": "jev", "messages": []}):
            with self.subTest(payload=payload), self.assertRaises(urllib.error.HTTPError) as error:
                self.post(payload)
            self.assertEqual(error.exception.code, 422)
            error.exception.close()


class ReportTests(unittest.TestCase):
    def test_plain_and_prefixed_logs(self):
        line = json.dumps(record())
        records = list(summarize.read_records(io.StringIO("unrelated log\nJEV_EVAL " + line + "\n" + line)))
        self.assertEqual(len(records), 2)

    def test_corrupted_record_is_not_silently_dropped(self):
        for line in ("JEV_EVAL {", "JEV_EVAL {}", 'JEV_EVAL {"schema_version":2}'):
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, "line 1"):
                list(summarize.read_records(io.StringIO(line)))

    def test_invalid_shapes_and_nonfinite_values(self):
        for field, value in (("latency_ms", float("nan")), ("message_digest", "bad"),
                             ("baseline", {}), ("require_gpt", "false")):
            item = record()
            item[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                list(summarize.read_records(io.StringIO(json.dumps(item))))

    def test_mode_separation(self):
        result = summarize.summarize([record(), record("b", mode="mock")])
        self.assertEqual(result["scans"], 1)
        self.assertEqual(result["excluded_other_mode_scans"], 1)

    def test_no_labels_no_accuracy(self):
        result = summarize.summarize([record()])
        self.assertEqual(result["agreement"], 0)
        self.assertIsNone(result["paired_labeled_jev"]["precision"])

    def test_same_subset_for_labeled_comparison(self):
        items = [
            record("a", decision="phishing", baseline="ham"),
            record("b", decision="ham", baseline="spam"),
            record("c", decision="uncertain", baseline="spam"),
            record("d", decision="spam", baseline="not_observed"),
        ]
        labels = {"a" * 32: "phishing", "b" * 32: "ham", "c" * 32: "spam", "d" * 32: "spam"}
        result = summarize.summarize(items, labels=labels)
        self.assertEqual(result["paired_labeled_jev"]["n"], 2)
        self.assertEqual(result["paired_labeled_baseline"]["n"], 2)
        self.assertEqual(result["paired_labeled_coverage"], 0.5)
        self.assertEqual(result["paired_labeled_jev"]["ham_false_positive_rate"], 0)
        self.assertEqual(result["paired_labeled_baseline"]["ham_false_positive_rate"], 1)

    def test_repeated_scan_uses_latest_success_for_quality_only(self):
        old, new = record(), record(decision="ham", baseline="ham")
        new["timestamp"] = 200
        result = summarize.summarize([new, old])
        self.assertEqual(result["agreement"], 1)
        self.assertEqual(result["scans"], 2)
        self.assertEqual(result["successful_unique_messages"], 1)
        self.assertEqual(result["successful_input_tokens"], 4000)

    def test_skips_errors_and_abstentions(self):
        skipped, error = record("b"), record("c")
        skipped.update(status="skipped", reason="sample", requested=False)
        error.update(status="error", reason="transport")
        del skipped["jev"], error["jev"]
        result = summarize.summarize([record(decision="uncertain"), skipped, error])
        self.assertEqual(result["comparable_unique_messages"], 0)
        self.assertEqual(result["statuses"], {"ok": 1, "skipped": 1, "error": 1})
        self.assertEqual(result["http_latency_ms"]["n"], 2)

    def test_mixed_configs_rejected(self):
        for key, value in (("model", "jev-1.14.0"), ("sample_rate", 1), ("confidence_threshold", 0.5)):
            changed = record("b")
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                summarize.summarize([record(), changed])
        changed = record("b")
        changed["baseline"]["configured_model"] = "other-model"
        with self.assertRaises(ValueError):
            summarize.summarize([record(), changed])

    def test_current_pipeline_is_distinct_from_ollama_prediction(self):
        item = record(decision="spam", baseline="ham")
        item["rspamd_action"] = "reject"
        result = summarize.summarize([item], labels={"a" * 32: "spam"})
        self.assertEqual(result["paired_labeled_baseline"]["fn"], 1)
        self.assertEqual(result["pipeline_paired_labeled_rspamd"]["tp"], 1)
        self.assertEqual(result["pipeline_paired_labeled_rspamd_ollama"],
                         result["pipeline_paired_labeled_rspamd"])
        item["rspamd_action"] = "soft reject"
        result = summarize.summarize([item], labels={"a" * 32: "spam"})
        self.assertEqual(result["pipeline_paired_labeled_coverage"], 0)
        self.assertEqual(result["pipeline_paired_labeled_jev"]["n"], 0)

    def test_standalone_reports_pipeline_metrics_without_a_gpt_baseline(self):
        item = record(decision="phishing", baseline="not_observed")
        item.update(require_gpt=False, rspamd_action="no action")
        item["baseline"] = {"verdict": "not_observed"}
        result = summarize.summarize([item], labels={"a" * 32: "phishing"})
        self.assertIsNone(result["agreement"])
        self.assertEqual(result["paired_labeled_baseline"]["n"], 0)
        self.assertEqual(result["pipeline_paired_labeled_rspamd"]["fn"], 1)
        self.assertEqual(result["pipeline_paired_labeled_jev"]["tp"], 1)

    def test_selection_modes_and_legacy_records_cannot_be_silently_mixed(self):
        standalone, comparison, legacy = record(), record("b"), record("c")
        standalone["require_gpt"] = False
        comparison["require_gpt"] = True
        for other in (comparison, legacy):
            with self.assertRaisesRegex(ValueError, "selection"):
                summarize.summarize([standalone, other])
        self.assertEqual(summarize.summarize([legacy])["scans"], 1)

    def test_cost_and_percentiles(self):
        items = [record(format(index, "x")) for index in range(10)]
        for index, item in enumerate(items):
            item["latency_ms"] = (index + 1) * 100
        result = summarize.summarize(items)
        self.assertAlmostEqual(result["estimated_success_cost_usd"], 0.00084)
        self.assertEqual(result["http_latency_ms"]["p95"], 1000)
        self.assertEqual(result["http_latency_ms"]["p50"], 500)

    def test_labels_validation(self):
        labels = summarize.read_labels(io.StringIO("message_digest,label\n" + "a" * 32 + ",ham\n"))
        self.assertEqual(labels["a" * 32], "ham")
        for csv_text in ("digest,label\na,ham\n", "message_digest,label\na,ham\na,spam\n",
                         "message_digest,label\na,unknown\n"):
            with self.subTest(csv_text=csv_text), self.assertRaises(ValueError):
                summarize.read_labels(io.StringIO(csv_text))

    def test_empty_log(self):
        result = summarize.summarize([])
        self.assertEqual(result["scans"], 0)
        self.assertIsNone(result["agreement"])
        self.assertIsNone(result["http_latency_ms"]["p99"])

    def test_evidence_versions_are_separate_from_legacy_observations(self):
        old, new = record(), record("b")
        new.update(evidence_version="email-evidence-v2", utf8_repaired_fields=2)
        with self.assertRaisesRegex(ValueError, "evidence"):
            summarize.summarize([old, new])
        result = summarize.summarize([old, new], evidence_version="email-evidence-v2")
        self.assertEqual(result["scans"], 1)
        self.assertEqual(result["excluded_other_evidence_scans"], 1)
        self.assertEqual(result["excluded_other_mode_scans"], 0)
        self.assertEqual(result["utf8_repaired_scans"], 1)
        self.assertEqual(result["utf8_repaired_fields"], 2)
        self.assertEqual(summarize.summarize([old])["scans"], 1)

    def test_reports_http_errors_repairs_and_abstentions(self):
        success, error = record(decision="uncertain"), record("b")
        success.update(http_status=200, utf8_repaired_fields=3)
        error.update(status="error", reason="http_status", http_status=400,
                     api_error="body_parse_error")
        del error["jev"]
        result = summarize.summarize([success, error])
        self.assertEqual(result["http_statuses"], {"200": 1, "400": 1})
        self.assertEqual(result["api_error_classes"], {"body_parse_error": 1})
        self.assertEqual(result["utf8_repaired_scans"], 1)
        self.assertEqual(result["jev_abstention_rate"], 1)

    def test_invalid_diagnostic_metadata_is_rejected(self):
        for field, value in (
            ("evidence_version", ""), ("evidence_version", False),
            ("utf8_repaired_fields", -1), ("utf8_repaired_fields", 1.5),
            ("utf8_repaired_fields", True), ("api_error", "arbitrary upstream text"),
        ):
            item = record()
            item[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                list(summarize.read_records(io.StringIO(json.dumps(item))))

    def test_mock_cost_is_zero(self):
        result = summarize.summarize([record(mode="mock")], mode="mock")
        self.assertEqual(result["estimated_success_cost_usd"], 0)
        self.assertIn("synthetic", result["warning"])


if __name__ == "__main__":
    unittest.main()
