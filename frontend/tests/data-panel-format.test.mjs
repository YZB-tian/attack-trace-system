import assert from "node:assert/strict";
import test from "node:test";
import { dataTime, endpointLabel, parseEvidenceSummary } from "../src/components/data-panel-format.ts";

test("Beacon evidence keeps zero and false, and marks heuristic scores as non-probabilities", () => {
  const original = JSON.stringify({ sample_count: 0, span: 0, median_interval: 0, regularity: 0, stable_size: false, score_kind: "heuristic_not_probability" });
  const parsed = parseEvidenceSummary(original);
  assert.equal(parsed.structured, true);
  assert.equal(parsed.heuristic, true);
  assert.equal(parsed.original, original);
  assert.deepEqual(Object.fromEntries(parsed.fields.map(({ key, value }) => [key, value])), {
    sample_count: "0", span: "0 s", median_interval: "0 s", regularity: "0.00", stable_size: "否", score_kind: "启发式评分（非概率）",
  });
});

test("unknown evidence fields retain nested objects, arrays and nulls", () => {
  const original = '{"sample_count":10,"unknown":{"values":[0,false,null]},"__proto__":{"keep":true}}';
  const parsed = parseEvidenceSummary(original);
  assert.equal(parsed.fields[0].value, "10");
  assert.deepEqual(parsed.otherFields.map(({ key }) => key), ["unknown", "__proto__"]);
  assert.deepEqual(JSON.parse(parsed.otherFields[0].value), { values: [0, false, null] });
  assert.deepEqual(JSON.parse(parsed.otherFields[1].value), { keep: true });
  assert.equal(parsed.original, original);
});

test("plain text, invalid JSON, arrays and scalar JSON remain verbatim text", () => {
  for (const original of ["Periodic communication", "{invalid", "[]", "null", "false", "0", '"heuristic_not_probability"', "  "]) {
    const parsed = parseEvidenceSummary(original);
    assert.equal(parsed.structured, false);
    assert.equal(parsed.original, original);
    assert.equal(parsed.heuristic, false);
    assert.deepEqual(parsed.fields, []);
  }
});

test("unusual known-field types do not get silently coerced into measurements", () => {
  const parsed = parseEvidenceSummary('{"span":"0","regularity":null,"stable_size":"false","score_kind":false}');
  assert.equal(parsed.heuristic, false);
  assert.deepEqual(Object.fromEntries(parsed.fields.map(({ key, value }) => [key, value])), {
    span: "0", regularity: "null", stable_size: "false", score_kind: "false",
  });
});

test("empty objects remain structured and unrelated score kinds stay unchanged", () => {
  const empty = parseEvidenceSummary("{}");
  assert.equal(empty.structured, true);
  assert.equal(empty.fields.length + empty.otherFields.length, 0);
  const parsed = parseEvidenceSummary('{"score_kind":"other"}');
  assert.equal(parsed.heuristic, false);
  assert.equal(parsed.fields[0].value, "other");
});

test("network endpoints distinguish missing ports, port zero and IPv6", () => {
  assert.equal(endpointLabel("10.10.2.10", 0), "10.10.2.10:0");
  assert.equal(endpointLabel("2001:db8::1", 443), "[2001:db8::1]:443");
  assert.equal(endpointLabel("2001:db8::1", null), "2001:db8::1");
  assert.equal(endpointLabel(null, 0), "地址未提供:0");
});

test("invalid timestamps stay readable instead of crashing the panel", () => {
  assert.equal(dataTime("invalid-timestamp"), "invalid-timestamp");
  assert.equal(dataTime(null), "未提供");
});
