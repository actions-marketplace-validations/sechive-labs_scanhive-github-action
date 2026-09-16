const assert = require("node:assert/strict");
const test = require("node:test");

const action = require("../dist/index.js");

test("normalizes the ScanHive server URL", () => {
  assert.equal(action.normalizeServerUrl("http://127.0.0.1:8000/"), "http://127.0.0.1:8000");
});

test("accepts supported scan types with exact casing", () => {
  assert.equal(action.validateScanType("IaC"), "IaC");
  assert.throws(() => action.validateScanType("iac"), /Invalid scan type/);
});

test("accepts a project name or a UUID", () => {
  assert.equal(
    action.validateProject("050faa1c-3739-4464-b049-8d735b11cc17"),
    "050faa1c-3739-4464-b049-8d735b11cc17",
  );
  assert.equal(action.validateProject("my-project"), "my-project");
  assert.equal(action.validateProject("  my-project  "), "my-project");
  assert.throws(() => action.validateProject("   "), /must not be empty/);
});
