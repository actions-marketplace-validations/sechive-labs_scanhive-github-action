const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const action = require("../dist/index.js");

const INPUT_KEYS = ["server-url", "api-key", "project", "scan-type", "sarif-file"];

function setInputs(overrides = {}) {
  const values = {
    "server-url": "http://127.0.0.1:8000",
    "api-key": "test-secret-key",
    project: "my-project",
    "scan-type": "IaC",
    "sarif-file": overrides["sarif-file"] ?? makeSarifFile(),
    ...overrides,
  };
  for (const key of INPUT_KEYS) {
    process.env[`INPUT_${key.toUpperCase()}`] = values[key];
  }
  return values;
}

function clearInputs() {
  for (const key of INPUT_KEYS) {
    delete process.env[`INPUT_${key.toUpperCase()}`];
  }
}

function makeSarifFile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scanhive-action-"));
  const file = path.join(dir, "results.sarif");
  fs.writeFileSync(file, JSON.stringify({ version: "2.1.0", runs: [] }));
  return file;
}

function makeOutputFile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scanhive-outputs-"));
  const file = path.join(dir, "github_output");
  fs.writeFileSync(file, "");
  process.env.GITHUB_OUTPUT = file;
  return file;
}

async function captureStdout(fn) {
  const originalWrite = process.stdout.write.bind(process.stdout);
  let output = "";
  process.stdout.write = (chunk) => {
    output += chunk.toString();
    return true;
  };
  try {
    await fn();
  } finally {
    process.stdout.write = originalWrite;
  }
  return output;
}

test("run() uploads with an Authorization: Bearer header, not X-API-Key", async (t) => {
  setInputs();
  const outputFile = makeOutputFile();
  const originalExitCode = process.exitCode;
  let capturedUrl;
  let capturedOptions;
  global.fetch = async (url, options) => {
    capturedUrl = url;
    capturedOptions = options;
    return { ok: true, status: 200, text: async () => JSON.stringify({ scan_id: "abc-123", findings: 4 }) };
  };

  t.after(() => {
    clearInputs();
    delete process.env.GITHUB_OUTPUT;
    process.exitCode = originalExitCode;
  });

  await action.run();

  assert.equal(capturedUrl, "http://127.0.0.1:8000/api/v1/scans/upload/my-project");
  assert.equal(capturedOptions.method, "POST");
  assert.deepEqual(capturedOptions.headers, { Authorization: "Bearer test-secret-key" });
  assert.ok(!("X-API-Key" in capturedOptions.headers), "must not send the old X-API-Key header");

  const form = capturedOptions.body;
  assert.equal(form.get("scan_type"), "IaC");
  const filePart = form.get("file");
  assert.equal(filePart.name, "results.sarif");
  assert.equal(filePart.type, "application/sarif+json");

  const outputs = fs.readFileSync(outputFile, "utf8");
  assert.match(outputs, /scan-id<<.*?\nabc-123\n/s);
  assert.match(outputs, /findings<<.*?\n4\n/s);
});

test("run() masks the API key so it never appears in logs", async (t) => {
  setInputs({ "api-key": "super-secret-value" });
  makeOutputFile();
  const originalExitCode = process.exitCode;
  global.fetch = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ scan_id: "x", findings: 0 }),
  });

  t.after(() => {
    clearInputs();
    delete process.env.GITHUB_OUTPUT;
    process.exitCode = originalExitCode;
  });

  const stdout = await captureStdout(() => action.run());
  assert.match(stdout, /::add-mask::super-secret-value/);
});

test("run() fails with the response status and body when the upload is rejected", async (t) => {
  setInputs();
  makeOutputFile();
  const originalExitCode = process.exitCode;
  global.fetch = async () => ({ ok: false, status: 401, text: async () => "Unauthorized" });

  t.after(() => {
    clearInputs();
    delete process.env.GITHUB_OUTPUT;
    process.exitCode = originalExitCode;
  });

  const stdout = await captureStdout(() => action.run());
  assert.equal(process.exitCode, 1);
  assert.match(stdout, /ScanHive upload failed \(401\): Unauthorized/);
});

test("run() fails when the SARIF file does not exist", async (t) => {
  const missing = path.join(os.tmpdir(), "does-not-exist.sarif");
  setInputs({ "sarif-file": missing });
  makeOutputFile();
  const originalExitCode = process.exitCode;
  global.fetch = async () => {
    throw new Error("fetch should not be called when the SARIF file is missing");
  };

  t.after(() => {
    clearInputs();
    delete process.env.GITHUB_OUTPUT;
    process.exitCode = originalExitCode;
  });

  const stdout = await captureStdout(() => action.run());
  assert.equal(process.exitCode, 1);
  assert.match(stdout, /SARIF file not found/);
});

test("run() rejects an unsupported scan type before calling fetch", async (t) => {
  setInputs({ "scan-type": "iac" });
  makeOutputFile();
  const originalExitCode = process.exitCode;
  global.fetch = async () => {
    throw new Error("fetch should not be called for an invalid scan type");
  };

  t.after(() => {
    clearInputs();
    delete process.env.GITHUB_OUTPUT;
    process.exitCode = originalExitCode;
  });

  const stdout = await captureStdout(() => action.run());
  assert.equal(process.exitCode, 1);
  assert.match(stdout, /Invalid scan type 'iac'/);
});
