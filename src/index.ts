import * as fs from "node:fs";
import * as path from "node:path";
import * as core from "@actions/core";

const SCAN_TYPES = new Set([
  "SAST",
  "SCA",
  "Secrets",
  "Container Security",
  "IaC",
  "DAST",
]);

export function normalizeServerUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("ScanHive server URL must use http or https.");
  }
  return url.toString().replace(/\/$/, "");
}

export function validateProject(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("ScanHive project (name or ID) must not be empty.");
  }
  return trimmed;
}

export function validateScanType(value: string): string {
  if (!SCAN_TYPES.has(value)) {
    throw new Error(`Invalid scan type '${value}'. Expected one of: ${[...SCAN_TYPES].join(", ")}.`);
  }
  return value;
}

async function run(): Promise<void> {
  try {
    const serverUrl = normalizeServerUrl(core.getInput("server-url", { required: true }));
    const apiKey = core.getInput("api-key", { required: true });
    const project = validateProject(core.getInput("project", { required: true }));
    const scanType = validateScanType(core.getInput("scan-type", { required: true }));
    const sarifFile = path.resolve(core.getInput("sarif-file", { required: true }));

    core.setSecret(apiKey);
    if (!fs.existsSync(sarifFile) || !fs.statSync(sarifFile).isFile()) {
      throw new Error(`SARIF file not found: ${sarifFile}`);
    }

    const report = fs.readFileSync(sarifFile);
    const form = new FormData();
    form.append("scan_type", scanType);
    form.append("file", new Blob([report], { type: "application/sarif+json" }), path.basename(sarifFile));

    core.info(`Uploading ${path.basename(sarifFile)} to ScanHive project ${project}.`);
    const response = await fetch(
      `${serverUrl}/api/v1/scans/upload/${encodeURIComponent(project)}`,
      { method: "POST", headers: { Authorization: `Bearer ${apiKey}` }, body: form },
    );
    const responseText = await response.text();
    if (!response.ok) {
      throw new Error(`ScanHive upload failed (${response.status}): ${responseText}`);
    }

    const result = JSON.parse(responseText) as { scan_id?: string; findings?: number };
    core.setOutput("scan-id", result.scan_id || "");
    core.setOutput("findings", result.findings ?? 0);
    core.info(`Uploaded ${result.findings ?? 0} findings to ScanHive.`);
  } catch (error) {
    core.setFailed(error instanceof Error ? error.message : String(error));
  }
}

if (require.main === module) {
  void run();
}
