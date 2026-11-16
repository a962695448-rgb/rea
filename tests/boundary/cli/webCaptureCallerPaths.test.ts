import { mkdir, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { publishCliAnalysisEvidence } from "../../../src/cli/analysisEvidenceDelivery.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { WEB_NETWORK_CAPTURE_LIMITS } from "../../../src/domain/webNetworkCapture.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import {
  protobufCaptureDescriptor,
  protobufHar,
} from "../../fixtures/protobufCapture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest(
  "names an oversized capture with each adapter's public input field",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-capture-oversized-");
    const path = join(root, "capture.har");
    await writeFile(path, "");
    await truncate(path, WEB_NETWORK_CAPTURE_LIMITS.inputBytes + 1);
    const { call } = await connectLocalToolsMcp();
    for (const format of ["har", "mitmproxy"] as const) {
      const cliResult = await cli.run({
        arguments: ["inspect-web-network-capture", path, format, "--json"],
      });
      expect(cliResult.exitCode).not.toBe(0);
      const mcpResult = await call("inspect_web_network_capture", {
        capture_path: path,
        format,
      });
      expect(mcpResult.isError).toBe(true);
      for (const [error, field] of [
        [cliResult.json, "capturePath"],
        [parseMcpToolError(mcpResult).error, "capture_path"],
      ] as const)
        expect(error).toMatchObject({
          category: "invalid_input",
          details: {
            issues: [
              {
                path: [field],
                reason: "out_of_range",
                expected: {
                  maximum_capture_bytes: WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
                },
              },
            ],
          },
        });
    }
  },
);

cliTest(
  "retains selected capture paths without exposing declared sensitive values",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-capture-selected-");
    const cwd = join(root, "secret-parent");
    await mkdir(cwd);
    await writeFile(join(cwd, "capture.har"), protobufHar());
    await writeFile(join(cwd, "capture.pb"), protobufCaptureDescriptor());
    const args = [
      "inspect-web-network-capture",
      "./capture.har",
      "har",
      "--record",
      "0",
      "--protobuf-schema",
      "./capture.pb",
      "--protobuf-message",
      "capture.Message",
      "--json",
    ];
    const result = await cli.run({ cwd, arguments: args });
    expect(result.exitCode, result.stderr).toBe(0);
    const evidence = parseEvidence(result.json);
    expect(evidence.caller_input_path).toBe("./capture.har");
    expect(evidence.caller_input_paths).toEqual({
      descriptor_set_path: "./capture.pb",
    });
    const parentExcluded = await cli.run({
      cwd,
      arguments: [...args, "--sensitive-value", "secret-parent"],
    });
    expect(parentExcluded.exitCode, parentExcluded.stderr).toBe(0);
    expect(JSON.stringify(parentExcluded.json)).not.toContain("secret-parent");
    expect(parseEvidence(parentExcluded.json).caller_input_path).toBe(
      "./capture.har",
    );
    const originalExcluded = await cli.run({
      cwd,
      arguments: [...args, "--sensitive-value", "capture.har"],
    });
    expect(originalExcluded.exitCode, originalExcluded.stderr).toBe(0);
    expect(JSON.stringify(originalExcluded.json)).not.toContain("capture.har");
    const safe = parseEvidence(originalExcluded.json);
    expect(safe.caller_input_path).toBeUndefined();
    expect(safe.caller_input_paths).toEqual({
      descriptor_set_path: "./capture.pb",
    });
    const summaryExcluded = await cli.run({
      cwd,
      arguments: [
        ...args,
        "--sensitive-value",
        "capture.har",
        "--detail",
        "summary",
        "--evidence_output",
        "./safe-evidence.json",
      ],
    });
    expect(summaryExcluded.exitCode, summaryExcluded.stderr).toBe(0);
    const summary = parseEvidence(
      (summaryExcluded.json as { summary: unknown }).summary,
    );
    expect(summary.caller_input_path).toBeUndefined();
    expect(summary.caller_input_paths).toEqual({
      descriptor_set_path: "./capture.pb",
    });
    expect(JSON.stringify(summaryExcluded.json)).not.toContain("capture.har");
    const applicationSummary = parseEvidence(
      (
        (await publishCliAnalysisEvidence(
          { ok: true, value: safe },
          {
            operation: safe.operation,
            signal: new AbortController().signal,
            detail: "summary",
            evidenceOutput: join(cwd, "application-evidence.json"),
          },
        )) as { summary: unknown }
      ).summary,
    );
    expect(applicationSummary.caller_input_path).toBeUndefined();
    expect(applicationSummary.caller_input_paths).toEqual({
      descriptor_set_path: "./capture.pb",
    });
    const descriptorExcluded = await cli.run({
      cwd,
      arguments: [...args, "--sensitive-value", "capture.pb"],
    });
    expect(descriptorExcluded.exitCode, descriptorExcluded.stderr).toBe(0);
    expect(JSON.stringify(descriptorExcluded.json)).not.toContain("capture.pb");
    const safeDescriptor = parseEvidence(descriptorExcluded.json);
    expect(safeDescriptor.caller_input_path).toBe("./capture.har");
    expect(safeDescriptor.caller_input_paths).toBeUndefined();
    const { client, call } = await connectLocalToolsMcp();
    try {
      const response = await call("inspect_web_network_capture", {
        capture_path: join(cwd, "capture.har"),
        format: "har",
        record_ordinals: [0],
        protobuf: {
          schema: {
            descriptor_set_path: join(cwd, "capture.pb"),
            message_type: "capture.Message",
          },
        },
        sensitive_values: ["secret-parent"],
      });
      expect(response.isError, JSON.stringify(response)).not.toBe(true);
      expect(JSON.stringify(response)).not.toContain("secret-parent");
      expect(
        parseEvidence(response.structuredContent).caller_input_path,
      ).toBeUndefined();
    } finally {
      await client.close();
    }
  },
);
