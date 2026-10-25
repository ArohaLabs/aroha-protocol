// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import type { TaskReceipt } from "@aroha-sdk/core";

/** Marker for receipt artifacts inside RunResponse.artifacts. */
export const RECEIPT_ARTIFACT_KIND = "aroha.task-receipt";

export interface TaskReceiptArtifact {
  kind: typeof RECEIPT_ARTIFACT_KIND;
  receipt: TaskReceipt;
  /** Receipts collected from downstream hops, nested in call order. */
  children: TaskReceiptArtifact[];
}
