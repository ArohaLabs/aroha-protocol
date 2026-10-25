// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

export {
  generateCredentialSecret, scopePoint, proveUniqueness, verifyUniquenessProof,
  type CredentialSecret, type NullifierProof, type VerifyResult,
} from "./nullifier.js";

export {
  issueCertificate, verifyCertificate,
  type KycCertificate, type CertVerifyResult,
} from "./kyc-issuer.js";
