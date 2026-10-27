// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.messages;

import java.util.Set;

/**
 * Aroha Layer 3 — Message Types and Error Codes
 *
 * All valid Aroha message type strings and error code wire values,
 * mirroring the TypeScript SDK's types.ts exactly so that agents
 * implemented in different SDKs interoperate correctly.
 */
public final class MessageTypes {

    private MessageTypes() {}

    // ── Message Types ─────────────────────────────────────────────────────────

    public static final String Aroha_REQUEST        = "ArohaRequest";
    public static final String Aroha_RESPONSE       = "ArohaResponse";
    public static final String Aroha_STREAM         = "ArohaStream";
    public static final String Aroha_NEGOTIATE      = "ArohaNegotiate";
    public static final String Aroha_COUNTER_OFFER  = "ArohaCounterOffer";
    public static final String Aroha_ACCEPT         = "ArohaAccept";
    public static final String Aroha_RESERVE        = "ArohaReserve";
    public static final String Aroha_RESERVE_ACK    = "ArohaReserveAck";
    public static final String Aroha_COMMIT         = "ArohaCommit";
    public static final String Aroha_COMMIT_ACK     = "ArohaCommitAck";
    public static final String Aroha_CANCEL         = "ArohaCancel";
    public static final String Aroha_CANCEL_ACK     = "ArohaCancelAck";
    public static final String Aroha_DELEGATE       = "ArohaDelegate";
    public static final String Aroha_ERROR          = "ArohaError";
    public static final String Aroha_SATISFACTION   = "ArohaSatisfactionSignal";
    public static final String Aroha_SPENDING_MANDATE   = "ArohaSpendingMandate";
    public static final String Aroha_TASK_MANDATE       = "ArohaTaskMandate";
    public static final String Aroha_DISPUTE            = "ArohaDispute";
    public static final String Aroha_DISPUTE_RESOLUTION = "ArohaDisputeResolution";

    /** All 19 members of the TypeScript {@code ArohaMessageType} union. */
    public static final Set<String> ALL = Set.of(
        Aroha_REQUEST, Aroha_RESPONSE, Aroha_STREAM,
        Aroha_NEGOTIATE, Aroha_COUNTER_OFFER, Aroha_ACCEPT,
        Aroha_RESERVE, Aroha_RESERVE_ACK,
        Aroha_COMMIT, Aroha_COMMIT_ACK,
        Aroha_CANCEL, Aroha_CANCEL_ACK,
        Aroha_DELEGATE, Aroha_ERROR, Aroha_SATISFACTION,
        Aroha_SPENDING_MANDATE, Aroha_TASK_MANDATE,
        Aroha_DISPUTE, Aroha_DISPUTE_RESOLUTION
    );

    // ── Error Codes ───────────────────────────────────────────────────────────
    //
    // These are string constants, not an enum, so that the wire value is always
    // the Aroha_* string — not a Java identifier that would break interoperability
    // with TypeScript, Go, and Python agents receiving ArohaError envelopes.
    //
    // Usage:  body.put("code", ErrorCode.UNKNOWN_CAPABILITY);

    public static final class ErrorCode {
        private ErrorCode() {}

        // Auth / access
        public static final String UNAUTHORIZED             = "Aroha_UNAUTHORIZED";
        public static final String FORBIDDEN                = "Aroha_FORBIDDEN";

        // Protocol
        public static final String INVALID_SIGNATURE        = "Aroha_INVALID_SIGNATURE";
        public static final String EXPIRED_MESSAGE          = "Aroha_EXPIRED_MESSAGE";
        public static final String REPLAY_DETECTED          = "Aroha_REPLAY_DETECTED";
        public static final String UNKNOWN_CAPABILITY       = "Aroha_UNKNOWN_CAPABILITY";
        public static final String TRUST_LEVEL_INSUFFICIENT = "Aroha_TRUST_LEVEL_INSUFFICIENT";

        // Saga
        public static final String RESERVATION_FAILED       = "Aroha_RESERVATION_FAILED";
        public static final String RESERVATION_EXPIRED      = "Aroha_RESERVATION_EXPIRED";
        public static final String COMMIT_FAILED            = "Aroha_COMMIT_FAILED";
        public static final String CANCEL_FAILED            = "Aroha_CANCEL_FAILED";
        public static final String INVALID_TOKEN            = "Aroha_INVALID_TOKEN";

        // Availability
        public static final String NO_INVENTORY             = "Aroha_NO_INVENTORY";
        public static final String CAPACITY_EXCEEDED        = "Aroha_CAPACITY_EXCEEDED";
        public static final String SERVICE_UNAVAILABLE      = "Aroha_SERVICE_UNAVAILABLE";

        // Generic
        public static final String INTERNAL_ERROR           = "Aroha_INTERNAL_ERROR";
        public static final String INVALID_PARAMS           = "Aroha_INVALID_PARAMS";

        // Capability Schema Negotiation
        public static final String CSN_NO_STRUCTURAL_MATCH  = "CSN_NO_STRUCTURAL_MATCH";

        // Task-mandate enforcement
        public static final String ACTION_LIMIT_EXCEEDED     = "Aroha_ACTION_LIMIT_EXCEEDED";
        public static final String COMPUTE_LIMIT_EXCEEDED    = "Aroha_COMPUTE_LIMIT_EXCEEDED";
        public static final String REVERSIBILITY_VIOLATION   = "Aroha_REVERSIBILITY_VIOLATION";
        public static final String HUMAN_GATE_REQUIRED       = "Aroha_HUMAN_GATE_REQUIRED";
        public static final String DATA_ACCESS_VIOLATION     = "Aroha_DATA_ACCESS_VIOLATION";
        public static final String SANDBOX_REQUIRED          = "Aroha_SANDBOX_REQUIRED";
        public static final String DELEGATION_DEPTH_EXCEEDED = "Aroha_DELEGATION_DEPTH_EXCEEDED";
        public static final String CAPABILITY_NOT_PERMITTED  = "Aroha_CAPABILITY_NOT_PERMITTED";

        // Settlement
        public static final String SETTLEMENT_RAIL_MISMATCH  = "Aroha_SETTLEMENT_RAIL_MISMATCH";
        public static final String COMMIT_DISPUTED           = "Aroha_COMMIT_DISPUTED";

        // Mandate-chain admission (delegation middleware)
        public static final String NO_MANDATE                = "Aroha_NO_MANDATE";
        public static final String CHAIN_INVALID             = "Aroha_CHAIN_INVALID";
        public static final String UNTRUSTED_ROOT            = "Aroha_UNTRUSTED_ROOT";
        public static final String ROOT_KEY_MISMATCH         = "Aroha_ROOT_KEY_MISMATCH";
        public static final String CHAIN_REJECTED            = "Aroha_CHAIN_REJECTED";
        public static final String SCOPE_UNKNOWN             = "Aroha_SCOPE_UNKNOWN";
        public static final String CONTEXT_MISMATCH          = "Aroha_CONTEXT_MISMATCH";

        /** Every wire value of the TypeScript {@code ArohaErrorCode} enum (35). */
        public static final Set<String> ALL = Set.of(
            UNAUTHORIZED, FORBIDDEN,
            INVALID_SIGNATURE, EXPIRED_MESSAGE, REPLAY_DETECTED, UNKNOWN_CAPABILITY, TRUST_LEVEL_INSUFFICIENT,
            RESERVATION_FAILED, RESERVATION_EXPIRED, COMMIT_FAILED, CANCEL_FAILED, INVALID_TOKEN,
            NO_INVENTORY, CAPACITY_EXCEEDED, SERVICE_UNAVAILABLE,
            INTERNAL_ERROR, INVALID_PARAMS,
            CSN_NO_STRUCTURAL_MATCH,
            ACTION_LIMIT_EXCEEDED, COMPUTE_LIMIT_EXCEEDED, REVERSIBILITY_VIOLATION, HUMAN_GATE_REQUIRED,
            DATA_ACCESS_VIOLATION, SANDBOX_REQUIRED, DELEGATION_DEPTH_EXCEEDED, CAPABILITY_NOT_PERMITTED,
            SETTLEMENT_RAIL_MISMATCH, COMMIT_DISPUTED,
            NO_MANDATE, CHAIN_INVALID, UNTRUSTED_ROOT, ROOT_KEY_MISMATCH, CHAIN_REJECTED,
            SCOPE_UNKNOWN, CONTEXT_MISMATCH
        );

        /** Base of the error reference (TS {@code DOCS}). */
        public static final String DOCS = "https://aroha-labs.com/docs/errors";

        /** Link to the reference entry for {@code code} (TS {@code errorDocsUrl}). */
        public static String docsUrl(String code) {
            return DOCS + "#" + code;
        }
    }
}
