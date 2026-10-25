// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package messages implements Aroha Layer 3 — Messaging.
//
// Provides the envelope builder, validator, nonce registry, and all message
// type constants.
package messages

// Message type constants — the 19 ArohaMessageType values of
// @aroha-sdk/core (packages/aroha-core/src/messages/types.ts).
const (
	TypeRequest           = "ArohaRequest"
	TypeResponse          = "ArohaResponse"
	TypeStream            = "ArohaStream"
	TypeNegotiate         = "ArohaNegotiate"
	TypeCounterOffer      = "ArohaCounterOffer"
	TypeAccept            = "ArohaAccept"
	TypeReserve           = "ArohaReserve"
	TypeReserveAck        = "ArohaReserveAck"
	TypeCommit            = "ArohaCommit"
	TypeCommitAck         = "ArohaCommitAck"
	TypeCancel            = "ArohaCancel"
	TypeCancelAck         = "ArohaCancelAck"
	TypeDelegate          = "ArohaDelegate"
	TypeError             = "ArohaError"
	TypeSatisfaction      = "ArohaSatisfactionSignal"
	TypeSpendingMandate   = "ArohaSpendingMandate"
	TypeTaskMandate       = "ArohaTaskMandate"
	TypeDispute           = "ArohaDispute"
	TypeDisputeResolution = "ArohaDisputeResolution"
)

// MessageTypes lists every message type, in the TypeScript declaration order.
var MessageTypes = []string{
	TypeRequest, TypeResponse, TypeStream, TypeNegotiate, TypeCounterOffer,
	TypeAccept, TypeReserve, TypeReserveAck, TypeCommit, TypeCommitAck,
	TypeCancel, TypeCancelAck, TypeDelegate, TypeError, TypeSatisfaction,
	TypeSpendingMandate, TypeTaskMandate, TypeDispute, TypeDisputeResolution,
}

// IsMessageType reports whether t is one of the protocol's message types.
func IsMessageType(t string) bool {
	for _, mt := range MessageTypes {
		if mt == t {
			return true
		}
	}
	return false
}

// ErrorCode is the wire value for the "code" field of a ArohaError body.
// Values must match the TypeScript ArohaErrorCode enum exactly so that agents
// implemented in different SDKs can interoperate.
type ErrorCode string

const (
	// Auth / access
	ErrUnauthorized ErrorCode = "Aroha_UNAUTHORIZED"
	ErrForbidden    ErrorCode = "Aroha_FORBIDDEN"

	// Protocol
	ErrInvalidSignature       ErrorCode = "Aroha_INVALID_SIGNATURE"
	ErrExpiredMessage         ErrorCode = "Aroha_EXPIRED_MESSAGE"
	ErrReplayDetected         ErrorCode = "Aroha_REPLAY_DETECTED"
	ErrUnknownCapability      ErrorCode = "Aroha_UNKNOWN_CAPABILITY"
	ErrTrustLevelInsufficient ErrorCode = "Aroha_TRUST_LEVEL_INSUFFICIENT"

	// Saga
	ErrReservationFailed  ErrorCode = "Aroha_RESERVATION_FAILED"
	ErrReservationExpired ErrorCode = "Aroha_RESERVATION_EXPIRED"
	ErrCommitFailed       ErrorCode = "Aroha_COMMIT_FAILED"
	ErrCancelFailed       ErrorCode = "Aroha_CANCEL_FAILED"
	ErrInvalidToken       ErrorCode = "Aroha_INVALID_TOKEN"

	// Availability
	ErrNoInventory        ErrorCode = "Aroha_NO_INVENTORY"
	ErrCapacityExceeded   ErrorCode = "Aroha_CAPACITY_EXCEEDED"
	ErrServiceUnavailable ErrorCode = "Aroha_SERVICE_UNAVAILABLE"

	// Generic
	ErrInternalError ErrorCode = "Aroha_INTERNAL_ERROR"
	ErrInvalidParams ErrorCode = "Aroha_INVALID_PARAMS"

	// Capability Schema Negotiation (note: no Aroha_ prefix on the wire)
	ErrCSNNoStructuralMatch ErrorCode = "CSN_NO_STRUCTURAL_MATCH"

	// Task-mandate enforcement
	ErrActionLimitExceeded     ErrorCode = "Aroha_ACTION_LIMIT_EXCEEDED"
	ErrComputeLimitExceeded    ErrorCode = "Aroha_COMPUTE_LIMIT_EXCEEDED"
	ErrReversibilityViolation  ErrorCode = "Aroha_REVERSIBILITY_VIOLATION"
	ErrHumanGateRequired       ErrorCode = "Aroha_HUMAN_GATE_REQUIRED"
	ErrDataAccessViolation     ErrorCode = "Aroha_DATA_ACCESS_VIOLATION"
	ErrSandboxRequired         ErrorCode = "Aroha_SANDBOX_REQUIRED"
	ErrDelegationDepthExceeded ErrorCode = "Aroha_DELEGATION_DEPTH_EXCEEDED"
	ErrCapabilityNotPermitted  ErrorCode = "Aroha_CAPABILITY_NOT_PERMITTED"

	// Settlement and disputes (design spec §8)
	ErrSettlementRailMismatch ErrorCode = "Aroha_SETTLEMENT_RAIL_MISMATCH"
	ErrCommitDisputed         ErrorCode = "Aroha_COMMIT_DISPUTED"
)

// ErrorCodes lists every ArohaErrorCode value, in the TypeScript enum order.
var ErrorCodes = []ErrorCode{
	ErrUnauthorized, ErrForbidden,
	ErrInvalidSignature, ErrExpiredMessage, ErrReplayDetected, ErrUnknownCapability, ErrTrustLevelInsufficient,
	ErrReservationFailed, ErrReservationExpired, ErrCommitFailed, ErrCancelFailed, ErrInvalidToken,
	ErrNoInventory, ErrCapacityExceeded, ErrServiceUnavailable,
	ErrInternalError, ErrInvalidParams,
	ErrCSNNoStructuralMatch,
	ErrActionLimitExceeded, ErrComputeLimitExceeded, ErrReversibilityViolation, ErrHumanGateRequired,
	ErrDataAccessViolation, ErrSandboxRequired, ErrDelegationDepthExceeded, ErrCapabilityNotPermitted,
	ErrSettlementRailMismatch, ErrCommitDisputed,
}

// ErrorDocsURL returns the documentation URL for an error code.
func ErrorDocsURL(code ErrorCode) string {
	return "https://aroha-labs.com/docs/errors#" + string(code)
}
