// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The anti-spam, compliance and relay-authorization surface of RailGun.
//
// This barrel exposes the package-local policy engine to the surfaces (SMTP,
// HTTP, MCP, CLI) and to the outbound delivery engine. It is deliberately
// separate from the package's general barrel so that the policy subsystem can
// be reviewed, audited and consumed as one unit.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md.

// Domain vocabulary.
export {
  REASON_CODES,
  allowedRecipients,
  deniedRecipients,
  isAtLeastAsRestrictive,
  mostRestrictive,
} from "../domain/policy.js";
export type {
  DecisionEvidence,
  Envelope,
  HeaderMap,
  MessageUnderPolicy,
  PolicyDecision,
  PolicyDecisionRecord,
  Principal,
  Recipient,
  RecipientDecision,
  RecipientScope,
  SubmissionDecision,
  SubmissionRequest,
} from "../domain/policy.js";
export {
  BLOCKLIST_ENTRY_KINDS,
  DEFAULT_ROLE_ADDRESSES,
  DEFAULT_SUPPRESSION_EXPIRY_HOURS,
  DMARC_POSTURES,
  DKIM_ALGORITHMS,
  REPUTATION_STATES,
  ROLE_ADDRESS_MODES,
  SUPPRESSION_REASONS,
  WARMUP_STATES,
  isBlocklistEntryKind,
  isDkimAlgorithm,
  isRoleAddressMode,
  isSuppressionReason,
  warmupCapForDay,
} from "../domain/identity.js";
export type {
  AlignmentMode,
  BlocklistEntry,
  BlocklistEntryKind,
  DkimAlgorithm,
  DkimKeyRecord,
  DkimKeyStatus,
  DmarcPosture,
  DnsFailurePolicy,
  RemoteFailPolicy,
  ReputationCounters,
  RoleAddressConfig,
  RoleAddressMode,
  SendingDomain,
  SendingDomainStatus,
  SpfRequirement,
  SuppressionEntry,
  SuppressionReason,
  SuppressionScope,
  WarmupPolicy,
  WarmupState,
} from "../domain/identity.js";

// Ports.
export { fixedClock, systemClock } from "../ports/index.js";
export type {
  AuditSink,
  BlocklistStore,
  BlocklistSubject,
  Clock,
  DkimKeyStore,
  DkimPrivateKeyLoader,
  DnsResolver,
  DuplicateContentStore,
  FeedbackOutcome,
  FeedbackSink,
  RateLimitStore,
  RemoteBlocklistClient,
  ReputationStore,
  SendingDomainRecord,
  SendingDomainStore,
  SuppressionStore,
  VerifiedRecipientStore,
  WarmupStore,
} from "../ports/index.js";

// Identity and address security.
export {
  domainsAligned,
  isDomainWithin,
  isLookalikeDomain,
  isValidDomain,
  levenshtein,
  organizationalDomain,
  parseAddress,
} from "../security/address.js";
export type { AlignmentMode as AddressAlignmentMode, ParsedAddress } from "../security/address.js";
export {
  SPF_MAX_LOOKUPS,
  evaluateSpfRecord,
  parseSpfRecord,
  selectSpfRecord,
  spfExcludesSender,
} from "../security/spf.js";
export type {
  SpfEvaluation,
  SpfMechanism,
  SpfQualifier,
  SpfRecord,
} from "../security/spf.js";
export {
  evaluateDmarcPosture,
  parseDmarcRecord,
  postureBlocksSending,
  selectDmarcRecord,
} from "../security/dmarc.js";
export type { DmarcEvaluation, DmarcPostureInput, DmarcRecord } from "../security/dmarc.js";

// DKIM signing and verification.
export {
  DEFAULT_CANONICALIZATION,
  canonicalizeBody,
  canonicalizeHeader,
  canonicalizeHeaderSet,
  canonicalizeRelaxedBody,
  canonicalizeRelaxedHeader,
  canonicalizeSimpleBody,
  canonicalizeSimpleHeader,
  parseHeaderBlock,
} from "../signer/canonicalization.js";
export type {
  BodyCanonicalization,
  Canonicalization,
  HeaderCanonicalization,
  RawHeader,
} from "../signer/canonicalization.js";
export {
  DEFAULT_SIGN_HEADERS,
  RSA_MIN_BITS,
  bodyHash,
  keyFingerprint,
  signDkim,
  validateKey,
  verifyDkim,
} from "../signer/dkim.js";
export type {
  DkimSignInput,
  DkimSignResult,
  DkimVerifyResult,
} from "../signer/dkim.js";

// Policy engine.
export {
  DEFAULT_POLICY_CONFIG,
  validatePolicyConfig,
} from "../spam/config.js";
export type {
  AuditConfig,
  BlocklistConfig,
  IdentityConfig,
  PolicyConfig,
  RateLimitConfig,
  RelayConfig,
  SignerConfig,
  SpamConfig,
} from "../spam/config.js";
export {
  CONTENT_FEATURES,
  FEATURE_WEIGHTS,
  SPAM_MODEL_VERSION,
  contentHmac,
  scoreContent,
  scoreToDecision,
} from "../spam/content.js";
export type { ContentFeature, ContentScore, ContentScoringInput } from "../spam/content.js";
export { checkLimits, checkWarmup, warmupDayIndex, warmupDayKey } from "../spam/limits.js";
export type { LimitContext, LimitOutcome, WarmupOutcome } from "../spam/limits.js";
export {
  authorizeRelay,
  authorizeSenderDomain,
  effectiveScope,
} from "../spam/relay.js";
export type { RelayAuthorization } from "../spam/relay.js";
export {
  checkBlocklist,
  checkRoleAddress,
  checkSuppression,
  isBulkToRole,
  isVerifiedRecipient,
} from "../spam/abuse.js";
export type { AbuseCheckResult } from "../spam/abuse.js";
export {
  dmarcBlocks,
  evaluateDmarc,
  evaluateSpfPosture,
  resolveIdentityPosture,
  verifyPublishedDkimRecord,
} from "../spam/identity.js";
export type { IdentityPosture, SpfPosture } from "../spam/identity.js";
export { PolicyEngine, hashRecipient, toRecipient } from "../spam/engine.js";
export type { PolicyEngineDeps } from "../spam/engine.js";
export { runCheapGates } from "../spam/cheap-gates.js";
export type { CheapGateDeps, PrecheckResult } from "../spam/cheap-gates.js";
export { validateRequestShape } from "../spam/shape.js";
export type { RequestShapeResult } from "../spam/shape.js";
export {
  appendAudit,
  auditFailureRecord,
  buildDecisionRecord,
} from "../spam/decision.js";
export type { DecisionExtras } from "../spam/decision.js";
export {
  SMTP_POLICY_CODES,
  createSmtpPolicyHooks,
  headersToMap,
  toSmtpOutcome,
} from "../spam/smtp-hooks.js";
export type {
  PrincipalResolver,
  SmtpHookContext,
  SmtpPolicyOutcome,
} from "../spam/smtp-hooks.js";
export {
  MAX_FEEDBACK_BYTES,
  SOFT_BOUNCE_THRESHOLD,
  classifyFeedback,
  extractDomain,
  extractRecipient,
  extractStatus,
  ingestFeedback,
  isComplaint,
  parseFeedback,
  secretsMatch,
  verifyFeedbackSignature,
} from "../spam/feedback.js";
export type { ParsedFeedback, SoftBounceCounter } from "../spam/feedback.js";
