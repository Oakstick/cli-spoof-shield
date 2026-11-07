import Foundation

// MARK: - Domain Models

public enum STIRSHAKENAttestation: String, Codable, CaseIterable {
    case fullA = "A"          // Full Attestation: Carrier verified caller identity & number ownership
    case partialB = "B"       // Partial Attestation: Carrier knows customer, but not specific DID ownership
    case gatewayC = "C"       // Gateway Attestation: International/TDM gateway, no ownership verification
    case notVerified = "NONE" // No PASSporT / verstat=No-TN-Validation
    case failed = "FAILED"    // Cryptographic signature invalid or verstat=TN-Validation-Failed
}

public enum CarrierLineType: String, Codable, CaseIterable {
    case mobile = "mobile"
    case landline = "landline"
    case fixedVoip = "fixedVoip"         // Physical/Enterprise VoIP (e.g., Comcast Business, Vonage residential)
    case nonFixedVoip = "nonFixedVoip"   // Burner/Virtual VoIP (high risk for CLI spoofing & robocalling)
    case tollFree = "tollFree"
    case unknown = "unknown"
}

public enum CallDefenseAction: String, Codable {
    case allow = "ALLOW"
    case warnLabel = "WARN_LABEL"
    case block = "BLOCK"
}

public struct SIPHeaderContext: Codable {
    public let fromURI: String?
    public let pAssertedIdentity: String?
    public let verstat: String?          // e.g., "TN-Validation-Passed", "TN-Validation-Failed", "No-TN-Validation"
    public let passportJWT: String?      // RFC 8225 Identity header JWT token

    public init(fromURI: String? = nil, pAssertedIdentity: String? = nil, verstat: String? = nil, passportJWT: String? = nil) {
        self.fromURI = fromURI
        self.pAssertedIdentity = pAssertedIdentity
        self.verstat = verstat
        self.passportJWT = passportJWT
    }
}

public struct ProtectedEntity: Codable, Identifiable {
    public let id: String
    public let name: String              // e.g., "Chase Fraud Dept", "IRS Official", "Citibank Security"
    public let e164Number: Int64         // e.g., 18009359935
    public let category: String          // "Bank", "Government", "VIP"
    public let inboundAllowed: Bool      // False if number is outbound-only customer service (never dials out)

    public init(id: String = UUID().uuidString, name: String, e164Number: Int64, category: String, inboundAllowed: Bool = false) {
        self.id = id
        self.name = name
        self.e164Number = e164Number
        self.category = category
        self.inboundAllowed = inboundAllowed
    }
}

public struct DefensePolicyConfig: Codable {
    public var blockNonFixedVoip: Bool
    public var blockFailedStirShaken: Bool
    public var enableNeighborSpoofShield: Bool
    public var neighborSpoofAction: CallDefenseAction
    public var protectOutboundOnlyInstitutions: Bool
    public var userOwnNumberE164: Int64

    public init(
        blockNonFixedVoip: Bool = true,
        blockFailedStirShaken: Bool = true,
        enableNeighborSpoofShield: Bool = true,
        neighborSpoofAction: CallDefenseAction = .warnLabel,
        protectOutboundOnlyInstitutions: Bool = true,
        userOwnNumberE164: Int64 = 14155550100
    ) {
        self.blockNonFixedVoip = blockNonFixedVoip
        self.blockFailedStirShaken = blockFailedStirShaken
        self.enableNeighborSpoofShield = enableNeighborSpoofShield
        self.neighborSpoofAction = neighborSpoofAction
        self.protectOutboundOnlyInstitutions = protectOutboundOnlyInstitutions
        self.userOwnNumberE164 = userOwnNumberE164
    }
}

public struct SpoofRiskSignal: Codable {
    public let layer: String
    public let code: String
    public let scoreDelta: Int
    public let explanation: String
}

public struct CallScreeningVerdict: Codable {
    public let callerE164: Int64
    public let riskScore: Int
    public let action: CallDefenseAction
    public let callKitLabel: String
    public let attestation: STIRSHAKENAttestation
    public let lineType: CarrierLineType
    public let carrierName: String
    public let signals: [SpoofRiskSignal]
    public let evaluatedAtISO: String
}

// MARK: - Core On-Device CLI Spoof & VoIP Defense Engine

public final class CLISpoofEngine {

    public init() {}

    /// Normalizes a phone string into a strictly positive Int64 E.164 format required by iOS CallKit (CXCallDirectoryPhoneNumber).
    public static func normalizeToE164Int64(_ rawNumber: String) -> Int64? {
        let digits = rawNumber.filter { $0.isNumber }
        guard !digits.isEmpty else { return nil }
        if digits.count == 10 {
            return Int64("1" + digits)
        }
        return Int64(digits)
    }

    /// Evaluates an incoming call across all 5 defense layers and returns a deterministic CallKit/LiveLookup verdict.
    public func evaluateCall(
        rawNumber: String,
        attestation: STIRSHAKENAttestation,
        lineType: CarrierLineType,
        carrierName: String,
        sipContext: SIPHeaderContext? = nil,
        policy: DefensePolicyConfig,
        protectedEntities: [ProtectedEntity],
        trustedContacts: Set<Int64>
    ) -> CallScreeningVerdict {
        let callerE164 = Self.normalizeToE164Int64(rawNumber) ?? 0
        var score = 0
        var signals: [SpoofRiskSignal] = []
        var effectiveAttestation = attestation

        // -----------------------------------------------------------------
        // LAYER 1: Protected Entity / Bank / VIP De-Aliasing Vault
        // -----------------------------------------------------------------
        if let entity = protectedEntities.first(where: { $0.e164Number == callerE164 }) {
            if !entity.inboundAllowed && policy.protectOutboundOnlyInstitutions {
                if effectiveAttestation != .fullA {
                    score += 75
                    signals.append(SpoofRiskSignal(
                        layer: "Layer 1: Protected Vault",
                        code: "IMPERSONATION_OUTBOUND_ONLY_ENTITY",
                        scoreDelta: 75,
                        explanation: "Caller ID matches \(entity.name) (\(entity.category)), which is an outbound-only helpline and lacks Level-A cryptographic attestation."
                    ))
                } else {
                    score += 35
                    signals.append(SpoofRiskSignal(
                        layer: "Layer 1: Protected Vault",
                        code: "PROTECTED_ENTITY_CAUTION",
                        scoreDelta: 35,
                        explanation: "Caller ID matches \(entity.name). Verify in official app before sharing OTPs."
                    ))
                }
            }
        }

        // -----------------------------------------------------------------
        // LAYER 2: On-Device Heuristics (Neighbor Spoofing & E.164 Anomalies)
        // -----------------------------------------------------------------
        if !trustedContacts.contains(callerE164) {
            if Self.isNeighborSpoof(callerE164: callerE164, userOwnE164: policy.userOwnNumberE164) {
                let delta = policy.enableNeighborSpoofShield ? 45 : 25
                score += delta
                signals.append(SpoofRiskSignal(
                    layer: "Layer 2: On-Device Heuristics",
                    code: "NEIGHBOR_SPOOF_NPA_NXX",
                    scoreDelta: delta,
                    explanation: "Caller shares your exact Area Code & Central Office Exchange (NPA-NXX) but is not in your Trusted Contacts."
                ))
            }

            if Self.hasInvalidOrHighRiskNANPFormat(callerE164) {
                score += 50
                signals.append(SpoofRiskSignal(
                    layer: "Layer 2: On-Device Heuristics",
                    code: "INVALID_OR_UNALLOCATED_EXCHANGE",
                    scoreDelta: 50,
                    explanation: "Caller ID uses an unassignable NANP exchange (e.g., 555-01XX, N11, or invalid leading digit) proving synthetic CLI generation."
                ))
            }
        } else {
            signals.append(SpoofRiskSignal(
                layer: "Layer 2: On-Device Heuristics",
                code: "TRUSTED_CONTACT_MATCH",
                scoreDelta: -20,
                explanation: "Number exists in verified device contacts."
            ))
            score -= 20
        }

        // -----------------------------------------------------------------
        // LAYER 3: STIR/SHAKEN PASSporT & SIP Header Inspection
        // -----------------------------------------------------------------
        if let sip = sipContext {
            if sip.verstat == "TN-Validation-Failed" {
                effectiveAttestation = .failed
            }
            if let fromURI = sip.fromURI, let pai = sip.pAssertedIdentity {
                let fromNorm = Self.normalizeToE164Int64(fromURI)
                let paiNorm = Self.normalizeToE164Int64(pai)
                if let f = fromNorm, let p = paiNorm, f != p {
                    score += 80
                    signals.append(SpoofRiskSignal(
                        layer: "Layer 3: SIP & PASSporT",
                        code: "SIP_FROM_PAI_MISMATCH",
                        scoreDelta: 80,
                        explanation: "SIP 'From' display CLI (+\(f)) contradicts network-asserted 'P-Asserted-Identity' (+\(p)). Active CLI spoofing confirmed."
                    ))
                }
            }
            if let jwt = sip.passportJWT, !jwt.isEmpty {
                let passportResult = Self.inspectPASSporT(jwt: jwt, expectedCallerE164: callerE164)
                if !passportResult.valid {
                    score += passportResult.penalty
                    signals.append(SpoofRiskSignal(
                        layer: "Layer 3: SIP & PASSporT",
                        code: passportResult.code,
                        scoreDelta: passportResult.penalty,
                        explanation: passportResult.reason
                    ))
                } else if let parsedAttest = passportResult.attestation {
                    effectiveAttestation = parsedAttest
                }
            }
        }

        switch effectiveAttestation {
        case .fullA:
            score -= 25
            signals.append(SpoofRiskSignal(
                layer: "Layer 3: STIR/SHAKEN",
                code: "ATTESTATION_A_FULL",
                scoreDelta: -25,
                explanation: "Full STIR/SHAKEN Attestation (Level A): Originating carrier cryptographically verified caller's right to use this CLI."
            ))
        case .partialB:
            score += 15
            signals.append(SpoofRiskSignal(
                layer: "Layer 3: STIR/SHAKEN",
                code: "ATTESTATION_B_PARTIAL",
                scoreDelta: 15,
                explanation: "Partial Attestation (Level B): Carrier authenticated trunk origin but NOT specific telephone number ownership."
            ))
        case .gatewayC:
            score += 35
            signals.append(SpoofRiskSignal(
                layer: "Layer 3: STIR/SHAKEN",
                code: "ATTESTATION_C_GATEWAY",
                scoreDelta: 35,
                explanation: "Gateway Attestation (Level C): Call entered via international or legacy TDM gateway without CLI verification."
            ))
        case .notVerified:
            score += 30
            signals.append(SpoofRiskSignal(
                layer: "Layer 3: STIR/SHAKEN",
                code: "VERSTAT_NOT_VERIFIED",
                scoreDelta: 30,
                explanation: "No STIR/SHAKEN signature present (verstat=No-TN-Validation)."
            ))
        case .failed:
            let delta = policy.blockFailedStirShaken ? 90 : 65
            score += delta
            signals.append(SpoofRiskSignal(
                layer: "Layer 3: STIR/SHAKEN",
                code: "VERSTAT_VALIDATION_FAILED",
                scoreDelta: delta,
                explanation: "STIR/SHAKEN cryptographic signature failed validation (TN-Validation-Failed)."
            ))
        }

        // -----------------------------------------------------------------
        // LAYER 4: Carrier Line-Type Intelligence (Disable Rogue VoIP)
        // -----------------------------------------------------------------
        switch lineType {
        case .nonFixedVoip:
            let delta = policy.blockNonFixedVoip ? 55 : 35
            score += delta
            signals.append(SpoofRiskSignal(
                layer: "Layer 4: Carrier Intelligence",
                code: "LINE_TYPE_NON_FIXED_VOIP",
                scoreDelta: delta,
                explanation: "Originating number is classified as Non-Fixed (Virtual/Burner) VoIP via \(carrierName)."
            ))
        case .fixedVoip:
            score += 10
            signals.append(SpoofRiskSignal(
                layer: "Layer 4: Carrier Intelligence",
                code: "LINE_TYPE_FIXED_VOIP",
                scoreDelta: 10,
                explanation: "Originating number is Fixed Enterprise/Residential VoIP (\(carrierName))."
            ))
        case .tollFree:
            if effectiveAttestation != .fullA {
                score += 25
                signals.append(SpoofRiskSignal(
                    layer: "Layer 4: Carrier Intelligence",
                    code: "UNVERIFIED_TOLL_FREE_ORIGIN",
                    scoreDelta: 25,
                    explanation: "Inbound Toll-Free CLI without Full (Level A) Attestation—commonly spoofed by outbound call centers."
                ))
            }
        case .mobile, .landline:
            signals.append(SpoofRiskSignal(
                layer: "Layer 4: Carrier Intelligence",
                code: "LINE_TYPE_PHYSICAL_PSTN",
                scoreDelta: 0,
                explanation: "Line type is physical \(lineType.rawValue) (\(carrierName))."
            ))
        case .unknown:
            score += 10
        }

        // -----------------------------------------------------------------
        // LAYER 5: Final Score Clamping & CallKit Enforcement Decision
        // -----------------------------------------------------------------
        let clampedScore = max(0, min(100, score))
        let action: CallDefenseAction
        let label: String

        if clampedScore >= 70 {
            action = .block
            if let entity = protectedEntities.first(where: { $0.e164Number == callerE164 }) {
                label = "🛑 BLOCKED: Spoofed \(entity.name) CLI"
            } else if lineType == .nonFixedVoip {
                label = "🛑 BLOCKED: Unverified Non-Fixed VoIP"
            } else {
                label = "🛑 BLOCKED: High-Risk CLI Spoof (\(clampedScore)/100)"
            }
        } else if clampedScore >= 35 {
            action = .warnLabel
            if let entity = protectedEntities.first(where: { $0.e164Number == callerE164 }) {
                label = "⚠️ [NEVER CALLS INBOUND] \(entity.name)"
            } else if Self.isNeighborSpoof(callerE164: callerE164, userOwnE164: policy.userOwnNumberE164) {
                label = "⚠️ [NEIGHBOR SPOOF RISK] Unverified Caller"
            } else if lineType == .nonFixedVoip {
                label = "⚠️ [VOIP SPOOF RISK] \(carrierName)"
            } else {
                label = "⚠️ [UNVERIFIED CLI] Risk \(clampedScore)/100"
            }
        } else {
            action = .allow
            label = "✅ Verified Caller (\(carrierName))"
        }

        let formatter = ISO8601DateFormatter()
        return CallScreeningVerdict(
            callerE164: callerE164,
            riskScore: clampedScore,
            action: action,
            callKitLabel: label,
            attestation: effectiveAttestation,
            lineType: lineType,
            carrierName: carrierName,
            signals: signals,
            evaluatedAtISO: formatter.string(from: Date())
        )
    }

    // MARK: - Helper Detectors

    /// Detects if the incoming number shares the exact Country Code + Area Code + Exchange Prefix (first 7 digits in NANP) as the user's own SIM number.
    public static func isNeighborSpoof(callerE164: Int64, userOwnE164: Int64) -> Bool {
        guard callerE164 != userOwnE164 else { return true } // Calling yourself is a classic spoof trick!
        let callerStr = String(callerE164)
        let ownStr = String(userOwnE164)
        guard callerStr.count >= 10 && ownStr.count >= 10 else { return false }
        let prefixLen = callerStr.hasPrefix("1") ? 7 : 6
        return callerStr.prefix(prefixLen) == ownStr.prefix(prefixLen)
    }

    /// Generates all 10,000 E.164 numbers in the user's own NPA-NXX exchange (excluding saved contacts)
    /// so iOS CallKit can deterministically label or block neighbor-spoofed calls offline!
    public static func generateNeighborSpoofSet(deviceE164: Int64, excludingContacts contacts: Set<Int64>) -> [Int64] {
        let ownStr = String(deviceE164)
        guard ownStr.count == 11, ownStr.hasPrefix("1") else { return [] }
        let npaNxxPrefix = String(ownStr.prefix(7)) // e.g. "1415555"
        guard let base = Int64(npaNxxPrefix) else { return [] }

        var results: [Int64] = []
        results.reserveCapacity(10_000)
        let start = base * 10_000
        for suffix in 0..<10_000 {
            let candidate = start + Int64(suffix)
            if !contacts.contains(candidate) {
                results.append(candidate)
            }
        }
        return results // Already in strictly ascending order for CXCallDirectoryProvider!
    }

    /// Checks for invalid NANP structures or reserved fictitious blocks often used by sloppy SIP spoofers.
    public static func hasInvalidOrHighRiskNANPFormat(_ e164: Int64) -> Bool {
        let s = String(e164)
        guard s.count == 11 && s.hasPrefix("1") else { return false }
        let npa = String(s.dropFirst(1).prefix(3))
        let nxx = String(s.dropFirst(4).prefix(3))
        let xxxx = String(s.suffix(4))

        // Area code or exchange cannot start with 0 or 1 in NANP
        if npa.hasPrefix("0") || npa.hasPrefix("1") || nxx.hasPrefix("0") || nxx.hasPrefix("1") {
            return true
        }
        // 555-0100 through 555-0199 are reserved for fictional use
        if nxx == "555", let suffixInt = Int(xxxx), (100...199).contains(suffixInt) {
            return true
        }
        return false
    }

    /// Inspects an RFC 8225 STIR/SHAKEN PASSporT compact JWT string.
    public static func inspectPASSporT(jwt: String, expectedCallerE164: Int64) -> (valid: Bool, attestation: STIRSHAKENAttestation?, penalty: Int, code: String, reason: String) {
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2 else {
            return (false, .failed, 75, "MALFORMED_PASSPORT_JWT", "STIR/SHAKEN Identity header contains a malformed PASSporT token.")
        }

        guard let payloadData = decodeBase64URL(String(parts[1])),
              let json = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            return (false, .failed, 75, "UNREADABLE_PASSPORT_PAYLOAD", "Failed to decode PASSporT payload claims.")
        }

        // Verify originating TN matches displayed CLI
        if let orig = json["orig"] as? [String: Any],
           let origTN = orig["tn"] as? String,
           let origE164 = normalizeToE164Int64(origTN),
           origE164 != expectedCallerE164 {
            return (false, .failed, 90, "PASSPORT_ORIG_TN_MISMATCH", "PASSporT signed orig.tn (+\(origE164)) does not match displayed Caller ID (+\(expectedCallerE164)).")
        }

        // Verify token freshness (RFC 8224 recommends max 60s window to prevent replay attacks)
        if let iat = json["iat"] as? TimeInterval {
            let age = abs(Date().timeIntervalSince1970 - iat)
            if age > 120 {
                return (false, .failed, 70, "PASSPORT_TOKEN_REPLAY_EXPIRED", "STIR/SHAKEN PASSporT iat timestamp expired (\(Int(age))s old > 120s replay limit).")
            }
        }

        let attestStr = (json["attest"] as? String) ?? "C"
        let parsedAttest = STIRSHAKENAttestation(rawValue: attestStr) ?? .gatewayC
        return (true, parsedAttest, 0, "PASSPORT_VALID", "PASSporT token structure verified.")
    }

    private static func decodeBase64URL(_ input: String) -> Data? {
        var base64 = input
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: base64)
    }
}
