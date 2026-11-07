import Foundation

public struct CarrierLookupResult: Codable {
    public let e164: Int64
    public let lineType: CarrierLineType
    public let carrierName: String
    public let countryCode: String
    public let source: String // "twilio_v2", "numverify", or "offline_heuristic_db"
}

public struct LookupCredentials: Codable {
    public var provider: String // "offline", "twilio", "numverify"
    public var twilioAccountSid: String
    public var twilioAuthToken: String
    public var numverifyApiKey: String
    public var pirServerURL: String

    public init(
        provider: String = "offline",
        twilioAccountSid: String = "",
        twilioAuthToken: String = "",
        numverifyApiKey: String = "",
        pirServerURL: String = "http://localhost:4150/api/pir-lookup"
    ) {
        self.provider = provider
        self.twilioAccountSid = twilioAccountSid
        self.twilioAuthToken = twilioAuthToken
        self.numverifyApiKey = numverifyApiKey
        self.pirServerURL = pirServerURL
    }
}

/// Carrier Line-Type Intelligence Service with Live Cloud Lookup + Zero-Auth Local Offline Fallback.
public final class CarrierLookupService {

    public init() {}

    public func lookupNumber(e164: Int64, credentials: LookupCredentials) async -> CarrierLookupResult {
        if credentials.provider == "twilio",
           !credentials.twilioAccountSid.isEmpty,
           !credentials.twilioAuthToken.isEmpty {
            if let live = try? await queryTwilioLookupV2(e164: e164, sid: credentials.twilioAccountSid, token: credentials.twilioAuthToken) {
                return live
            }
        } else if credentials.provider == "numverify",
                  !credentials.numverifyApiKey.isEmpty {
            if let live = try? await queryNumverify(e164: e164, apiKey: credentials.numverifyApiKey) {
                return live
            }
        }

        // Always provide a fast, deterministic Local Offline Fallback
        return Self.offlineFallbackLookup(e164: e164)
    }

    private func queryTwilioLookupV2(e164: Int64, sid: String, token: String) async throws -> CarrierLookupResult {
        let urlStr = "https://lookups.twilio.com/v2/PhoneNumbers/+\(e164)?Fields=line_type_intelligence"
        guard let url = URL(string: urlStr) else { throw URLError(.badURL) }

        var request = URLRequest(url: url, timeoutInterval: 3.5)
        let authStr = "\(sid):\(token)"
        if let authData = authStr.data(using: .utf8) {
            request.setValue("Basic \(authData.base64EncodedString())", forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw URLError(.badServerResponse)
        }

        let country = (json["country_code"] as? String) ?? "US"
        let lti = (json["line_type_intelligence"] as? [String: Any]) ?? [:]
        let rawType = (lti["type"] as? String) ?? "unknown"
        let carrier = (lti["carrier_name"] as? String) ?? "Unknown Carrier"

        let mappedType: CarrierLineType
        switch rawType {
        case "nonFixedVoip": mappedType = .nonFixedVoip
        case "fixedVoip": mappedType = .fixedVoip
        case "mobile": mappedType = .mobile
        case "landline": mappedType = .landline
        case "tollFree": mappedType = .tollFree
        default: mappedType = .unknown
        }

        return CarrierLookupResult(e164: e164, lineType: mappedType, carrierName: carrier, countryCode: country, source: "twilio_v2")
    }

    private func queryNumverify(e164: Int64, apiKey: String) async throws -> CarrierLookupResult {
        let urlStr = "http://apilayer.net/api/validate?access_key=\(apiKey)&number=\(e164)"
        guard let url = URL(string: urlStr) else { throw URLError(.badURL) }

        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw URLError(.badServerResponse)
        }

        let country = (json["country_code"] as? String) ?? "US"
        let carrier = (json["carrier"] as? String) ?? "Unknown Carrier"
        let rawLineType = (json["line_type"] as? String) ?? "unknown"

        let mappedType: CarrierLineType
        if rawLineType == "voip" {
            // Heuristic: Wholesale CLECs like Bandwidth, Peerless, Onvoy/Sinch, TextNow are typically Non-Fixed VoIP
            let lower = carrier.lowercased()
            if lower.contains("bandwidth") || lower.contains("onvoy") || lower.contains("sinch") || lower.contains("peerless") || lower.contains("twilio") {
                mappedType = .nonFixedVoip
            } else {
                mappedType = .fixedVoip
            }
        } else if rawLineType == "mobile" {
            mappedType = .mobile
        } else if rawLineType == "landline" {
            mappedType = .landline
        } else if rawLineType == "toll_free" {
            mappedType = .tollFree
        } else {
            mappedType = .unknown
        }

        return CarrierLookupResult(e164: e164, lineType: mappedType, carrierName: carrier, countryCode: country, source: "numverify")
    }

    /// Built-in Zero-Dependency Offline Carrier & VoIP Prefix Classifier
    public static func offlineFallbackLookup(e164: Int64) -> CarrierLookupResult {
        let s = String(e164)
        let tollFreePrefixes = ["1800", "1888", "1877", "1866", "1855", "1844", "1833"]
        if tollFreePrefixes.contains(where: { s.hasPrefix($0) }) {
            return CarrierLookupResult(
                e164: e164,
                lineType: .tollFree,
                carrierName: "NANP Toll-Free RespOrg",
                countryCode: "US",
                source: "offline_heuristic_db"
            )
        }

        // Known Non-Fixed / Wholesale VoIP OCN prefixes used for simulation & offline detection
        let nonFixedVoipPrefixes = ["1302555", "1415890", "1650999", "1702888", "1917440", "4470"]
        if nonFixedVoipPrefixes.contains(where: { s.hasPrefix($0) }) {
            return CarrierLookupResult(
                e164: e164,
                lineType: .nonFixedVoip,
                carrierName: "Wholesale SIP / Non-Fixed VoIP CLEC",
                countryCode: s.hasPrefix("44") ? "GB" : "US",
                source: "offline_heuristic_db"
            )
        }

        if s.hasPrefix("1212") || s.hasPrefix("1415555") {
            return CarrierLookupResult(
                e164: e164,
                lineType: .mobile,
                carrierName: "Tier-1 Mobile Network Operator (MNO)",
                countryCode: "US",
                source: "offline_heuristic_db"
            )
        }

        return CarrierLookupResult(
            e164: e164,
            lineType: .mobile,
            carrierName: "Domestic Wireless / LEC",
            countryCode: "US",
            source: "offline_heuristic_db"
        )
    }
}
