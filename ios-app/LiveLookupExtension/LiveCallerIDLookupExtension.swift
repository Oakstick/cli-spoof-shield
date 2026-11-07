import Foundation
#if canImport(IdentityLookup)
import IdentityLookup
#endif

/// iOS Live Caller ID Lookup Extension (`IdentityLookup` framework).
/// Queries the CLI Spoof Shield PIR (Private Information Retrieval) endpoint in real time
/// when an unknown caller rings the device, preserving user privacy via Apple Oblivious HTTP (OHTTP).
public struct CLISpoofLiveCallerIDLookupExtension {

    public static let defaultServiceURL = URL(string: "https://pir.clispoofshield.local/api/pir-lookup")!
    public static let defaultTokenIssuerURL = URL(string: "https://pir.clispoofshield.local/api/pir-token-issuer")!

    /// Retrieves user-configured PIR endpoints from the shared App Group container, falling back to local defaults.
    public static var configuredServiceURL: URL {
        let defaults = UserDefaults(suiteName: SQLiteStore.appGroupIdentifier)
        if let custom = defaults?.string(forKey: "pirServerURL"),
           let url = URL(string: custom) {
            return url
        }
        return defaultServiceURL
    }

    public static var configuredTokenIssuerURL: URL {
        let defaults = UserDefaults(suiteName: SQLiteStore.appGroupIdentifier)
        if let custom = defaults?.string(forKey: "pirTokenIssuerURL"),
           let url = URL(string: custom) {
            return url
        }
        return defaultTokenIssuerURL
    }
}
