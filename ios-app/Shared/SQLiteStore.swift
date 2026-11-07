import Foundation
import SQLite3

/// Shared App Group SQLite3 Persistence Layer for Companion App, CallDirectoryExtension, and LiveCallerIDLookup.
/// Uses Apple's built-in libsqlite3 with zero external package dependencies.
public final class SQLiteStore {
    public static let appGroupIdentifier = "group.com.security.clispoofshield"
    private var db: OpaquePointer?
    private let queue = DispatchQueue(label: "com.security.clispoofshield.sqlite", qos: .userInitiated)

    public struct CallKitRuleRecord: Codable {
        public let e164: Int64
        public let isBlocked: Bool
        public let label: String
        public let updatedAt: Int64
    }

    public init(customPath: String? = nil) {
        let dbURL: URL
        if let customPath = customPath {
            dbURL = URL(fileURLWithPath: customPath)
        } else if let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroupIdentifier) {
            dbURL = containerURL.appendingPathComponent("cli_spoof_shield.sqlite3")
        } else {
            let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
            dbURL = docs.appendingPathComponent("cli_spoof_shield.sqlite3")
        }

        if sqlite3_open_v2(dbURL.path, &db, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK {
            // Enable WAL mode for concurrent read access from CallDirectoryExtension
            sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nil, nil, nil)
            createTables()
        }
    }

    deinit {
        if db != nil {
            sqlite3_close(db)
        }
    }

    private func createTables() {
        let schemaSQL = """
        CREATE TABLE IF NOT EXISTS callkit_rules (
            e164 INTEGER PRIMARY KEY ASC,
            is_blocked INTEGER NOT NULL DEFAULT 0,
            label TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS protected_entities (
            e164 INTEGER PRIMARY KEY ASC,
            id TEXT NOT NULL,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            inbound_allowed INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS screening_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caller_e164 INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            action TEXT NOT NULL,
            label TEXT NOT NULL,
            attestation TEXT NOT NULL,
            line_type TEXT NOT NULL,
            carrier_name TEXT NOT NULL,
            evaluated_at TEXT NOT NULL
        );
        """
        sqlite3_exec(db, schemaSQL, nil, nil, nil)
    }

    /// Inserts or updates a CallKit blocking/identification rule.
    public func upsertCallKitRule(e164: Int64, isBlocked: Bool, label: String) {
        queue.sync {
            let sql = """
            INSERT INTO callkit_rules (e164, is_blocked, label, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(e164) DO UPDATE SET
                is_blocked = excluded.is_blocked,
                label = excluded.label,
                updated_at = excluded.updated_at;
            """
            var stmt: OpaquePointer?
            if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
                sqlite3_bind_int64(stmt, 1, e164)
                sqlite3_bind_int(stmt, 2, isBlocked ? 1 : 0)
                sqlite3_bind_text(stmt, 3, (label as NSString).utf8String, -1, nil)
                sqlite3_bind_int64(stmt, 4, Int64(Date().timeIntervalSince1970))
                sqlite3_step(stmt)
            }
            sqlite3_finalize(stmt)
        }
    }

    /// Fetches CallKit rules in strictly ascending E.164 order as mandated by CXCallDirectoryProvider.
    public func fetchSortedRules(blockedOnly: Bool? = nil) -> [CallKitRuleRecord] {
        return queue.sync {
            var sql = "SELECT e164, is_blocked, label, updated_at FROM callkit_rules"
            if let blockedOnly = blockedOnly {
                sql += blockedOnly ? " WHERE is_blocked = 1" : " WHERE is_blocked = 0"
            }
            sql += " ORDER BY e164 ASC;"

            var results: [CallKitRuleRecord] = []
            var stmt: OpaquePointer?
            if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
                while sqlite3_step(stmt) == SQLITE_ROW {
                    let e164 = sqlite3_column_int64(stmt, 0)
                    let isBlocked = sqlite3_column_int(stmt, 1) != 0
                    let labelC = sqlite3_column_text(stmt, 2)
                    let label = labelC != nil ? String(cString: labelC!) : ""
                    let updatedAt = sqlite3_column_int64(stmt, 3)
                    results.append(CallKitRuleRecord(e164: e164, isBlocked: isBlocked, label: label, updatedAt: updatedAt))
                }
            }
            sqlite3_finalize(stmt)
            return results
        }
    }

    /// Logs a call screening verdict for inspection in the Companion App dashboard.
    public func recordVerdict(_ verdict: CallScreeningVerdict) {
        queue.sync {
            let sql = """
            INSERT INTO screening_logs
            (caller_e164, risk_score, action, label, attestation, line_type, carrier_name, evaluated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """
            var stmt: OpaquePointer?
            if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
                sqlite3_bind_int64(stmt, 1, verdict.callerE164)
                sqlite3_bind_int(stmt, 2, Int32(verdict.riskScore))
                sqlite3_bind_text(stmt, 3, (verdict.action.rawValue as NSString).utf8String, -1, nil)
                sqlite3_bind_text(stmt, 4, (verdict.callKitLabel as NSString).utf8String, -1, nil)
                sqlite3_bind_text(stmt, 5, (verdict.attestation.rawValue as NSString).utf8String, -1, nil)
                sqlite3_bind_text(stmt, 6, (verdict.lineType.rawValue as NSString).utf8String, -1, nil)
                sqlite3_bind_text(stmt, 7, (verdict.carrierName as NSString).utf8String, -1, nil)
                sqlite3_bind_text(stmt, 8, (verdict.evaluatedAtISO as NSString).utf8String, -1, nil)
                sqlite3_step(stmt)
            }
            sqlite3_finalize(stmt)
        }
    }
}
