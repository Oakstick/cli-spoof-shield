import Foundation
import CallKit

/// Native iOS CallKit Call Directory Extension (`CXCallDirectoryProvider`).
/// Pre-compiles blocked Non-Fixed VoIP ranges, Neighbor Spoofing NPA-NXX shields,
/// and Protected Institution (Bank/Government) De-Aliasing labels into iOS SpringBoard.
public final class CallDirectoryHandler: CXCallDirectoryProvider {

    private let store = SQLiteStore()

    public override func beginRequest(with context: CXCallDirectoryExtensionContext) {
        context.delegate = self

        // If incremental loading is requested after initial setup, remove stale entries first
        if context.isIncremental {
            context.removeAllBlockingEntries()
            context.removeAllIdentificationEntries()
        }

        // 1. Load & Merge Strictly Ascending E.164 Blocked Numbers
        addAllBlockingPhoneNumbers(to: context)

        // 2. Load & Merge Strictly Ascending E.164 Identification Warning Labels
        addAllIdentificationPhoneNumbers(to: context)

        context.completeRequest()
    }

    private func addAllBlockingPhoneNumbers(to context: CXCallDirectoryExtensionContext) {
        let blockedRecords = store.fetchSortedRules(blockedOnly: true)
        var lastAdded: CXCallDirectoryPhoneNumber = 0

        for record in blockedRecords {
            let number = CXCallDirectoryPhoneNumber(record.e164)
            // CXCallDirectoryProvider strictly requires ascending order without duplicates
            if number > lastAdded {
                context.addBlockingEntry(withNextSequentialPhoneNumber: number)
                lastAdded = number
            }
        }
    }

    private func addAllIdentificationPhoneNumbers(to context: CXCallDirectoryExtensionContext) {
        let labeledRecords = store.fetchSortedRules(blockedOnly: false)
        var lastAdded: CXCallDirectoryPhoneNumber = 0

        for record in labeledRecords {
            let number = CXCallDirectoryPhoneNumber(record.e164)
            if number > lastAdded {
                context.addIdentificationEntry(
                    withNextSequentialPhoneNumber: number,
                    label: record.label
                )
                lastAdded = number
            }
        }
    }
}

extension CallDirectoryHandler: CXCallDirectoryExtensionContextDelegate {
    public func requestFailed(for extensionContext: CXCallDirectoryExtensionContext, withError error: Error) {
        NSLog("[CLISpoofShield] CallDirectoryExtension failed: \(error.localizedDescription)")
    }
}
