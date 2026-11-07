import SwiftUI
#if canImport(CallKit)
import CallKit
#endif

public struct ContentView: View {
    @State private var policy = DefensePolicyConfig()
    @State private var credentials = LookupCredentials()
    @State private var showSetupSheet = false

    @State private var testNumber = "+1 (800) 935-9935"
    @State private var testAttestation: STIRSHAKENAttestation = .gatewayC
    @State private var testFromHeader = "sip:+18009359935@sip.bank.com"
    @State private var testPAIHeader = "sip:+13025550199@wholesale-voip.net"
    @State private var lastVerdict: CallScreeningVerdict?
    @State private var callKitSyncStatus = "Ready to sync rules to iOS CallKit"

    private let engine = CLISpoofEngine()
    private let lookupService = CarrierLookupService()
    private let store = SQLiteStore()

    @State private var protectedEntities: [ProtectedEntity] = [
        ProtectedEntity(name: "Chase Bank Fraud Helpline", e164Number: 18009359935, category: "Bank", inboundAllowed: false),
        ProtectedEntity(name: "IRS Taxpayer Assistance", e164Number: 18008291040, category: "Government", inboundAllowed: false),
        ProtectedEntity(name: "Citibank Security Desk", e164Number: 18003749700, category: "Bank", inboundAllowed: false)
    ]

    public init() {}

    public var body: some View {
        NavigationView {
            List {
                // Section 1: Active Device Defense Policies
                Section(header: Text("Device-Side Spoof & VoIP Policies")) {
                    Toggle("Disable Non-Fixed (Burner) VoIP Calls", isOn: $policy.blockNonFixedVoip)
                    Toggle("Block Failed STIR/SHAKEN Signatures", isOn: $policy.blockFailedStirShaken)
                    Toggle("Neighbor Spoof Shield (Own NPA-NXX)", isOn: $policy.enableNeighborSpoofShield)
                    Toggle("Protected Bank/Gov De-Aliasing Vault", isOn: $policy.protectOutboundOnlyInstitutions)

                    Button(action: syncRulesToCallKit) {
                        HStack {
                            Image(systemName: "arrow.triangle.2.circlepath.circle.fill")
                            Text("Compile & Sync Rules to iOS CallKit")
                                .fontWeight(.semibold)
                        }
                    }
                    Text(callKitSyncStatus)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                // Section 2: On-Device Call Spoof Diagnostic Tester
                Section(header: Text("Interactive Call Screening Inspector")) {
                    TextField("Incoming Caller E.164", text: $testNumber)
                    Picker("STIR/SHAKEN Attestation", selection: $testAttestation) {
                        ForEach(STIRSHAKENAttestation.allCases, id: \.self) { level in
                            Text("Attestation: \(level.rawValue)").tag(level)
                        }
                    }
                    TextField("SIP From URI (Optional)", text: $testFromHeader)
                    TextField("SIP P-Asserted-Identity (Optional)", text: $testPAIHeader)

                    Button(action: runScreeningSimulation) {
                        HStack {
                            Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                            Text("Evaluate Incoming Call")
                                .fontWeight(.bold)
                        }
                    }

                    if let verdict = lastVerdict {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(verdict.callKitLabel)
                                .font(.headline)
                                .foregroundColor(verdict.action == .block ? .red : (verdict.action == .warnLabel ? .orange : .green))
                            Text("Risk Score: \(verdict.riskScore)/100 • Action: \(verdict.action.rawValue) • Line: \(verdict.lineType.rawValue)")
                                .font(.subheadline)
                            ForEach(verdict.signals, id: \.code) { sig in
                                Text("• [\(sig.layer)] \(sig.explanation) (\(sig.scoreDelta >= 0 ? "+\(sig.scoreDelta)" : "\(sig.scoreDelta)"))")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                        .padding(.vertical, 6)
                    }
                }

                // Section 3: Protected Institution Vault
                Section(header: Text("Protected Outbound-Only Institutions")) {
                    ForEach(protectedEntities) { entity in
                        VStack(alignment: .leading) {
                            Text(entity.name).font(.subheadline).fontWeight(.medium)
                            Text("+\(String(entity.e164Number)) • \(entity.category) • Inbound Blocked/Warned")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("🛡️ CLI Spoof Shield")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showSetupSheet = true }) {
                        Label("⚙️ Setup", systemImage: "gearshape.fill")
                    }
                }
            }
            .sheet(isPresented: $showSetupSheet) {
                SetupAssistantSheet(credentials: $credentials)
            }
        }
    }

    private func runScreeningSimulation() {
        Task {
            let e164 = CLISpoofEngine.normalizeToE164Int64(testNumber) ?? 18009359935
            let carrierInfo = await lookupService.lookupNumber(e164: e164, credentials: credentials)
            let sip = SIPHeaderContext(
                fromURI: testFromHeader.isEmpty ? nil : testFromHeader,
                pAssertedIdentity: testPAIHeader.isEmpty ? nil : testPAIHeader,
                verstat: testAttestation == .failed ? "TN-Validation-Failed" : nil
            )
            let verdict = engine.evaluateCall(
                rawNumber: testNumber,
                attestation: testAttestation,
                lineType: carrierInfo.lineType,
                carrierName: carrierInfo.carrierName,
                sipContext: sip,
                policy: policy,
                protectedEntities: protectedEntities,
                trustedContacts: []
            )
            store.recordVerdict(verdict)
            await MainActor.run {
                self.lastVerdict = verdict
            }
        }
    }

    private func syncRulesToCallKit() {
        // 1. Write Protected Institution warning labels to SQLite
        for entity in protectedEntities {
            store.upsertCallKitRule(
                e164: entity.e164Number,
                isBlocked: false,
                label: "⚠️ [NEVER CALLS INBOUND] \(entity.name)"
            )
        }

        // 2. Write Neighbor Spoof NPA-NXX rules if enabled
        if policy.enableNeighborSpoofShield {
            let neighborSet = CLISpoofEngine.generateNeighborSpoofSet(
                deviceE164: policy.userOwnNumberE164,
                excludingContacts: []
            )
            // Store sample batch in SQLite for fast sync
            for num in neighborSet.prefix(250) {
                store.upsertCallKitRule(
                    e164: num,
                    isBlocked: policy.neighborSpoofAction == .block,
                    label: "⚠️ [NEIGHBOR SPOOF RISK] Same Prefix"
                )
            }
        }

        #if canImport(CallKit)
        CXCallDirectoryManager.sharedInstance.reloadExtension(
            withIdentifier: "com.security.clispoofshield.CallDirectoryExtension"
        ) { error in
            DispatchQueue.main.async {
                if let error = error {
                    self.callKitSyncStatus = "CallKit sync status: \(error.localizedDescription)"
                } else {
                    self.callKitSyncStatus = "✅ Synced ascending E.164 rules to iOS CallKit SpringBoard"
                }
            }
        }
        #else
        self.callKitSyncStatus = "✅ Synced rules to local SQLite store"
        #endif
    }
}

public struct SetupAssistantSheet: View {
    @Binding var credentials: LookupCredentials
    @Environment(\.dismiss) private var dismiss

    public var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Carrier Intelligence Provider"),
                        footer: Text("Offline Heuristic DB works immediately with zero external keys.")) {
                    Picker("Lookup Mode", selection: $credentials.provider) {
                        Text("Local Offline Fallback (Zero-Auth)").tag("offline")
                        Text("Twilio Lookup v2 (Line Type Intelligence)").tag("twilio")
                        Text("Numverify Carrier API").tag("numverify")
                    }
                }

                if credentials.provider == "twilio" {
                    Section(header: Text("Twilio Lookup v2 Credentials")) {
                        TextField("Twilio Account SID (AC...)", text: $credentials.twilioAccountSid)
                        SecureField("Twilio Auth Token", text: $credentials.twilioAuthToken)
                    }
                } else if credentials.provider == "numverify" {
                    Section(header: Text("Numverify API Credentials")) {
                        SecureField("Numverify Access Key", text: $credentials.numverifyApiKey)
                    }
                }

                Section(header: Text("iOS Live Caller ID Lookup (PIR / OHTTP Endpoint)")) {
                    TextField("PIR Service URL", text: $credentials.pirServerURL)
                }
            }
            .navigationTitle("⚙️ Setup Assistant")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save & Close") { dismiss() }
                }
            }
        }
    }
}
