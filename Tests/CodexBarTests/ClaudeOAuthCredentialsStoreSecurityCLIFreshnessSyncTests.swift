import Foundation
import Testing
@testable import CodexBarCore

@Suite(.serialized)
struct ClaudeOAuthCredentialsStoreSecurityCLIFreshnessSyncTests {
    private func makeCredentialsData(accessToken: String, expiresAt: Date, refreshToken: String? = nil) -> Data {
        let millis = Int(expiresAt.timeIntervalSince1970 * 1000)
        let refreshField: String = {
            guard let refreshToken else { return "" }
            return ",\n            \"refreshToken\": \"\(refreshToken)\""
        }()
        let json = """
        {
          "claudeAiOauth": {
            "accessToken": "\(accessToken)",
            "expiresAt": \(millis),
            "scopes": ["user:profile"]\(refreshField)
          }
        }
        """
        return Data(json.utf8)
    }

    @Test
    func experimentalReader_refreshesCachedClaudeCLIRecordViaSecurityCLIWithoutFingerprintProbe() throws {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        try KeychainCacheStore.withServiceOverrideForTesting(service) {
            try KeychainAccessGate.withTaskOverrideForTesting(false) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                ClaudeOAuthCredentialsStore.invalidateCache()
                ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                ClaudeOAuthCredentialsStore._resetClaudeKeychainChangeTrackingForTesting()
                defer {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                    ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                    ClaudeOAuthCredentialsStore._resetClaudeKeychainChangeTrackingForTesting()
                    ClaudeOAuthCredentialsStore.setClaudeKeychainDataOverrideForTesting(nil)
                    ClaudeOAuthCredentialsStore.setClaudeKeychainFingerprintOverrideForTesting(nil)
                }

                let tempDir = FileManager.default.temporaryDirectory
                    .appendingPathComponent(UUID().uuidString, isDirectory: true)
                try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
                let fileURL = tempDir.appendingPathComponent("credentials.json")

                try ClaudeOAuthCredentialsStore.withCredentialsURLOverrideForTesting(fileURL) {
                    let cachedData = self.makeCredentialsData(
                        accessToken: "cached-token",
                        expiresAt: Date(timeIntervalSinceNow: 3600),
                        refreshToken: "cached-refresh")
                    let updatedData = self.makeCredentialsData(
                        accessToken: "updated-token",
                        expiresAt: Date(timeIntervalSinceNow: 3600),
                        refreshToken: "updated-refresh")
                    let cacheKey = KeychainCacheStore.Key.oauth(provider: .claude)
                    KeychainCacheStore.store(
                        key: cacheKey,
                        entry: ClaudeOAuthCredentialsStore.CacheEntry(
                            data: cachedData,
                            storedAt: Date(),
                            owner: .claudeCLI))

                    final class ReadCounter: @unchecked Sendable {
                        var count = 0
                    }
                    let securityReadCalls = ReadCounter()

                    let creds = try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                        .securityCLIExperimental,
                        operation: {
                            try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                                .onlyOnUserAction,
                                operation: {
                                    try ProviderInteractionContext.$current.withValue(.userInitiated) {
                                        try ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                            .dynamic { _ in
                                                securityReadCalls.count += 1
                                                return updatedData
                                            }) {
                                                try ClaudeOAuthCredentialsStore.load(
                                                    environment: [:],
                                                    allowKeychainPrompt: false)
                                            }
                                    }
                                })
                        })

                    #expect(creds.accessToken == "updated-token")
                    #expect(securityReadCalls.count == 1)
                }
            }
        }
    }
}
