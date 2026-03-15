import Testing
@testable import CodexBarCore

@Suite("Claude OAuth legacy fallback policy")
struct ClaudeOAuthCredentialsStoreLegacyFallbackTests {
    @Test
    func interactiveLoad_skipsLegacyFallbackAfterPrimaryCandidateRead() {
        #expect(
            ClaudeOAuthCredentialsStore.shouldAttemptLegacySecurityFrameworkFallback(
                allowKeychainPrompt: true,
                attemptedPrimaryCandidateRead: true) == false)
    }

    @Test
    func interactiveLoad_allowsLegacyFallbackWhenNoPrimaryCandidateWasRead() {
        #expect(
            ClaudeOAuthCredentialsStore.shouldAttemptLegacySecurityFrameworkFallback(
                allowKeychainPrompt: true,
                attemptedPrimaryCandidateRead: false) == true)
    }

    @Test
    func nonInteractiveLoad_keepsLegacyFallbackAvailableAfterPrimaryCandidateRead() {
        #expect(
            ClaudeOAuthCredentialsStore.shouldAttemptLegacySecurityFrameworkFallback(
                allowKeychainPrompt: false,
                attemptedPrimaryCandidateRead: true) == true)
    }
}
