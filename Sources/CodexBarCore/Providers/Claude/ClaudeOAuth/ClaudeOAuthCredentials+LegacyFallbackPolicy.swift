extension ClaudeOAuthCredentialsStore {
    static var keychainAccessAllowed: Bool {
        #if DEBUG
        if let override = self.taskKeychainAccessOverride { return !override }
        #endif
        return !KeychainAccessGate.isDisabled
    }

    static func shouldAllowClaudeCodeKeychainAccess(
        mode: ClaudeOAuthKeychainPromptMode = ClaudeOAuthKeychainPromptPreference.current()) -> Bool
    {
        guard self.keychainAccessAllowed else { return false }
        switch mode {
        case .never: return false
        case .onlyOnUserAction:
            return ProviderInteractionContext.current == .userInitiated || self.allowBackgroundPromptBootstrap
        case .always: return true
        }
    }

    static func securityFrameworkFallbackPromptDecision(
        promptMode: ClaudeOAuthKeychainPromptMode,
        allowKeychainPrompt: Bool,
        respectKeychainPromptCooldown: Bool) -> (allowed: Bool, blockedReason: String?)
    {
        guard allowKeychainPrompt else {
            return (allowed: false, blockedReason: "allowKeychainPromptFalse")
        }
        guard self.shouldAllowClaudeCodeKeychainAccess(mode: promptMode) else {
            return (allowed: false, blockedReason: self.fallbackBlockedReason(promptMode: promptMode))
        }
        if respectKeychainPromptCooldown,
           !ClaudeOAuthKeychainAccessGate.shouldAllowPrompt()
        {
            return (allowed: false, blockedReason: "cooldown")
        }
        return (allowed: true, blockedReason: nil)
    }

    static func shouldAttemptLegacySecurityFrameworkFallback(
        allowKeychainPrompt: Bool,
        attemptedPrimaryCandidateRead: Bool) -> Bool
    {
        // On user-initiated interactive loads, a direct read of the newest candidate has already triggered the only
        // Keychain dialog we want for that action. Falling through to the legacy service-wide lookup can trigger a
        // second macOS prompt for a different access shape, so suppress it and let the next explicit refresh retry.
        if allowKeychainPrompt, attemptedPrimaryCandidateRead {
            return false
        }
        return true
    }

    private static func fallbackBlockedReason(promptMode: ClaudeOAuthKeychainPromptMode) -> String {
        if !self.keychainAccessAllowed { return "keychainDisabled" }
        switch promptMode {
        case .never:
            return "never"
        case .onlyOnUserAction:
            return "onlyOnUserAction-background"
        case .always:
            return "disallowed"
        }
    }
}
