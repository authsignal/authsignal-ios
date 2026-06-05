import XCTest

@testable import Authsignal

/// Unit tests for the credential-ID assembly that feeds the iOS Signal API
/// (reportAllAcceptedPublicKeyCredentials). Mirrors the browser SDK's filtering
/// + de-dup logic.
final class AcceptedCredentialIdsTests: XCTestCase {
  private func passkey(_ credentialId: String) -> Authenticator {
    Authenticator(
      userAuthenticatorId: "ua_\(credentialId)",
      verificationMethod: "PASSKEY",
      webauthnCredential: WebauthnCredential(credentialId: credentialId)
    )
  }

  func testIncludesAllServerPasskeysAndCurrentCredential() {
    let authenticators = [passkey("cred-a"), passkey("cred-b")]

    let result = buildAcceptedCredentialIds(authenticators: authenticators, currentCredentialId: "cred-c")

    XCTAssertEqual(result, ["cred-a", "cred-b", "cred-c"])
  }

  func testDoesNotDuplicateCurrentCredentialWhenAlreadyPresent() {
    let authenticators = [passkey("cred-a"), passkey("cred-b")]

    let result = buildAcceptedCredentialIds(authenticators: authenticators, currentCredentialId: "cred-a")

    XCTAssertEqual(result, ["cred-a", "cred-b"])
  }

  func testIgnoresNonPasskeyAuthenticators() {
    let authenticators = [
      passkey("cred-a"),
      Authenticator(userAuthenticatorId: "ua_sms", verificationMethod: "SMS", webauthnCredential: nil),
      Authenticator(userAuthenticatorId: "ua_totp", verificationMethod: "AUTHENTICATOR_APP", webauthnCredential: nil),
    ]

    let result = buildAcceptedCredentialIds(authenticators: authenticators, currentCredentialId: "cred-a")

    XCTAssertEqual(result, ["cred-a"])
  }

  func testIgnoresPasskeysMissingAWebauthnCredential() {
    let authenticators = [
      passkey("cred-a"),
      Authenticator(userAuthenticatorId: "ua_b", verificationMethod: "PASSKEY", webauthnCredential: nil),
    ]

    let result = buildAcceptedCredentialIds(authenticators: authenticators, currentCredentialId: "cred-b")

    XCTAssertEqual(result, ["cred-a", "cred-b"])
  }

  func testReturnsOnlyCurrentCredentialWhenServerListIsEmpty() {
    let result = buildAcceptedCredentialIds(authenticators: [], currentCredentialId: "cred-a")

    XCTAssertEqual(result, ["cred-a"])
  }
}
