import AuthenticationServices
import XCTest
@testable import Authsignal

@available(iOS 15.0, *)
final class PasskeyAssertionRequestTests: XCTestCase {
  func testAuthenticationOptionsRestrictRequestToAllowedCredentials() throws {
    let response = try JSONDecoder().decode(
      AuthenticationOptsResponse.self,
      from: Data("""
        {
          "challengeId": "test-challenge",
          "options": {
            "rpId": "example.com",
            "challenge": "AQIDBA",
            "allowCredentials": [
              { "type": "public-key", "id": "-__vAQ" },
              { "type": "public-key", "id": "BQYHCAk" }
            ]
          }
        }
        """.utf8)
    )

    let request = try PasskeyManager.createAssertionRequest(options: response.options)

    XCTAssertEqual(request.relyingPartyIdentifier, "example.com")
    XCTAssertEqual(request.challenge, Data([1, 2, 3, 4]))
    XCTAssertEqual(request.allowedCredentials.map { $0.credentialID }, [
      Data([0xfb, 0xff, 0xef, 0x01]),
      Data([5, 6, 7, 8, 9])
    ])
  }

  func testEmptyAllowListPreservesDiscoverableSignIn() throws {
    let request = try PasskeyManager.createAssertionRequest(options: options(credentialIds: []))

    XCTAssertTrue(request.allowedCredentials.isEmpty)
  }

  func testSingleCredentialSupportsBase64PaddingVariants() throws {
    for (id, expectedBytes) in [
      ("AQID", Data([1, 2, 3])),
      ("AQIDBA==", Data([1, 2, 3, 4]))
    ] {
      let request = try PasskeyManager.createAssertionRequest(options: options(credentialIds: [id]))

      XCTAssertEqual(request.allowedCredentials.map { $0.credentialID }, [expectedBytes])
    }
  }

  func testMalformedCredentialCannotBecomeAnUnrestrictedRequest() {
    XCTAssertThrowsError(
      try PasskeyManager.createAssertionRequest(options: options(credentialIds: ["invalid!"]))
    )
  }

  func testMixedValidAndMalformedCredentialsRejectRequest() {
    XCTAssertThrowsError(
      try PasskeyManager.createAssertionRequest(options: options(credentialIds: ["AQIDBA", "invalid!"]))
    )
  }

  func testEmptyCredentialIdRejectsRequest() {
    XCTAssertThrowsError(
      try PasskeyManager.createAssertionRequest(options: options(credentialIds: [""]))
    )
  }

  func testInvalidChallengeRejectsRequest() {
    let options = AuthenticationOpts(challenge: "invalid!", rpId: "example.com", allowCredentials: [])

    XCTAssertThrowsError(try PasskeyManager.createAssertionRequest(options: options)) { error in
      XCTAssertEqual(error.localizedDescription, "Error encoding challenge.")
    }
  }

  @MainActor
  func testMalformedCredentialsReturnAnErrorInEveryPresentationMode() async {
    let manager = PasskeyManager()

    for autofill in [false, true] {
      for preferImmediatelyAvailableCredentials in [false, true] {
        let response = await manager.auth(
          options: options(credentialIds: ["invalid!"]),
          autofill: autofill,
          preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials
        )

        XCTAssertNil(response.data)
        XCTAssertEqual(response.error, "Error decoding allowed credential ID.")
      }
    }
  }

  @MainActor
  func testInvalidRequestDoesNotLeaveAuthenticationInProgress() async {
    let manager = PasskeyManager()
    _ = await manager.auth(
      options: options(credentialIds: [""]),
      autofill: false,
      preferImmediatelyAvailableCredentials: true
    )

    let response = await manager.auth(
      options: AuthenticationOpts(challenge: "invalid!", rpId: "example.com", allowCredentials: []),
      autofill: false,
      preferImmediatelyAvailableCredentials: true
    )

    XCTAssertEqual(response.error, "Error encoding challenge.")
  }

  private func options(credentialIds: [String]) -> AuthenticationOpts {
    AuthenticationOpts(
      challenge: "AQIDBA",
      rpId: "example.com",
      allowCredentials: credentialIds.map { AuthenticationOptsCredential(id: $0, type: "public-key") }
    )
  }
}
