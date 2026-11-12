import AuthenticationServices
import XCTest
@testable import Authsignal

final class PasskeyRegistrationErrorTests: XCTestCase {
  func testWebKitInvalidStateErrorIsMatchedExcludedCredential() {
    let error = NSError(domain: "WKErrorDomain", code: 8)

    XCTAssertTrue(PasskeyManager.isMatchedExcludedCredentialError(error))
  }

  func testUnderlyingWebKitInvalidStateErrorIsMatchedExcludedCredential() {
    let underlying = NSError(domain: "WKErrorDomain", code: 8)
    let error = NSError(
      domain: ASAuthorizationError.errorDomain,
      code: ASAuthorizationError.failed.rawValue,
      userInfo: [NSUnderlyingErrorKey: underlying]
    )

    XCTAssertTrue(PasskeyManager.isMatchedExcludedCredentialError(error))
  }

  @available(iOS 18.0, *)
  func testAuthorizationMatchedExcludedCredentialIsMatchedExcludedCredential() {
    let error = ASAuthorizationError(.matchedExcludedCredential)

    XCTAssertTrue(PasskeyManager.isMatchedExcludedCredentialError(error))
  }

  func testResponseCarriesNativeErrorDomainAndCode() {
    let response = AuthsignalResponse<String>(
      error: "Failed",
      nativeError: NSError(domain: "WKErrorDomain", code: 8)
    )

    XCTAssertEqual(response.nativeErrorDomain, "WKErrorDomain")
    XCTAssertEqual(response.nativeErrorCode, 8)
  }

  func testOtherErrorsAreNotMatchedExcludedCredential() {
    XCTAssertFalse(PasskeyManager.isMatchedExcludedCredentialError(NSError(domain: "WKErrorDomain", code: 9)))
    XCTAssertFalse(PasskeyManager.isMatchedExcludedCredentialError(ASAuthorizationError(.failed)))
  }
}
