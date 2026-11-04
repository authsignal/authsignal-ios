import XCTest
@testable import Authsignal

final class RetryScenarioTests: XCTestCase {
  let baseURL = "https://api.example.test/v1"
  let fastRetries = RetryPolicy(maxRetries: 2, baseDelay: 0.01, maxDelay: 1)

  override func setUp() {
    StubURLProtocol.replies = []
    StubURLProtocol.requestCount = 0
    URLProtocol.registerClass(StubURLProtocol.self)
  }

  override func tearDown() {
    URLProtocol.unregisterClass(StubURLProtocol.self)
  }

  func testPasskeyOptionsAreRetriedAfterAServerError() async {
    StubURLProtocol.replies = [.status(503), .status(200, body: authenticationOptions)]

    let response = await passkeyAPI().authenticationOptions(token: "token")

    XCTAssertEqual(response.data?.challengeId, "challenge-1")
    XCTAssertEqual(StubURLProtocol.requestCount, 2)
  }

  func testPasskeyOptionsAreRetriedAfterAGatewayErrorWithAnHTMLBody() async {
    StubURLProtocol.replies = [
      .status(502, body: "<html>502 Bad Gateway</html>"),
      .status(200, body: authenticationOptions),
    ]

    let response = await passkeyAPI().authenticationOptions(token: "token")

    XCTAssertEqual(response.data?.challengeId, "challenge-1")
    XCTAssertEqual(StubURLProtocol.requestCount, 2)
  }

  func testPasskeyVerifyIsNotRetriedAfterAServerError() async {
    StubURLProtocol.replies = [.status(500, body: #"{"error": "internal_error"}"#)]

    let response = await passkeyAPI().verify(challengeId: "challenge-1", credential: credential)

    XCTAssertNil(response.data)
    XCTAssertEqual(StubURLProtocol.requestCount, 1)
  }

  func testPasskeyVerifyIsNotRetriedAfterATimeout() async {
    StubURLProtocol.replies = [.failure(.timedOut)]

    let response = await passkeyAPI().verify(challengeId: "challenge-1", credential: credential)

    XCTAssertEqual(response.errorCode, "network_error")
    XCTAssertEqual(StubURLProtocol.requestCount, 1)
  }

  func testPasskeyVerifyIsRetriedWhenItNeverReachedTheServer() async {
    StubURLProtocol.replies = [.failure(.cannotConnectToHost), .status(200, body: #"{"isVerified": true}"#)]

    let response = await passkeyAPI().verify(challengeId: "challenge-1", credential: credential)

    XCTAssertEqual(response.data?.isVerified, true)
    XCTAssertEqual(StubURLProtocol.requestCount, 2)
  }

  func testSMSChallengeIsNotRetriedAfterATimeoutSoNoSecondSMSIsSent() async {
    StubURLProtocol.replies = [.failure(.timedOut)]

    let response = await smsAPI().challengeSMS(token: "token")

    XCTAssertEqual(response.errorCode, "network_error")
    XCTAssertEqual(StubURLProtocol.requestCount, 1)
  }

  func testSMSChallengeIsRetriedAfterARateLimitWithAShortRetryAfter() async {
    StubURLProtocol.replies = [
      .status(429, headers: ["Retry-After": "0"]),
      .status(200, body: #"{"challengeId": "challenge-1"}"#),
    ]

    let response = await smsAPI().challengeSMS(token: "token")

    XCTAssertEqual(response.data?.challengeId, "challenge-1")
    XCTAssertEqual(StubURLProtocol.requestCount, 2)
  }

  func testRateLimitWithoutRetryAfterIsNotRetried() async {
    StubURLProtocol.replies = [
      .status(429, body: #"{"error": "too_many_requests", "retryAfterSeconds": 540}"#),
      .status(200, body: #"{"challengeId": "challenge-1"}"#),
    ]

    let response = await smsAPI().challengeSMS(token: "token")

    XCTAssertEqual(response.error, "too_many_requests")
    XCTAssertEqual(StubURLProtocol.requestCount, 1)
  }

  func testRateLimitIsNotRetriedWhenTheServerAsksForALongerWait() async {
    StubURLProtocol.replies = [.status(429, body: #"{"error": "too_many_requests"}"#, headers: ["Retry-After": "60"])]

    let response = await smsAPI().challengeSMS(token: "token")

    XCTAssertEqual(response.error, "too_many_requests")
    XCTAssertEqual(StubURLProtocol.requestCount, 1)
  }

  func testWrongCodeIsNeverRetried() async {
    StubURLProtocol.replies = [.status(400, body: #"{"error": "invalid_code"}"#)]

    let response = await smsAPI().verifySMS(token: "token", code: "000000")

    XCTAssertEqual(response.error, "invalid_code")
    XCTAssertEqual(StubURLProtocol.requestCount, 1)
  }

  func testGivesUpAfterMaxRetries() async {
    StubURLProtocol.replies = [.status(503), .status(503), .status(503), .status(503)]

    let response = await passkeyAPI().authenticationOptions(token: "token")

    XCTAssertNil(response.data)
    XCTAssertEqual(StubURLProtocol.requestCount, 3)
  }

  func testRetriesCanBeTurnedOff() async {
    StubURLProtocol.replies = [.status(503), .status(200, body: authenticationOptions)]

    let api = passkeyAPI()
    api.retryPolicy = RetryPolicy(maxRetries: 0, baseDelay: 0, maxDelay: 0)

    let response = await api.authenticationOptions(token: "token")

    XCTAssertNil(response.data)
    XCTAssertEqual(StubURLProtocol.requestCount, 1)
  }

  private func passkeyAPI() -> PasskeyAPIClient {
    let api = PasskeyAPIClient(tenantID: "tenant", baseURL: baseURL, deviceID: "device")
    api.retryPolicy = fastRetries
    return api
  }

  private func smsAPI() -> SMSAPIClient {
    let api = SMSAPIClient(tenantID: "tenant", baseURL: baseURL)
    api.retryPolicy = fastRetries
    return api
  }

  private let authenticationOptions = """
    {
      "challengeId": "challenge-1",
      "options": { "challenge": "AQID", "rpId": "example.com", "allowCredentials": [] }
    }
    """

  private let credential = PasskeyAuthenticationCredential(
    id: "credential",
    rawId: "credential",
    type: "public-key",
    authenticatorAttachment: "platform",
    response: PasskeyAuthenticationCredentialResponse(
      authenticatorData: "data",
      clientDataJSON: "client-data",
      signature: "signature",
      userHandle: "user"
    )
  )
}

final class StubURLProtocol: URLProtocol {
  enum Reply {
    case status(Int, body: String = "{}", headers: [String: String] = [:])
    case failure(URLError.Code)
  }

  static var replies: [Reply] = []
  static var requestCount = 0

  override class func canInit(with request: URLRequest) -> Bool { true }

  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

  override func startLoading() {
    Self.requestCount += 1

    switch Self.replies.isEmpty ? .failure(.resourceUnavailable) : Self.replies.removeFirst() {
    case .status(let statusCode, let body, let headers):
      let response = HTTPURLResponse(url: request.url!, statusCode: statusCode, httpVersion: nil, headerFields: headers)!
      client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
      client?.urlProtocol(self, didLoad: Data(body.utf8))
      client?.urlProtocolDidFinishLoading(self)
    case .failure(let code):
      client?.urlProtocol(self, didFailWithError: URLError(code))
    }
  }

  override func stopLoading() {}
}
