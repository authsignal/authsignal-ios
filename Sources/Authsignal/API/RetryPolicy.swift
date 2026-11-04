import Foundation

/// Decides whether a failed request is sent again, and how long to wait first.
///
/// Sending a request twice is only safe when the second send cannot do something the first did not.
/// So the decision rests on two questions:
/// 1. Could the server have processed the failed attempt? That is the ``Outcome``.
/// 2. Is the endpoint safe to call twice? Each API client marks its replay-safe endpoints.
///
/// | Outcome    | Replay-safe endpoint | Any other endpoint |
/// |------------|----------------------|--------------------|
/// | `notSent`  | retry                | retry              |
/// | `rejected` | retry                | retry              |
/// | `unknown`  | retry                | give up            |
/// | `final`    | give up              | give up            |
struct RetryPolicy {
  /// How many times a request is sent again after the first attempt. 0 turns retries off.
  let maxRetries: Int
  /// The wait before the first retry. It doubles for each retry after that.
  let baseDelay: TimeInterval
  /// The longest wait before a retry. If the server asks for a longer wait, the request is not retried.
  let maxDelay: TimeInterval

  static let `default` = RetryPolicy(maxRetries: 2, baseDelay: 0.5, maxDelay: 5)

  /// What a failed attempt tells us about whether the server processed it.
  enum Outcome: Equatable {
    /// The request never reached the server: no network, no DNS answer, or no connection.
    case notSent
    /// The server answered without processing the request: 408 Request Timeout, or 429 Too Many Requests
    /// with a `Retry-After` header.
    case rejected
    /// The server may or may not have processed the request: a timeout, a dropped connection or a 5xx.
    case unknown
    /// The server gave a definite answer, such as a 4xx. Sending the request again gets the same answer.
    case final
  }

  /// The outcome of an attempt, or `nil` if it succeeded.
  static func outcome(of result: Result<(Data, URLResponse), Error>) -> Outcome? {
    switch result {
    case .success(let (_, response)):
      guard let httpResponse = response as? HTTPURLResponse else { return nil }

      return outcome(
        statusCode: httpResponse.statusCode,
        retryAfter: httpResponse.value(forHTTPHeaderField: "Retry-After")
      )
    case .failure(let error):
      return outcome(error: error)
    }
  }

  static func outcome(statusCode: Int, retryAfter: String? = nil) -> Outcome? {
    switch statusCode {
    case 200..<300:
      return nil
    case 408:
      return .rejected
    // Authsignal's 429s are rate limits that last minutes, so only retry when the server says how long to wait.
    case 429:
      return retryAfter == nil ? .final : .rejected
    case 500, 502, 503, 504:
      return .unknown
    default:
      return .final
    }
  }

  static func outcome(error: Error) -> Outcome {
    guard let code = (error as? URLError)?.code else { return .final }

    switch code {
    case .notConnectedToInternet,
      .cannotFindHost,
      .cannotConnectToHost,
      .dnsLookupFailed,
      .dataNotAllowed,
      .internationalRoamingOff,
      .callIsActive:
      return .notSent
    // Each of these can happen after the request was sent.
    case .timedOut,
      .networkConnectionLost,
      .secureConnectionFailed:
      return .unknown
    default:
      return .final
    }
  }

  func shouldRetry(_ outcome: Outcome, replaySafe: Bool) -> Bool {
    switch outcome {
    case .notSent, .rejected:
      return true
    case .unknown:
      return replaySafe
    case .final:
      return false
    }
  }

  /// The wait before retry number `retry`, counting from 1, or `nil` if the server's `Retry-After`
  /// asks for longer than `maxDelay`.
  func delay(beforeRetry retry: Int, retryAfter: String?) -> TimeInterval? {
    if let retryAfter = retryAfter, let seconds = TimeInterval(retryAfter.trimmingCharacters(in: .whitespaces)) {
      return seconds <= maxDelay ? max(seconds, 0) : nil
    }

    let backoff = min(baseDelay * pow(2, Double(retry - 1)), maxDelay)

    // Jitter spreads out retries from devices that all failed at the same moment.
    return backoff / 2 + .random(in: 0...(backoff / 2))
  }
}
