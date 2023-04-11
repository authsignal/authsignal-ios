import Foundation

class ChallengeAPI {
  private let baseUrl: String

  public init(region: AuthsignalRegion = .us) {
    switch region {
    case .au:
      self.baseUrl = "https://au-challenge.authsignal.com/v1"
    case .eu:
      self.baseUrl = "https://eu-challenge.authsignal.com/v1"
    case .us:
      self.baseUrl = "https://challenge.authsignal.com/v1"
    }
  }

  public init(withBaseUrl baseUrl: String) {
    self.baseUrl = baseUrl
  }

  func addCredential(accessToken: String, publicKey: String) async -> Bool {
    let url = URL(string: "\(baseUrl)/device/add-credential")!
    let body = ["publicKey": publicKey]

    var request = URLRequest(url: url)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
    request.httpMethod = "POST"
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)

    do {
      let (data, _) = try await URLSession.shared.data(for: request)

      let responseJSON = try? JSONSerialization.jsonObject(with: data, options: [])

      if let responseJSON = responseJSON as? [String: Any] {
        if let userAuthenticatorId = responseJSON["userAuthenticatorId"] {
          Logger.info("Credential added for authenticator: \(userAuthenticatorId)")

          return true
        }
      }

      return false
    } catch {
      Logger.error("Error adding credential: \(error).")

      return false
    }
  }

  func removeCredential(publicKey: String, signature: String) async -> Bool {
    let url = URL(string: "\(baseUrl)/device/remove-credential")!
    let body = ["publicKey": publicKey, "signature": signature]

    var request = URLRequest(url: url)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpMethod = "POST"
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)

    do {
      let (data, _) = try await URLSession.shared.data(for: request)

      let responseJSON = try? JSONSerialization.jsonObject(with: data, options: [])

      if let responseJSON = responseJSON as? [String: Any] {
        if let userAuthenticatorId = responseJSON["removedAuthenticatorId"] {
          Logger.info("Credential removed for authenticator: \(userAuthenticatorId)")

          return true
        }
      }

      return false
    } catch {
      Logger.error("Error removing credential: \(error).")

      return false
    }
  }

  public func getChallenge(publicKey: String) async -> String? {
    let url = URL(string: "\(baseUrl)/device/check-challenge")!
    let body = ["publicKey": publicKey]

    var request = URLRequest(url: url)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpMethod = "POST"
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)

    do {
      let (data, _) = try await URLSession.shared.data(for: request)

      let responseJSON = try? JSONSerialization.jsonObject(with: data, options: [])

      if let responseJSON = responseJSON as? [String: Any] {
        if let challengeId = responseJSON["sessionToken"] as? String {
          Logger.info("Challenge found: \(challengeId)")

          return challengeId
        }
      }

      return nil
    } catch {
      Logger.error("Error getting challenge: \(error).")

      return nil
    }
  }

  public func updateChallenge(
    challengeId: String,
    publicKey: String,
    signature: String,
    approved: Bool,
    verificationCode: String?
  ) async {
    let url = URL(string: "\(baseUrl)/device/update-challenge")!

    var body: [String: Any] = [
      "publicKey": publicKey,
      "sessionToken": challengeId,
      "approved": approved,
      "signature": signature,
    ]

    if let verificationCode = verificationCode, !verificationCode.isEmpty {
      body["verificationCode"] = verificationCode
    }

    var request = URLRequest(url: url)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpMethod = "POST"
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)

    do {
      let (_, _) = try await URLSession.shared.data(for: request)
    } catch {
      Logger.error("Error updating challenge: \(error).")
    }
  }
}

@available(iOS, deprecated: 15.0, message: "Use the built-in API instead")
extension URLSession {
  func data(from request: URLRequest) async throws -> (Data, URLResponse) {
    try await withCheckedThrowingContinuation { continuation in
      let task = self.dataTask(
        with: request,
        completionHandler: { data, response, error in
          guard let data = data, let response = response else {
            let error = error ?? URLError(.badServerResponse)
            return continuation.resume(throwing: error)
          }

          continuation.resume(returning: (data, response))
        })

      task.resume()
    }
  }
}

public enum AuthsignalRegion {
  case us
  case eu
  case au
}
