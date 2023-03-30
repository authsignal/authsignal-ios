import Foundation

class DeviceAPI {
  private let baseUrl: String?

  init() {
    self.baseUrl = Bundle.main.object(forInfoDictionaryKey: "AuthsignalURL") as? String

    if self.baseUrl == nil {
      Logger.info("AuthsignalURL not configured.")
    }
  }

  func addCredential(accessToken: String, publicKey: String) async -> Bool {
    guard let baseUrl = baseUrl else {
      return false
    }

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
    guard let baseUrl = baseUrl else {
      return false
    }

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
    guard let baseUrl = baseUrl else {
      return nil
    }

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
    challengeId: String, publicKey: String, signature: String, approved: Bool
  ) async {
    guard let baseUrl = baseUrl else {
      return
    }

    let url = URL(string: "\(baseUrl)/device/update-challenge")!

    let body: [String: Any] = [
      "publicKey": publicKey,
      "sessionToken": challengeId,
      "approved": approved,
      "signature": signature,
    ]

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
