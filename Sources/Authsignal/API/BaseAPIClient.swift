import Foundation

class BaseAPIClient {
  let baseURL: String
  let clientID: String

  var basicAuth: String {
    return "Basic \(Data( "\(clientID):".utf8).base64URLEncodedString())"
  }

  public init(clientID: String, baseURL: String) {
    self.clientID = clientID
    self.baseURL = baseURL
  }

  func getRequest<T: Decodable>(url: String) async -> T? {
    var request = URLRequest(url: URL(string: url)!)

    request.httpMethod = "GET"
    request.setValue(basicAuth, forHTTPHeaderField: "Authorization")

    return await performRequest(request: request)
  }

  func postRequest<TBody: Encodable, TRes: Decodable>(url: String, body: TBody, auth: String? = nil)
    async -> TRes?
  {
    var request = URLRequest(url: URL(string: url)!)

    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue(auth ?? basicAuth, forHTTPHeaderField: "Authorization")

    let encoder = JSONEncoder()

    guard let httpBody = try? encoder.encode(body) else {
      return nil
    }

    request.httpBody = httpBody

    return await performRequest(request: request)
  }

  private func performRequest<T: Decodable>(request: URLRequest) async -> T? {
    do {
      let (data, response) = try await URLSession.shared.data(for: request)

      let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]

      if let httpResponse = response as? HTTPURLResponse,
        httpResponse.statusCode != 200
      {
        if let error = json?["error"] as? String {
          Logger.error("Error: \(error)")
        }

        if let errorMessage = json?["message"] as? String {
          Logger.error("Error description: \(errorMessage)")
        }

        return nil
      }

      let decoder = JSONDecoder()

      return try? decoder.decode(T.self, from: data)
    } catch {
      Logger.error("Request error: \(error).")

      return nil
    }
  }
}
