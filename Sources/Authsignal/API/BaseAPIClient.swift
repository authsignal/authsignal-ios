import Foundation

class BaseAPIClient {
  let baseURL: String
  let basicAuth: String

  public init(tenantID: String, baseURL: String) {
    self.baseURL = baseURL
    self.basicAuth = "Basic \(Data( "\(tenantID):".utf8).base64URLEncodedString())"
  }

  func getRequest<T: Decodable>(url: String, token: String? = nil) async -> T? {
    var request = URLRequest(url: URL(string: url)!)

    request.httpMethod = "GET"
    
    if let token = token {
      request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    } else {
      request.setValue(basicAuth, forHTTPHeaderField: "Authorization")
    }
  
    return await performRequest(request: request)
  }

  func postRequest<T: Decodable, TBody: Encodable>(url: String, body: TBody, token: String? = nil)
    async -> T?
  {
    var request = URLRequest(url: URL(string: url)!)

    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    
    if let token = token {
      request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    } else {
      request.setValue(basicAuth, forHTTPHeaderField: "Authorization")
    }

    let encoder = JSONEncoder()

    if let httpBody = try? encoder.encode(body) {
      request.httpBody = httpBody
    }

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
