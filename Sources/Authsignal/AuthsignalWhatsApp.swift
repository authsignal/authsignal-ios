import Foundation
import Security
import UIKit

public class AuthsignalWhatsApp {
  private let api: WhatsAppAPIClient
  private let cache = TokenCache.shared
  
  public init(tenantID: String, baseURL: String) {
    self.api = WhatsAppAPIClient(tenantID: tenantID, baseURL: baseURL)
  }
  
  public func challenge() async -> AuthsignalResponse<ChallengeResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    return await api.challengeWhatsApp(token: token)
  }
  
  public func verify(code: String) async -> AuthsignalResponse<VerifyResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    let verifyResponse = await api.verifyWhatsApp(token: token, code: code)
    
    if let responseToken = verifyResponse.data?.token {
      cache.token = responseToken
    }
    
    return verifyResponse
  }
}
