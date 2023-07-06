import Foundation
import Security
import UIKit

public class AuthsignalPush {
  private let api: PushAPIClient

  public init(tenantID: String, baseURL: String) {
    api = PushAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func getCredential() async -> AuthsignalResponse<PushCredential> {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      return AuthsignalResponse(error: "Key pair not found")
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      return AuthsignalResponse(error: "Error deriving public key")
    }

    let response = await api.getCredential(publicKey: publicKey)

    guard let responseData = response.data else {
      return AuthsignalResponse(error: response.error)
    }

    let credential = PushCredential(
      credentialID: responseData.userAuthenticatorId,
      createdAt: responseData.verifiedAt,
      lastAuthenticatedAt: responseData.lastVerifiedAt
    )
    
    return AuthsignalResponse(data: credential)
  }

  public func addCredential(token: String) async -> AuthsignalResponse<Bool> {
    guard let publicKey = KeyManager.getOrCreatePublicKey() else {
      return AuthsignalResponse(error: "Unable to generate key pair")
    }

    let deviceName = await UIDevice.current.name

    let response = await api.addCredential(
      token: token,
      publicKey: publicKey,
      deviceName: deviceName
    )
    
    guard let responseData = response.data else {
      return AuthsignalResponse(error: response.error)
    }
    
    let success = responseData.userAuthenticatorId != nil

    return AuthsignalResponse(data: success)
  }

  public func removeCredential() async -> AuthsignalResponse<Bool> {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      return AuthsignalResponse(error: "Key pair not found")
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      return AuthsignalResponse(error: "Error deriving public key")
    }

    var signature: String? = nil

    let message = getTimeBasedDataToSign()

    do {
      signature = try Signature.sign(message: message, privateKey: secKey)
    } catch {
      return AuthsignalResponse(error: "Error generating signature. \(error)")
    }

    let response = await api.removeCredential(publicKey: publicKey, signature: signature!)

    guard let responseData = response.data else {
      return AuthsignalResponse(error: response.error)
    }
    
    let success = responseData.removedAuthenticatorId != nil

    if success {
      return AuthsignalResponse(data: KeyManager.deleteKeyPair())
    }

    return AuthsignalResponse(error: "Error removing authenticator")
  }

  public func getChallenge() async -> AuthsignalResponse<String> {
    guard let publicKey = KeyManager.getPublicKey() else {
      return AuthsignalResponse(error: "Key pair not found")
    }

    let response = await api.getChallenge(publicKey: publicKey)

    guard let responseData = response.data else {
      return AuthsignalResponse(error: response.error)
    }
    
    return AuthsignalResponse(data: responseData.challengeId)
  }

  public func updateChallenge(
    challengeID: String,
    approved: Bool,
    verificationCode: String? = nil
  ) async -> AuthsignalResponse<Bool> {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      return AuthsignalResponse(error: "Key pair not found")
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      return AuthsignalResponse(error: "Error deriving public key")
    }

    var signature: String? = nil

    do {
      signature = try Signature.sign(message: challengeID, privateKey: secKey)
    } catch {
      return AuthsignalResponse(error: "Error generating signature. \(error)")
    }

    let response = await api.updateChallenge(
      challengeID: challengeID,
      publicKey: publicKey,
      signature: signature!,
      approved: approved,
      verificationCode: verificationCode
    )
    
    return AuthsignalResponse(data: response.error == nil, error: response.error)
  }

  private func getTimeBasedDataToSign() -> String {
    let secondsSinceEpoch = Double(Date().timeIntervalSince1970)

    return String(floor(secondsSinceEpoch / (60 * 10)))
  }
}
