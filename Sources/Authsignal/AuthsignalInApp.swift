import Foundation
import Security
import UIKit
import DeviceCheck
import CryptoKit

public class AuthsignalInApp {
  private let api: InAppAPIClient
  private let cache = TokenCache.shared
  private let keyManager = KeyManager(keySuffix: "in_app")
  private let pinManager = PinManager()
  private let tenantID: String

  public init(tenantID: String, baseURL: String) {
    self.tenantID = tenantID
    api = InAppAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func getCredential(username: String? = nil) async -> AuthsignalResponse<AppCredential> {
    guard let publicKey = keyManager.getPublicKey(username: username) else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.credentialNotFound)
    }

    let response = await api.getCredential(publicKey: publicKey)

    if let error = response.error {
      return AuthsignalResponse(error: error, errorCode: response.errorCode)
    }
    
    guard let data = response.data else {
      return AuthsignalResponse(error: nil)
    }

    let credential = AppCredential(
      credentialId: data.userAuthenticatorId,
      createdAt: data.verifiedAt,
      userId: data.userId,
      lastAuthenticatedAt: data.lastVerifiedAt
    )

    return AuthsignalResponse(data: credential)
  }

  public func addCredential(
    token: String? = nil,
    keychainAccess: KeychainAccess = .whenUnlockedThisDeviceOnly,
    userPresenceRequired: Bool = false,
    username: String? = nil,
    performAttestation: Bool = false
  ) async -> AuthsignalResponse<AppCredential> {
    guard let userToken = token ?? cache.token else { return cache.handleTokenNotSetError() }

    guard let publicKey = keyManager.getOrCreatePublicKey(
      keychainAccess: keychainAccess,
      userPresenceRequired: userPresenceRequired,
      username: username
    ) else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.createKeyPairFailed)
    }

    var resolvedIntegrity: DeviceIntegrity? = nil
    if performAttestation {
      if #available(iOS 14.0, *), DCAppAttestService.shared.isSupported {
        do {
          guard let idempotencyKey = Self.extractIdempotencyKey(from: userToken) else {
            return AuthsignalResponse(error: "Failed to extract idempotencyKey from token", errorCode: "invalid_token")
          }

          let nonce = idempotencyKey
          let nonceData = Data(nonce.utf8)
          let nonceHash = Data(SHA256.hash(data: nonceData))

          let keyId = try await DCAppAttestService.shared.generateKey()
          let integrityData = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: nonceHash)
          let integrityToken = integrityData.base64EncodedString()

          resolvedIntegrity = DeviceIntegrity(integrityToken: integrityToken, keyId: keyId)
        } catch {
          Logger.error("App Attest failed: \(error.localizedDescription)")
        }
      }
    }

    let deviceName = await UIDevice.current.name

    let response = await api.addCredential(
      token: userToken,
      publicKey: publicKey,
      deviceName: deviceName,
      performAttestation: resolvedIntegrity
    )

    guard let data = response.data else {
      return AuthsignalResponse(error: response.error, errorCode: response.errorCode)
    }

    let credential = AppCredential(
      credentialId: data.userAuthenticatorId,
      createdAt: data.verifiedAt,
      userId: data.userId,
      lastAuthenticatedAt: data.verifiedAt
    )

    return AuthsignalResponse(data: credential)
  }

  public func removeCredential(username: String? = nil) async -> AuthsignalResponse<Bool> {
    let secKey = keyManager.getKey(username: username)
    let publicKey = keyManager.getPublicKey(username: username)

    guard let secKey = secKey, let publicKey = publicKey else {
      return AuthsignalResponse(data: false)
    }

    let signatureResponse = Signature.signWithTimeBasedMessage(privateKey: secKey)
    
    guard let signature = signatureResponse.data else {
      return AuthsignalResponse(error: signatureResponse.error)
    }

    let response = await api.removeCredential(publicKey: publicKey, signature: signature)

    return AuthsignalResponse(
      data: keyManager.deleteKeyPair(username: username),
      error: response.error,
      errorCode: response.errorCode
    )
  }
  
  public func verify(action: String? = nil, username: String? = nil) async -> AuthsignalResponse<InAppVerifyResponse> {
    let challengeResponse = await api.challenge(action: action)
    
    guard let challengeId = challengeResponse.data?.challengeId else {
      return AuthsignalResponse(error: challengeResponse.error ?? "Error generating challenge.")
    }
    
    let secKey = keyManager.getKey(username: username)
    let publicKey = keyManager.getPublicKey(username: username)

    guard let secKey = secKey, let publicKey = publicKey else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.credentialNotFound)
    }
    
    let signatureResponse = Signature.sign(message: challengeId, privateKey: secKey)
    
    guard let signature = signatureResponse.data else {
      return AuthsignalResponse(error: signatureResponse.error)
    }
    
    // Only set a user token if an action is not provided
    let userToken = action == nil ? cache.token : nil

    let response = await api.verify(
      challengeId: challengeId,
      publicKey: publicKey,
      signature: signature,
      token: userToken
    )
    
    if let error = response.error {
      return AuthsignalResponse(
        error: error,
        errorCode: response.errorCode
      )
    } else {
      return AuthsignalResponse(data: response.data!)
    }
  }
  
  public func createPin(pin: String, username: String, token: String? = nil) async -> AuthsignalResponse<AppCredential> {
    guard pinManager.validateFormat(pin: pin) else {
      return AuthsignalResponse(
        error: "Invalid PIN format.",
        errorCode: SdkErrorCodes.invalidPinFormat
      )
    }
    
    pinManager.createPin(pin: pin, username: username)
    
    return await addCredential(token: token, username: username)
  }
  
  public func verifyPin(pin: String, username: String, action: String? = nil) async -> AuthsignalResponse<VerifyPinResponse> {
    let isPinValid = pinManager.validatePin(pin: pin, username: username)
    
    if (isPinValid) {
      let verifyResponse = await verify(action: action, username: username)
      
      if let error = verifyResponse.error {
        return AuthsignalResponse(
          error: error,
          errorCode: verifyResponse.errorCode
        )
      }
      
      if let verifyResponseData = verifyResponse.data {
        let data = VerifyPinResponse(
          isVerified: true,
          token: verifyResponseData.token,
          userId: verifyResponseData.userId
        )
        
        return AuthsignalResponse(data: data)
      }
    }
    
    return AuthsignalResponse(
      data: VerifyPinResponse(isVerified: false)
    )
  }
  
  public func deletePin(username: String) async -> AuthsignalResponse<Bool> {
    let removeCredentialResponse = await removeCredential(username: username)
    
    if removeCredentialResponse.error == nil, removeCredentialResponse.data == true {
      pinManager.deletePin(username: username)
    }
    
    return removeCredentialResponse
  }

  public func getAllPinUsernames() async -> AuthsignalResponse<[String]> {
    let usernames = pinManager.getAllUsernames()

    return AuthsignalResponse(data: usernames)
  }

  private static func extractIdempotencyKey(from token: String) -> String? {
    let parts = token.split(separator: ".")
    guard parts.count >= 2 else { return nil }

    let payload = String(parts[1]).base64URLUnescaped()
    guard let data = Data(base64Encoded: payload) else { return nil }
    guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    guard let other = json["other"] as? [String: Any] else { return nil }

    return other["idempotencyKey"] as? String
  }
}
