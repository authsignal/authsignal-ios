import Foundation
import Security
import UIKit

public class AuthsignalPush {
  private let api: PushAPIClient

  public init(clientID: String, baseURL: String) {
    api = PushAPIClient(clientID: clientID, baseURL: baseURL)
  }

  public func getCredential() async -> PushCredential? {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      return nil
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      return nil
    }

    let response = await api.getCredential(publicKey: publicKey)

    guard let response = response else {
      return nil
    }

    return PushCredential(
      credentialID: response.userAuthenticatorId,
      createdAt: response.verifiedAt,
      lastAuthenticatedAt: response.lastVerifiedAt
    )
  }

  public func addCredential(accessToken: String) async -> Bool {
    guard let publicKey = KeyManager.getOrCreatePublicKey() else {
      Logger.info("Error adding credential: unable to generate key pair.")

      return false
    }

    let deviceName = await UIDevice.current.name

    let response = await api.addCredential(
      accessToken: accessToken,
      publicKey: publicKey,
      deviceName: deviceName
    )

    let success = response?.userAuthenticatorId != nil

    return success
  }

  public func removeCredential() async -> Bool {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      Logger.error("Error removing credential: no credential found.")

      return false
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      Logger.error("Error removing credential: unable to derive public key.")

      return false
    }

    var signature: String? = nil

    let message = getTimeBasedDataToSign()

    do {
      signature = try Signature.sign(message: message, privateKey: secKey)
    } catch {
      Logger.error("Error generating signature.")

      return false
    }

    let response = await api.removeCredential(publicKey: publicKey, signature: signature!)

    let success = response?.removedAuthenticatorId != nil

    if success {
      return KeyManager.deleteKeyPair()
    }

    return false
  }

  public func getChallenge() async -> String? {
    guard let publicKey = KeyManager.getPublicKey() else {
      Logger.error("Error getting challenge: device not enrolled.")

      return nil
    }

    let challenge = await api.getChallenge(publicKey: publicKey)

    return challenge?.challengeId
  }

  public func updateChallenge(challengeID: String, approved: Bool, verificationCode: String? = nil)
    async
  {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      Logger.error("Error updating challenge: device not enrolled.")

      return
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      Logger.error("Error updating challenge: unable to derive public key.")

      return
    }

    var signature: String? = nil

    do {
      signature = try Signature.sign(message: challengeID, privateKey: secKey)
    } catch {
      Logger.error("Error generating signature. \(error)")

      return
    }

    return await api.updateChallenge(
      challengeID: challengeID,
      publicKey: publicKey,
      signature: signature!,
      approved: approved,
      verificationCode: verificationCode
    )
  }

  private func getTimeBasedDataToSign() -> String {
    let secondsSinceEpoch = Double(Date().timeIntervalSince1970)

    return String(floor(secondsSinceEpoch / (60 * 10)))
  }
}
