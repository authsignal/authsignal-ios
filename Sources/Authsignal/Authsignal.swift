import Foundation
import Security

public class Authsignal {
  private let api: ChallengeAPI

  public init(region: AuthsignalRegion = .us) {
    api = ChallengeAPI(region: region)
  }

  public init(withBaseUrl baseUrl: String) {
    api = ChallengeAPI(withBaseUrl: baseUrl)
  }

  public func addCredential(accessToken: String) async -> Bool {
    guard let publicKey = KeyManager.getOrCreatePublicKey() else {
      Logger.info("Error adding credential: unable to generate key pair.")

      return false
    }

    return await api.addCredential(accessToken: accessToken, publicKey: publicKey)
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

    let success = await api.removeCredential(publicKey: publicKey, signature: signature!)

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

    return await api.getChallenge(publicKey: publicKey)
  }

  public func updateChallenge(challengeId: String, approved: Bool, verificationCode: String? = nil)
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
      signature = try Signature.sign(message: challengeId, privateKey: secKey)
    } catch {
      Logger.error("Error generating signature. \(error)")

      return
    }

    return await api.updateChallenge(
      challengeId: challengeId,
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
