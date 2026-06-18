import AuthenticationServices
import Foundation

class PasskeySignalManager {
  func signalAllAcceptedCredentials(
    rpId: String,
    userHandle: Data,
    credentialIds: [String]
  ) async {
    #if compiler(>=6.2)
    guard #available(iOS 26.0, *) else { return }

    let credentialIdData = credentialIds.compactMap { Data(base64URLEncoded: $0) }

    do {
      try await ASCredentialUpdater().reportAllAcceptedPublicKeyCredentials(
        relyingPartyIdentifier: rpId,
        userHandle: userHandle,
        acceptedCredentialIDs: credentialIdData
      )
    } catch {
      Logger.error("signalAllAcceptedCredentials failed: \(error.localizedDescription)")
    }
    #endif
  }

  func signalUnknownCredential(
    rpId: String,
    credentialId: String
  ) async {
    #if compiler(>=6.2)
    guard #available(iOS 26.0, *) else { return }

    guard let credentialIdData = Data(base64URLEncoded: credentialId) else {
      Logger.error("signalUnknownCredential failed: could not decode credential ID.")

      return
    }

    do {
      try await ASCredentialUpdater().reportUnknownPublicKeyCredential(
        relyingPartyIdentifier: rpId,
        credentialID: credentialIdData
      )
    } catch {
      Logger.error("signalUnknownCredential failed: \(error.localizedDescription)")
    }
    #endif
  }
}
