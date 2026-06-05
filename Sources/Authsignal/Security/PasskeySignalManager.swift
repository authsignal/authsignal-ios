import AuthenticationServices
import Foundation

/// Wraps Apple's relying-party Signal API used to keep the passkeys stored in
/// the system credential manager consistent with the credentials known to the
/// Authsignal server.
///
/// `ASCredentialDataManager` is only available from iOS 26.2, so all calls are
/// gated behind an availability check and fail silently — a missing or throttled
/// Signal API must never break the auth flow. Devices on earlier OS versions
/// simply skip the sync.
class PasskeySignalManager {
  /// Reports the full set of credential IDs the server will accept for the user.
  /// Credentials not present in the list may be removed or hidden by the system
  /// credential manager.
  func signalAllAcceptedCredentials(
    rpId: String,
    userHandle: Data,
    credentialIds: [String]
  ) async {
    guard #available(iOS 26.2, *) else { return }

    let credentialIdData = credentialIds.compactMap { Data(base64URLEncoded: $0) }

    do {
      try await ASCredentialDataManager().reportAllAcceptedPublicKeyCredentials(
        relyingPartyIdentifier: rpId,
        userHandle: userHandle,
        acceptedCredentialIDs: credentialIdData
      )
    } catch {
      Logger.error("signalAllAcceptedCredentials failed: \(error.localizedDescription)")
    }
  }

  /// Reports that a credential is no longer known to the server, so the system
  /// credential manager can remove or hide it.
  func signalUnknownCredential(
    rpId: String,
    credentialId: String
  ) async {
    guard #available(iOS 26.2, *) else { return }

    guard let credentialIdData = Data(base64URLEncoded: credentialId) else {
      Logger.error("signalUnknownCredential failed: could not decode credential ID.")

      return
    }

    do {
      try await ASCredentialDataManager().reportUnknownPublicKeyCredential(
        relyingPartyIdentifier: rpId,
        credentialID: credentialIdData
      )
    } catch {
      Logger.error("signalUnknownCredential failed: \(error.localizedDescription)")
    }
  }
}
