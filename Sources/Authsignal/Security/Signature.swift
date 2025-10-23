import Foundation

class Signature {
  static var algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256

  static func sign(message: String, privateKey: SecKey) -> AuthsignalResponse<String> {
    let messageData = (message).data(using: .utf8)! as CFData

    guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
      return AuthsignalResponse(error: "Algorithm not supported on this device")
    }

    var error: Unmanaged<CFError>?

    let signedMessage = SecKeyCreateSignature(privateKey, Signature.algorithm, messageData, &error)

    guard signedMessage != nil else {
      return AuthsignalResponse(error: "Error signing message: \(error!)")
    }
    
    return AuthsignalResponse(data: (signedMessage! as Data).base64EncodedString())
  }
  
  static func signWithTimeBasedMessage(privateKey: SecKey) -> AuthsignalResponse<String> {
    let secondsSinceEpoch = Double(Date().timeIntervalSince1970)
    
    let message = String(floor(secondsSinceEpoch / (60 * 10)))
    
    return sign(message: message, privateKey: privateKey)
  }
}
