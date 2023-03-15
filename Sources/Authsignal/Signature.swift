import Foundation

class Signature {
  static var algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256

  static func sign(message: String, privateKey: SecKey) throws -> String {
    let messageData = (message).data(using: .utf8)! as CFData
  
    guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
      throw SignatureError.message("Algorithm not supported on this device")
    }
    
    var error: Unmanaged<CFError>?
    
    let signedMessage = SecKeyCreateSignature(privateKey, Signature.algorithm, messageData, &error)
    
    guard signedMessage != nil else {
      throw SignatureError.message("Error signing message: \(error!)")
    }
    
    return (signedMessage! as Data).base64EncodedString()
  }
}

enum SignatureError: Error {
  case message(String)
}
