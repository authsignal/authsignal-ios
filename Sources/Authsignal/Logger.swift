import Foundation
import os.log

class Logger {
  static func info(_ message: String, redacted: Bool = false) {
    log(message, type: .info, redacted: redacted)
  }

  static func error(_ message: String, redacted: Bool = false) {
    log(message, type: .error, redacted: redacted)
  }

  private static func log(_ message: String, type: OSLogType, redacted: Bool) {
    let messageWithPrefix = "[Authsignal] \(message)"

    if #available(iOS 12.0, *) {
      os_log(
        type, redacted ? Constants.privateLogFormat : Constants.publicLogFormat, messageWithPrefix)
    } else {
      os_log(redacted ? Constants.privateLogFormat : Constants.publicLogFormat, messageWithPrefix)
    }
  }
}

extension Logger {
  fileprivate struct Constants {
    static let publicLogFormat: StaticString = "%{public}@"
    static let privateLogFormat: StaticString = "%{private}@"
  }
}
