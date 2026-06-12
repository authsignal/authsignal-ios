public enum JSONValue: Codable, Equatable {
  case string(String)
  case number(Double)
  case bool(Bool)
  case object([String: JSONValue])
  case array([JSONValue])
  case null

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()

    if let bool = try? container.decode(Bool.self) {
      self = .bool(bool)
    } else if let number = try? container.decode(Double.self) {
      self = .number(number)
    } else if let string = try? container.decode(String.self) {
      self = .string(string)
    } else if let object = try? container.decode([String: JSONValue].self) {
      self = .object(object)
    } else if let array = try? container.decode([JSONValue].self) {
      self = .array(array)
    } else if container.decodeNil() {
      self = .null
    } else {
      throw DecodingError.dataCorruptedError(
        in: container,
        debugDescription: "Invalid JSON value"
      )
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()

    switch self {
    case .string(let string):
      try container.encode(string)
    case .number(let number):
      try container.encode(number)
    case .bool(let bool):
      try container.encode(bool)
    case .object(let object):
      try container.encode(object)
    case .array(let array):
      try container.encode(array)
    case .null:
      try container.encodeNil()
    }
  }

  public var value: Any? {
    switch self {
    case .string(let string):
      return string
    case .number(let number):
      return number
    case .bool(let bool):
      return bool
    case .object(let object):
      return object.mapValues { $0.value }
    case .array(let array):
      return array.map { $0.value }
    case .null:
      return nil
    }
  }
}
