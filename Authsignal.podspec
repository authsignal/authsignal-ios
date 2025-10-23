Pod::Spec.new do |s|
  s.name             = 'Authsignal'
  s.version          = '1.6.1'
  s.summary          = 'The Authsignal SDK for iOS'

  s.homepage         = 'https://github.com/authsignal/authsignal-ios'
  s.license          = { :type => 'MIT', :file => 'LICENSE.md' }
  s.author           = { 'Authsignal' => 'support@authsignal.com' }
  s.source           = { :git => 'https://github.com/authsignal/authsignal-ios.git', :tag => "v#{s.version.to_s}" }

  s.ios.deployment_target = '13.0'
  s.swift_version = '5.0'
  s.source_files = 'Sources/Authsignal/**/*'
end
