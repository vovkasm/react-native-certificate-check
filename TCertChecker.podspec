require 'json'
version = JSON.parse(File.read('package.json'))['version']

Pod::Spec.new do |s|
  s.name            = 'TCertChecker'
  s.version         = version
  s.homepage        = 'https://github.com/vovkasm/react-native-certificate-check'
  s.summary         = 'Check certificate for validity'
  s.license         = 'MIT'
  s.author          = { 'Vladimir Timofeev' => 'vovkasm@gmail.com' }
  s.ios.deployment_target = '8.0'
  s.source          = { :git => 'https://github.com/vovkasm/react-native-certificate-check.git', :tag => "v#{s.version}" }
  s.source_files    = 'ios/TCertChecker/*.{h,m}'
  s.preserve_paths  = '**/*.js'
  s.frameworks      = 'Foundation', 'Security'
  s.dependency 'React'
end
