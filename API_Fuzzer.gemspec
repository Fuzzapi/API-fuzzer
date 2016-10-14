# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'API_Fuzzer/version'

Gem::Specification.new do |spec|
  spec.name          = "API_Fuzzer"
  spec.version       = APIFuzzer::VERSION
  spec.authors       = ["Lalith Rallabhandi"]
  spec.email         = ["lalithr95@gmail.com"]

  spec.summary       = %q{APIFuzzer gem builds api for finding security issues through a fuzzer}
  spec.description   = %q{APIFuzzer gem builds api for finding security issues through a fuzzer}
  spec.homepage      = "https://github.com/lalithr95/API-Fuzzer"
  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency 'http', '~> 2.0'
  spec.add_dependency 'activesupport'
  spec.add_dependency 'rails', '>= 4.2'
  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest", "~> 5.0"
end
