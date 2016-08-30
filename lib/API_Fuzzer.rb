require 'API_Fuzzer/version'
require 'API_Fuzzer/header_info'
require 'API_Fuzzer/resource_info'
require 'API_Fuzzer/sql_check'
require 'API_Fuzzer/sql_blind_check'
require 'API_Fuzzer/xss_check'
require 'API_Fuzzer/request'

module API_Fuzzer
  # Scans all the checks
  def self.scan(options = {})
    vulnerabilities = []
    options.freeze
    vulnerabilities << static_analysis(options)
    vulnerabilities << API_Fuzzer::XssCheck.scan(options)
    vulnerabilities << API_Fuzzer::SqlCheck.scan(options)
    vulnerabilities << API_Fuzzer::SqlBlindCheck.scan(options)
    vulnerabilities.uniq.flatten
  end

  def self.static_analysis(options = {})
    url = options[:url]
    response = API_Fuzzer::Request.send_api_request(url: url)
    issues = []

    issues << API_Fuzzer::ResourceInfo.scan(response)
    issues << API_Fuzzer::HeaderInfo.scan(response)
    issues
  end
end
