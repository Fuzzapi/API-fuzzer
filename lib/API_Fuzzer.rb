require 'API_Fuzzer/version'
require 'API_Fuzzer/header_info'
require 'API_Fuzzer/resource_info'
require 'API_Fuzzer/sql_check'
require 'API_Fuzzer/sql_blind_check'
require 'API_Fuzzer/xss_check'
require 'API_Fuzzer/request'
require 'API_Fuzzer/engine'
require 'API_Fuzzer/xxe_check'
require 'API_Fuzzer/redirect_check'
require 'API_Fuzzer/idor_check'
require 'API_Fuzzer/rate_limit_check'
require 'API_Fuzzer/csrf_check'
require 'API_Fuzzer/privilege_escalation_check'

module API_Fuzzer
  # Scans all the checks
  def self.scan(options = {})
    vulnerabilities = []
    options.freeze

    vulnerabilities << static_analysis(options)
    vulnerabilities << API_Fuzzer::XssCheck.scan(options)
    vulnerabilities << API_Fuzzer::SqlCheck.scan(options)
    vulnerabilities << API_Fuzzer::SqlBlindCheck.scan(options)
    vulnerabilities << API_Fuzzer::RedirectCheck.scan(options)
    vulnerabilities << API_Fuzzer::IdorCheck.scan(options)
    vulnerabilities << API_Fuzzer::RateLimitCheck.scan(options)
    vulnerabilities << API_Fuzzer::CsrfCheck.scan(options)
    vulnerabilities << API_Fuzzer::PrivilegeEscalationCheck.scan(options)
    API_Fuzzer::XxeCheck.scan(options)
    vulnerabilities.uniq.flatten
  end

  def self.static_analysis(options = {})
    response = API_Fuzzer::Request.send_api_request(url: options[:url], cookies: options[:cookies])
    issues = []

    issues << API_Fuzzer::ResourceInfo.scan(response)
    issues << API_Fuzzer::HeaderInfo.scan(response)
    issues
  end
end
