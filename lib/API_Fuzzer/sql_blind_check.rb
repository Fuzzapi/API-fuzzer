require 'API_Fuzzer/vulnerability'
require 'API_Fuzzer/error'
require 'API_Fuzzer/request'
require 'API_Fuzzer/sql_check'

module API_Fuzzer
  class InvalidURLError < StandardError; end
  class SqlBlindCheck < SqlCheck
    PAYLOAD_PATH = '../../../payloads/blind_sql.txt'.freeze
    PAYLOADS = []
    SQL_ERRORS = []
    SCAN_TIME = '20'
    protected

    def self.fuzz_each_parameter(parameter, payload)
      @params[parameter] << payload
      ALLOWED_METHODS.each do |method|
        start_time = Time.now
        response = API_Fuzzer::Request.send_api_request(
          url: @url,
          params: @params,
          method: method,
          cookies: @cookies
        )
        end_time = Time.now
        diff = end_time - start_time
        if diff > 20 && diff < 25
          @vulnerabilities << API_Fuzzer::Vulnerability.new(
            description: "Possible blind SQL injection in #{method} #{@url} parameter: #{parameter}",
            value: "[PAYLOAD] #{payload}"
          )
        end
      end
    end

    def self.fetch_payloads
      file = File.expand_path(PAYLOAD_PATH, __FILE__)
      File.readlines(file).each do |line|
        PAYLOADS << line.gsub('__TIME__', SCAN_TIME).gsub('__MARK__', '20000000')
      end
    end
  end
end
