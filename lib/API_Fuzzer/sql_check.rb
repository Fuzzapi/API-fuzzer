require 'API_Fuzzer/vulnerability'
require 'API_Fuzzer/error'
require 'API_Fuzzer/request'

module API_Fuzzer
  class InvalidURLError < StandardError; end

  class SqlCheck
    attr_accessor :parameters

    ALLOWED_METHODS = [:get, :post].freeze
    PAYLOAD_PATH = '../../../payloads/sql.txt'.freeze
    DETECT_PATH = '../../../payloads/detect/sql.txt'.freeze
    PAYLOADS = []
    SQL_ERRORS = []

    def self.scan(options = {})
      fetch_payloads
      @url = options.delete(:url) || nil
      raise InvalidURLError, "[ERROR] URL missing in argument" unless @url
      @params = options.delete(:params) || {}
      @cookies = options.delete(:cookies) || {}
      @json = options.delete(:json) || false
      @vulnerabilities = []

      fuzz_payloads
      p @vulnerabilities
    rescue HTTP::ConnectionError => e
      sleep(5)
      fuzz_payloads
    end

    protected

    def self.fuzz_payloads
      PAYLOADS.each do |payload|
        fuzz_each_payload(payload)
      end
    end

    def self.fuzz_each_payload(payload)
      @params.keys.each do |parameter|
        fuzz_each_parameter(parameter, payload)
      end
    end

    def self.fuzz_each_parameter(parameter, payload)
      @params[parameter] = payload
      ALLOWED_METHODS.each do |method|
        response = API_Fuzzer::Request.send_api_request(
          url: @url,
          params: @params,
          method: method,
          cookies: @cookies
        )
        next if response_json?(response)
        body = response.body.to_s.downcase
        vulnerable = check_response?(body, payload)
        if success?(response)
          @vulnerabilities << API_Fuzzer::Vulnerability.new(
            description: "Possible SQL injection in #{method} #{@url} parameter: #{parameter}",
            value: "[PAYLOAD] #{payload}"
          ) if vulnerable
        else
          API_Fuzzer::Error.new(url: @url, status: response.status, value: @response.body)
          #Error
        end
      end
    end

    def self.check_response?(body, payload)
      SQL_ERRORS.each do |error|
        if body.match(error.chomp)
          return true
        end
      end
      false
    end

    def self.success?(response)
      response.code == 200
    end

    def self.response_json?(response)
      response && response.headers['Content-Type'].downcase =~ /application\/json/
    end

    def self.fetch_payloads
      file = File.expand_path(PAYLOAD_PATH, __FILE__)
      File.readlines(file).each do |line|
        PAYLOADS << line
      end

      file = File.expand_path(DETECT_PATH, __FILE__)
      File.readlines(file).each do |line|
        SQL_ERRORS << line.downcase
      end
    end
  end
end
