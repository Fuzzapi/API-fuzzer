require 'API_Fuzzer/vulnerability'
require 'API_Fuzzer/error'
require 'API_Fuzzer/request'

module API_Fuzzer

  class InvalidURLError < StandardError; end

  class XssCheck
    attr_accessor :parameters

    ALLOWED_METHODS = [:get, :post].freeze
    PAYLOADS = ["\"><script>alert(1)</script>"]

    def self.scan(options = {})
      @url = options.delete(:url) || nil
      raise InvalidURLError, "[ERROR] URL missing in argument" unless @url
      @params = options.delete(:params) || {}
      @params = { :txtSearch => 'abc' }
      @cookies = options.delete(:cookies) || {}
      @json = options.delete(:json) || false
      PAYLOADS.each do |payload|
        fuzz_each_payload(payload)
      end
    end

    private

    def self.fuzz_each_payload(payload)
      @params.keys.each do |parameter|
        fuzz_each_parameter(parameter, payload)
      end
    end

    def self.fuzz_each_parameter(parameter, payload)
      @params[parameter] = payload
      @vulnerabilities = []
      ALLOWED_METHODS.each do |method|
        response = API_Fuzzer::Request.send_api_request(
          url: @url,
          params: @params,
          method: method,
          cookies: @cookies
        )
        next if response_json?(response.body)
        vulnerable = check_response?(response.body, payload)
        if success?(response)
          @vulnerabilities << API_Fuzzer::Vulnerability.new(
            description: "Possible XSS in #{method} #{@url} parameter: #{@parameter}",
            value: "[PAYLOAD] #{payload}"
          )
        else
          API_Fuzzer::Error.new(url: @url, status: response.status, value: @response.body)
          #Error
        end
      end
      p @vulnerabilities.uniq
    end

    def self.check_response?(body, payload)
      if body.to_s.match(payload)
        true
      end
      false
    end

    def self.success?(response)
      response.code == 200
    end

    def response_json?(response)
      response.headers['Content-Type'].downcase ~= /application\/json/
    end
  end
end
