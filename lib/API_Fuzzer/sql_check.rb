require 'API_Fuzzer/vulnerability'
require 'API_Fuzzer/error'
require 'API_Fuzzer/request'

module API_Fuzzer
  class InvalidURLError < StandardError; end

  class SqlCheck
    attr_accessor :parameters

    ALLOWED_METHODS = [:get, :post].freeze
    PAYLOAD_PATH = File.expand_path('../../../payloads/sql.txt', __FILE__)
    DETECT_PATH = File.expand_path('../../../payloads/detect/sql.txt', __FILE__)
    PAYLOADS = []
    SQL_ERRORS = []

    def self.scan(options = {})
      fetch_payloads
      @url = options[:url] || nil
      raise InvalidURLError, "[ERROR] URL missing in argument" unless @url
      @params = options[:params] || {}
      @cookies = options[:cookies] || {}
      @json = options[:json] || false
      @vulnerabilities = []

      fuzz_payloads
      return @vulnerabilities.uniq { |vuln| vuln.description }
    rescue HTTP::ConnectionError => e
      sleep(5)
      fuzz_payloads
      return @vulnerabilities.uniq { |vuln| vuln.description }
    end

    protected

    def self.fuzz_payloads
      PAYLOADS.each do |payload|
        fuzz_each_payload(payload)
      end
    end

    def self.fuzz_each_payload(payload)
      if @params.empty?
        fragments = URI(@url).path.split("/") - ['']
        fragments.each do |fragment|
          url = @url.gsub(fragment, payload)
          fuzz_each_fragment(url, payload)
        end
      else
        @params.keys.each do |parameter|
          fuzz_each_parameter(parameter, payload)
        end
      end
    end

    def self.fuzz_each_fragment(url, payload)
      ALLOWED_METHODS.each  do |method|
        begin
          response = API_Fuzzer::Request.send_api_request(
            url: url,
            method: method,
            cookies: @cookies
          )
          
          @vulnerabilities << API_Fuzzer::Error.new(url: "#{method} #{@url}", status: response.status, value: response.body) unless success?(response)
          body = ''
          if response_json?(response)
            body = JSON.parse(response.body)
          else
            body = response.body
          end

          vulnerable = check_response?(body.to_s.downcase, payload)
          next unless vulnerable
          @vulnerabilities << API_Fuzzer::Vulnerability.new(
            description: "Possible SQL injection in #{method} #{@url}",
            parameter: "URL: #{url}",
            value: "[PAYLOAD] #{payload}",
            type: 'HIGH'
          )
        rescue Exception => e
          puts e.message
        end
      end
    end

    def self.fuzz_each_parameter(parameter, payload)
      @params[parameter] = payload
      ALLOWED_METHODS.each do |method|
        begin
          response = API_Fuzzer::Request.send_api_request(
            url: @url,
            params: @params,
            method: method,
            cookies: @cookies
          )

          @vulnerabilities << API_Fuzzer::Error.new(url: "[ERROR] #{method} #{@url}", status: response.status, value: response.body) unless success?(response)
          body = response.body.to_s.downcase
          vulnerable = check_response?(body, payload)
          next unless vulnerable

          @vulnerabilities << API_Fuzzer::Vulnerability.new(
            description: "Possible SQL injection in #{method} #{@url} parameter: #{parameter}",
            parameter: "parameter: #{@parameter}",
            value: "[PAYLOAD] #{payload}",
            type: 'HIGH'
          )
        rescue Exception => e
          puts e.message
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
      response && response.headers['Content-Type'] && response.headers['Content-Type'].downcase =~ /application\/json/
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
