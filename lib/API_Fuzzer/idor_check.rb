require 'API_Fuzzer/vulnerability'
require 'API_Fuzzer/error'
require 'API_Fuzzer/request'

module API_Fuzzer
  class IdorCheck
    class << self
      def scan(options = {})
        @url = options[:url]
        @params = options[:params]
        @methods = options[:method]
        @headers = options[:headers] || {}
        @cookies = options[:cookies]
        @vulnerabilities = []

        fuzz_without_session
        @vulnerabilities.uniq { |vuln| vuln.description }
      end

      def fuzz_without_session
        @methods.each do |method|
          response = API_Fuzzer::Request.send_api_request(
            url: @url,
            params: @params,
            method: method,
            headers: @headers,
            cookies: @cookies
          )

          response_without_session = API_Fuzzer::Request.send_api_request(
            url: @url,
            params: @params,
            method: method
          )

          fuzz_sensitive_files(response, method)
          fuzz_match(response, response_without_session, method)
        end
      end

      def fuzz_match(resp, resp_without_session, method)
        @vulnerabilities << API_Fuzzer::Vulnerability.new(
          type: 'HIGH',
          value: "API doesn't have access control protection",
          description: "Possible IDOR in #{method} #{@url}"
        ) if resp.body.to_s == resp_without_session.body.to_s
      end

      def fuzz_sensitive_files(response, method)
        file_url = /^((https?:\/\/)?(www\.)?([\da-z\.-]+)\.([a-z\.]{2,6})\/[\w \.-]+?\.(pdf|doc|docs|rtf)([a-zA-Z0-9=?]*?))$/
        flagged_url = response.body.to_s.scan(file_url) || []
        flagged_url.each do |url|
          @vulnerabilities << API_Fuzzer::Vulnerability.new(
            type: 'MEDIUM',
            value: "File #{url} can be accessed without proper permissions",
            description: "Access control violation in #{method} #{url}"
          )
        end
      end
    end
  end
end
