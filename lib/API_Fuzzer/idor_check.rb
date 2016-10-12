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
            cookies: @cookies
          )

          response_without_session = API_Fuzzer::Request.send_api_request(
            url: @url,
            params: @params,
            method: method
          )

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
    end
  end
end
