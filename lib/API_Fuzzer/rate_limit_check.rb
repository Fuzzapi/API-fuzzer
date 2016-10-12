require 'API_Fuzzer/vulnerability'
require 'API_Fuzzer/request'

module API_Fuzzer
  class RateLimitCheck
    def self.scan(options = {})
      @url = options[:url]
      @params = options[:params] || {}
      @headers = options[:headers] || {}
      @cookies = options[:cookies] || {}
      @vulnerabilities = []
      @limit = options[:limit] || 50
      @methods = options[:method] || [:get]

      @methods.each { |method| fuzz_api_requests(method) }
      @vulnerabilities.uniq { |vuln| vuln.description }
    end

    def self.fuzz_api_requests(method)
      initial_response = fetch_initial_response(method)

      responses = []
      @limit.times do
        responses << API_Fuzzer::Request.send_api_request(
          url: @url,
          method: method,
          cookies: @cookies,
          headers: @headers,
          params: @params
        )
      end

      vulnerable = true
      responses.each do |response|
        if response.code  == initial_response.code
          content_length = response_content_length(response)
          initial_content_length = response_content_length(initial_response)
          if  content_length != initial_content_length
            vulnerable = false
            break
          end
        else
          vulnerable = false
          break
        end
      end
      @vulnerabilities << API_Fuzzer::Vulnerability.new(
        description: "API is not rate limited for #{method} #{@url}",
        value: "API doesn't have any ratelimiting protection enabled which can be implemented by either throttling request or using captcha",
        type: 'LOW'
      ) if vulnerable
    end

    private
    def self.fetch_initial_response(method)
      API_Fuzzer::Request.send_api_request(
        url: @url,
        method: method,
        cookies: @cookies,
        headers: @headers,
        params: @params
      )
    end

    def self.response_content_length(response)
      response.headers['Content-Length'] || response.body.to_s.size
    end
  end
end
