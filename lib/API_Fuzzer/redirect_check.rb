require 'API_Fuzzer/vulnerability'
require 'API_Fuzzer/error'
require 'API_Fuzzer/request'
require 'uri'

module API_Fuzzer
  class RedirectCheck
    REDIRECT_URL = 'http://127.0.0.1:3000/ping'
    ALLOWED_METHODS = [:get, :post]
    class << self
      def scan(options = {})
        @url = options[:url]
        @params = options[:params] || {}
        @cookies = options[:cookies] || {}
        @json = options[:json] || false
        @headers = options[:headers] || {}

        @vulnerabilities = []
        fuzz_payload
        return @vulnerabilities.uniq { |vuln| vuln.description }
      rescue Exception => e
        @vulnerabilities << API_Fuzzer::Error.new(
          description: e.message,
          status: 'ERROR',
          value: e.backtrace
        )
      end

      def fuzz_payload
        uri = URI(@url)
        path = uri.path
        query = uri.query
        # base_uri = query.nil? ? path : [path, query].join("?")
        fragments = path.split(/[\/,?,&]/) - ['']
        fragments << query.split('&') if query
        fragments.flatten!
        fragments.each do |fragment|
          if fragment.match(/\A(\w+)=(.?*)\z/) && valid_url?($2)
            url = @url.gsub($2, REDIRECT_URL).chomp
            fuzz_fragment(url)
          elsif valid_url?(fragment)
            url = @url.gsub(fragment, REDIRECT_URL)
            fuzz_fragment(url)
          end
        end
        return if @params.empty?

        @params.keys.each do |parameter|
          fuzz_each_parameter(parameter) if valid_url? @params[parameter]
        end
      end

      def fuzz_fragment(url)
        ALLOWED_METHODS.each do |method|
          begin
            response = API_Fuzzer::Request.send_api_request(
              url: url,
              method: method,
              cookies: @cookies,
              params: @params,
              headers: @headers
            )

            @vulnerabilities << API_Fuzzer::Vulnerability.new(
              description: "Possible Open Redirect vulnerability in #{method} #{url}",
              parameter: "URL: #{url}",
              value: "[PAYLOAD] #{url.gsub(REDIRECT_URL, 'PAYLOAD_URL')}",
              type: 'MEDIUM'
            ) if response.headers['Location'] =~ /#{REDIRECT_URL}/
          rescue Exception => e
            puts e.message
          end
        end
      end

      def fuzz_each_parameter(parameter)
        params = @params
        params[parameter] = REDIRECT_URL
        ALLOWED_METHODS.each do |method|
          begin
            response = API_Fuzzer::Request.send_api_request(
              url: @url,
              method: method,
              cookies: @cookies,
              params: params,
              headers: @headers
            )

            @vulnerabilities << API_Fuzzer::Vulnerability.new(
              description: "Possible Open Redirect vulnerability in #{method} #{url}",
              parameter: "Parameter: #{parameter}",
              value: "[PAYLOAD] #{params.to_s.gsub(REDIRECT_URL, 'PAYLOAD_URL')}",
              type: 'MEDIUM'
            ) if response.headers['LOCATION'] =~ /#{REDIRECT_URL}/
          rescue Exception => e
            puts e.message
          end
        end
      end

      def valid_url? url
        url =~ URI.regexp
      end
    end
  end
end
