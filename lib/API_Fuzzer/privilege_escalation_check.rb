require 'API_Fuzzer/vulnerability'
require 'API_Fuzzer/error'
require 'API_Fuzzer/request'

module API_Fuzzer
  class PrivilegeEscalationCheck
    class << self
      def scan(options = {})
        @url = options[:url]
        @params = options[:params] || {}
        @headers = options[:headers] || {}
        @methods = options[:method] || []
        @cookies = options[:cookies] || {}

        @vulnerabilities = []
        fuzz_privileges
        @vulnerabilities.uniq  { |vuln| vuln.description }
      rescue Exception => e
        Rails.logger.info e.message
      end

      def fuzz_privileges
        id = /\A\d+\z/
        uri = URI(@url)
        path = uri.path
        query = uri.query
        url = @url
        base_uri = query.nil? ? path : [path, query].join("?")
        fragments = base_uri.split(/[\/,?,&]/) - ['']
        fragments.each do |fragment|
          if fragment.match(/\A(\w)+=(\w)*\z/)
            key, value = fragment.split("=")
            if value.match(id)
              value = value.to_i
              value += 1
              url = url.gsub(fragment, [key, value].join("=")).chomp
              fuzz_identity(url, @params)
            end
          elsif fragment.match(id)
            value = fragment.to_i
            value += 1
            url = url.gsub(fragment, value.to_s).chomp if url
            fuzz_identity(url, @params, url)
          end
        end
        return if @params.empty?

        parameters = @params
        parameters.keys.each do |parameter|
          value = parameters[parameter]
          if value.match(id)
            value = value.to_i
            value += 1
            info = [parameter, value].join(" ")
            fuzz_identity(@url, parameters.merge(parameter, value), info)
          end
        end
      end

      def fuzz_identity(url, params, value)
        @methods.each do |method|
          response = API_Fuzzer::Request.send_api_request(
            url: url,
            method: method,
            params: @params,
            cookies: @cookies,
            headers: @headers
          )
          @vulnerabilities << API_Fuzzer::Vulnerability.new(
            type: 'HIGH',
            value: "ID in #{value} parameter is vulnerable to Privilege Escalation vulnerability.",
            description: "Privilege Escalation vulnerability in #{method} #{url}"
          ) if response.code == 200
        end
      end
    end
  end
end
