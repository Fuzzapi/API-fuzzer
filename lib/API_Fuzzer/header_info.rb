require 'yaml'
require 'API_Fuzzer/vulnerability'

module API_Fuzzer

  class InvalidResponse < StandardError; end
  class HeaderInfo
    def self.scan(response)
      @response = response
      @headers = @response.headers
      load_header_rules
      scan_headers
      raise InvalidResponse, "Invalid response argument passed" unless @response
    end

    def self.scan_headers
     @vulnerabilities = []

      @rules.each do |rule|
        name = rule['name']
        header_keys = @headers.keys.map { |key| key.downcase }
        if header_keys.include? name
          unless /#{rule['match']}/.match(@headers[name])
            @vulnerabilities << API_Fuzzer::Vulnerability.new(
              description: rule['description'],
              value: [name, @headers[name]].join(" ")
            )
          end
        else
          @vulnerabilities << API_Fuzzer::Vulnerability.new(
            description: rule['description'],
            value: [name, @headers[name]].join(" ")
          )
        end
      end
      @vulnerabilities
    end

    def self.load_header_rules
      info_rules = File.expand_path('../../../rules', __FILE__)
      @rules = YAML::load_file(File.join(info_rules, "headers.yml"))['rules']
    end
  end
end
