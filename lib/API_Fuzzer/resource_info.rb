require 'yaml'
require 'API_Fuzzer/vulnerability'

module API_Fuzzer

  class InvalidResponse < StandardError; end

  class ResourceInfo
    # Accepts response and performs rules match based on the ruleset

    class << self
      def scan(response)
        @response = response
        if @response
          fetch_rules
          scan_rules
        else
          raise InvalidResponse, "Invalid response argument has been passed"
        end
      end

      def fetch_rules
        info_rules = File.expand_path('../../../rules', __FILE__)
        @rules = YAML::load_file(File.join(info_rules, "info.yml"))['rules']
      end

      def scan_rules
        @vulnerability_info = []

        if @rules
          headers = @response.headers.keys
          
          @rules.each do |rule|
            headers.each do |header|
              
              if /#{rule['match'].downcase}/.match(header.downcase)
                @vulnerability_info << API_Fuzzer::Vulnerability.new(
                  description: rule['description'],
                  value: [header, @response.headers[header].to_s].join(": "),
                  type: 'INFORMATIVE'
                )
              end
            
            end
          end
        end
        return @vulnerability_info
      end
    end
  end
end
