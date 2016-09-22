require 'test_helper'
require 'API_Fuzzer/header_info'
require 'http'

class APIFuzzer::HeaderInfoTest < Minitest::Test
  def setup
    @response = Http.get('https://www.shopify.ca')
    @info = API_Fuzzer::HeaderInfo.new(@response)
  end
end
