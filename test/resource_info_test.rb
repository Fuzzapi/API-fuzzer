require 'test_helper'
require 'API_Fuzzer/resource_info'

class APIFuzzer::ResourceInfoTest < Minitest::Test
  def setup
    @response = HTTP.get('https://shopify.ca')
    @info = API_Fuzzer::ResourceInfo.new(@response)
  end
end
