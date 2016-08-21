require 'test_helper'
require 'API_Fuzzer/resource_info'
require 'http'

class APIFuzzer::ResourceInfoTest < Minitest::Test
  def setup
    @response = HTTP.get('https://shopify.ca')
    @info = API_Fuzzer::ResourceInfo.new(@response)
    p @info
  end

  def test_that_it_has_a_version_number
    refute_nil ::APIFuzzer::VERSION
  end

  def test_it_does_something_useful
    assert false
  end
end
