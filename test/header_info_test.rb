require 'test_helper'
require 'API_Fuzzer/header_info'
require 'http'

class APIFuzzer::HeaderInfoTest < Minitest::Test
  def setup
    @response = Http.get('https://www.shopify.ca')
    @info = API_Fuzzer::HeaderInfo.new(@response)
  end

  def test_that_it_has_a_version_number
    refute_nil ::APIFuzzer::VERSION
  end

  def test_it_does_something_useful
    assert false
  end
end
