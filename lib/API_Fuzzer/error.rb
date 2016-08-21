module API_Fuzzer
  class Error
    attr_accessor :url, :status, :value

    def initialize(options = {})
      @url = options.delete(:url) || nil
      @status = options.delete(:status)
      @value = options.delete(:value)
    end
  end
end
