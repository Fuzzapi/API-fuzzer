module API_Fuzzer
  class Error
    attr_accessor :description, :status, :value

    def initialize(options = {})
      @description = options.delete(:description) || nil
      @status = options.delete(:status)
      @value = options.delete(:value)
    end
  end
end
