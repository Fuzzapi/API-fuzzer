require 'http'
require 'byebug'

module API_Fuzzer
  class Request
    attr_accessor :response, :request

    class << self
      def send_api_request(options = {})
        @url = options.delete(:url)
        @params = options.delete(:params) || {}
        @method = options.delete(:method) || :get
        @json = options.delete(:json) ? true : false
        @request = set_cookies(options)
        send_request
      end
    end

    def response
      @response
    end

    def success?
      @response.code == 200
    end

    private

    def self.set_cookies(options = {})
      cookies = options.delete(:cookies) || {}
      request_object = HTTP.cookies('api_fuzzer' => true).headers("Content-Type" => "application/xml")
      cookies.each do |cookie, value|
        request_object.cookies(cookie, value)
      end
      request_object
    end

    def self.send_request
      @response = case @method.to_sym
      when :post
        @request.post(@url, set_params)
      when :put
        @request.put(@url, set_params)
      when :patch
        @request.patch(@url, set_params)
      when :head
        @request.head(@url, set_params)
      when :delete
        @request.delete(@url, set_params)
      else
        @request.get(@url, set_params)
      end
    end

    def self.set_params
      if @json && !method_get?
        { 'json' => @params }
      elsif method_get?
        { 'params' => @params }
      else
        { 'form' => @params }
      end
    end

    def self.method_get?
      @method.to_s == 'get'
    end
  end
end
