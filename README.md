# API Fuzzer

`API_Fuzzer` gem accepts a API request as input and returns vulnerabilities possible in the API. Following are the main check involved in API_Fuzzer gem

- Cross-site scripting vulnerability
- SQL injection
- Blind SQL injection
- XML External entity vulnerability
- IDOR (in specific cases)
- API Rate Limiting
- Open redirect vulnerabilities
- Information Disclosure flaws
- Info leakage through headers
- Cross-site request forgery vulnerability

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'API_Fuzzer'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install API_Fuzzer

## Usage

Run `bin/console`

Lets say you have following endpoint

```
POST /api/v2/credit_cards/123

Host: test.host.com
User-Agent: Mozilla Firefox
Auth: Basic Adnjefnef443nr4jh4h
{ credit_card: '4242424242424242', expiry: '07/17', cvv: '123', name: 'First name' }
```

API_Fuzzer module comes with static method `scan` and accepts above request
```ruby
require 'API_Fuzzer'

options = {
  url: 'http://test.host.com/api/v2/credit_cards/123',
  params: {
    credit_card: '4242424242424242',
    expiry: '07/17',
    cvv: '123',
    name: 'First name'
  },
  method: ['POST'],
  headers: {
    'Host' => 'test.host.com',
    'User-Agent' => 'Mozilla Firefox',
    'Auth' => 'Basic Adnjefnef443nr4jh4h'
  }
}
vulnerabilities = API_Fuzzer.scan(options)
```
`vulnerabilites` is an array of vulnerability, each distinguished with impact type, title and description.


Above Ruby code can be painful for writing ruby script for each request. [Fuzzapi](https://github.com/lalithr95/Fuzzapi) is a rails application which integrates and bundles API_Fuzzer and brings UI changes to easily scan API endpoints.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

If you have any issue, we would be happy to help. You can create an issue in repository or contact any of following twitter handles
@abhijeth, @srini0x00, @lalithr95 

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/lalithr95/API_Fuzzer. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

Copyrights [Fuzzdb](https://github.com/fuzzdb-project/fuzzdb) for fuzzing payloads
