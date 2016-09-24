API_Fuzzer::Engine.routes.draw do
  get '/ping/:id' => 'ping#index'
end
