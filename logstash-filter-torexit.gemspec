Gem::Specification.new do |s|
  s.name          = 'logstash-filter-torexit'
  s.version       = '0.1.0'
  s.licenses      = ['Apache License (2.0)']
  s.summary       = 'TOR exit node identifier'
  s.description   = 'This filter plugin allows you to identify events originating from TOR exit nodes.'
  s.homepage      = 'https://www.github.com/hartfordfive/logstash-filter-torexit'
  s.authors       = ['Alain Lefebvre']
  s.email         = 'alain.lefebvre@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'
end
