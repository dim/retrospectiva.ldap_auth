#--
# Copyright (C) 2009 Dimitrij Denissenko
# Please read LICENSE document for more information.
#++
begin 
  gem 'dim-ruby-net-ldap', '>= 0.1.1' 
  require 'net/ldap'
rescue LoadError
  puts "Missing net/ldap library. Please install the correct GEM via:"
  puts "  sudo gem install dim-ruby-net-ldap --source=http://gems.github.com"
  puts
  raise
end
require 'digest/sha1'
require 'retrospectiva/ldap_auth'

RetroEM::Views.register_extension 'ldap_auth/account', :user, :fields, :public, :existing
