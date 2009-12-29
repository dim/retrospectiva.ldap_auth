#--
# Copyright (C) 2009 Dimitrij Denissenko
# Please read LICENSE document for more information.
#++
User.class_eval do  
  
  # Authenticate user against LDAP. Fallback to standard password authentication
  # if user is an admin to ensure Admin/Setup is still accessible if the 
  # LDAP connection is e.g. not setup correctly 
  def valid_password_with_ldap?(plain)
    Retrospectiva::LDAPAuth.authenticates?(username, plain) || (admin? and valid_password_without_ldap?(plain)) 
  end
  alias_method_chain :valid_password?, :ldap

end
