#--
# Copyright (C) 2009 Dimitrij Denissenko
# Please read LICENSE document for more information.
#++
class AccountsController < ApplicationController
  alias_method :standard_registration, :create
  protected :standard_registration

  def create
    @user.attributes = params[:user].except(:username)    
    @user.username   = params[:user][:username]    
    @user.plain_password_confirmation = nil 
    
    @directory, @entry = find_person(@user.username, @user.plain_password)    
    if @entry
      @user.email = @entry.email
      @user.name  = @entry.name
    end
    
    if @directory.connected? and @user.save
      successful_registration 
    elsif @entry.present?
      failed_registration _('Missing attributes in directory entry.')
    else
      @user.errors.clear
      if @directory.connected?
         _('Unable to find user account in directory.')
      else
        failed_registration _('Invalid username or password.')
      end
    end
  end

  private
  
    def find_person(*credentials)
      entry = nil
      directory = Retrospectiva::LDAPAuth.connect(*credentials) do |ldap|
        entry = ldap.find_person
      end
      [directory, entry]      
    end

end