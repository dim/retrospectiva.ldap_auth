require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe User do
  fixtures :users

  before do
    Retrospectiva::LDAPAuth.stub!(:authenticates?).and_return(false)        
  end

  describe 'secure (salted) authentication' do    
    it 'should be disabled' do
      User.secure_auth?.should be(false)
    end
  end
  
  describe 'authentication' do

    def authenticate(username, password = 'somepassword')
      User.authenticate(:username => username.to_s, :password => password.to_s)
    end

    it 'should use check the password' do
      User.stub!(:identify).and_return(users(:agent))
      users(:agent).should_receive(:valid_password?).with('somepassword').and_return(true)        
      authenticate(:agent).should == users(:agent)
    end

    it 'should query the directory' do
      Retrospectiva::LDAPAuth.should_receive(:authenticates?).with('agent', 'somepassword').and_return(true)
      authenticate(:agent).should == users(:agent)
    end
    
    describe 'if directory authentication fails' do
            
      it 'should try normal authentication for admins' do
        User.stub!(:identify).and_return(users(:admin))
        Retrospectiva::LDAPAuth.should_receive(:authenticates?).with('admin', 'somepassword').and_return(false)
        users(:admin).should_receive(:valid_password_without_ldap?).with('somepassword')
        authenticate(:admin).should be_nil
      end
      
      it 'should fail authentication for normal users' do
        User.stub!(:identify).and_return(users(:agent))
        Retrospectiva::LDAPAuth.should_receive(:authenticates?).with('agent', 'somepassword').and_return(false)
        users(:agent).should_not_receive(:valid_password_without_ldap?)
        authenticate(:agent).should be_nil
      end
    end
    
    
  end
  
end