require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe Retrospectiva::LDAPAuth do

  def person_hash
    { 'dn' => ['CN=user,DN=any'], 'sAMAccountName' => ['user'], 'name' => ['User'], 'mail' => ['user@home.com'] }
  end

  def ldap
    @ldap ||= returning(mock('LDAPConn', :base => 'DN=any')) do |l|
      l.stub!(:search).and_return(person_hash)
    end
  end
  
  def connection(*args, &block)
    args = ['user', 'pass'] if args.empty?
    @connection ||= Retrospectiva::LDAPAuth.connect(*args, &block)
  end

  before do
    Net::LDAP.stub!(:new).and_return(ldap)
    ldap.stub!(:auth)
    ldap.stub!(:transaction).and_yield
  end
  
  describe 'if connected' do

    describe 'authentication' do
    
      it 'should accept simple credentials' do
        ldap.should_receive(:auth).with('user', 'pass')
        connection
      end

      it 'should accept credentials with domain prefix' do
        ldap.should_receive(:auth).with('user', 'pass')
        connection 'MY_DOMAIN\user', 'pass'
      end

      it 'should sanitize credentials with back-slashes' do
        ldap.should_receive(:auth).with('username', 'pass')
        connection "sanitize everything\\before.the\\username", 'pass'
      end

      it 'should sanitize credentials with forward-slashes' do
        ldap.should_receive(:auth).with('username', 'pass')
        connection "sanitize everything/before.the////username", 'pass'
      end

      it 'should extend username if domain is required' do          
        Retrospectiva::LDAPAuth.stub!(:config).and_return(:domain => 'my-domain.com')
        ldap.should_receive(:auth).with('user@my-domain.com', 'pass')
        connection 'user', 'pass'
      end

    end

    it 'should be connected' do
      connection.should be_connected   
    end
    
    it 'should perform block actions' do
      connection { |c| c.find_person.should be_a(Retrospectiva::LDAPAuth::Person) }
    end

  end

  describe 'if NOT connected' do
    
    before { ldap.stub!(:auth).and_raise(Net::LDAP::LdapError) }

    it 'should not be connected' do
      connection.should_not be_connected   
    end
    
    it 'should not perform any actions' do      
      ldap.should_not_receive(:search)      
      connection {|c| c.find_person }
    end
    
  end
    
end