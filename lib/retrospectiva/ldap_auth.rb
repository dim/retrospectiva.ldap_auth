# Small patch/extension for net/ldap
class Net::LDAP
  
  def transaction
    raise LdapError.new( "transaction already in progress" ) if @open_connection
    begin
      @open_connection = Connection.new( :host => @host, :port => @port, :encryption => @encryption )
      result = @open_connection.bind(@auth) 
      yield self if result.zero? 
    ensure
      @open_connection.close if @open_connection
      @open_connection = nil
    end
  end
  
end

module Retrospectiva
  module LDAPAuth

    def self.connect(username, password, &block)
      Base.new(username, password, &block)
    end 

    def self.authenticates?(username, password)
      connect(username, password).connected?
    end 

    def self.config
      RetroCM[:ldap][:server]      
    end
  
    class Base  
      attr_reader :conn     
      delegate :search, :to => :conn
      delegate :config, :to => :"Retrospectiva::LDAPAuth"
  
      def initialize(username, password, &block)
        @username = extract_username(username)
        @use_ssl  = config[:use_ssl]
        @domain   = config[:domain] unless config[:domain].blank? 
        @filter   = Net::LDAP::Filter.construct(config[:filter]) unless config[:filter].blank?                
        @conn     = Net::LDAP.new(
          :host => config[:host], 
          :port => config[:port], 
          :base => config[:base], 
          :encryption => use_ssl? ? :simple_tls : nil
        )
        bind_with! password, &block
      end
          
      def connected?
        @connected == true
      end
    
      def use_ssl?
        @use_ssl == true
      end

      def find(what, options = {})
        options[:base] ||= conn.base        
        case what
        when :first
          result = search(options) {|i| break(i) }
          result.blank? ? nil : result
        when :all
          search(options)
        end
      end
      
      def entry_for(dn)
        find( :first, :base => dn )         
      end
      
      def find_person(san = nil)
        san ||= @username
        entry = find :first, :filter => construct_filter(san.to_s)        
        entry ? Person.new(entry, self) : nil
      end
      
      def full_username
        [@username, @domain].compact.join('@')
      end
  
      protected
  
        def extract_username(username)
          username.to_s.split(/[\\\/]+/).last
        end
    
        def construct_filter(san)
          returning Net::LDAP::Filter.eq( RetroCM[:ldap][:attribute_names][:san], san ) do |filter|        
            filter &= @filter unless @filter.blank?
          end 
        end
  
        def bind_with!(password, &block)
          conn.auth full_username, password
          conn.transaction do
            @connected = true
            yield(self) if block_given?
          end
        rescue Net::LDAP::LdapError => e
          RAILS_DEFAULT_LOGGER.error "[LDAP-AUTH] #{e.message}"
        end

    end
  
    class AbstractUnit
      attr_reader :attributes, :conn, :entry
      delegate :entry_for, :to => :conn
  
      def initialize(entry, conn)
        @conn = conn
        @entry = entry
        @attributes = parse_attributes(entry).with_indifferent_access.freeze
        @attributes.keys.each do |name|
          self.class.class_eval "def #{name}; attributes['#{name}'].dup rescue attributes['#{name}']; end"
        end
      end
  
      def groups
        @groups ||= Array(member_of).compact.map do |group_dn|
          entry = entry_for(group_dn)
          entry.attribute_names.include?(:mail) ? Group.new(entry, conn) : nil        
        end.compact
      end
  
      def recursive_groups(limit = 20)
        @recursive_groups ||= groups.map do |group|
          limit > 0 ? [group] + group.recursive_groups(limit - 1) : []
        end.flatten.uniq
      end
  
      protected
      
        def parse_attributes(entry)
          {
            'member_of'   => entry[attribute_names[:member_of]],
            'dn'          => entry[attribute_names[:dn]].first
          }
        end

        def attribute_names
          RetroCM[:ldap][:attribute_names]
        end      

    end
  
  
    class Group < AbstractUnit    
      alias_method :parents, :groups
      alias_method :ancestors, :recursive_groups
  
      protected
        
        def parse_attributes(entry)
          super.merge(
            'name'        => entry[attribute_names[:name]].first,
            'description' => entry[attribute_names[:description]].first
          )
        end
    
    end
  
  
    class Person < AbstractUnit
      
      def inspect
        "<#{self.class.name} #{@attributes.inspect}>"
      end
      
      protected
        
        def parse_attributes(entry)
          super.merge(
            'username'   => entry[attribute_names[:san]].first.downcase,
            'name'       => entry[attribute_names[:name]].first,
            'email'      => entry[attribute_names[:email]].first
          )
        end
      
    end
  end
end
