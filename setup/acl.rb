#!/usr/bin/ruby
# -*- coding: utf-8 -*-

# man slapd.access(5)
# http://www.openldap.org/doc/admin24/access-control.html

# anonymous - unauthenticated clients
# users - authenticated clients
# self - authenticated entry itself
# realself - 

# <level> ::= none|disclose|auth|compare|search|read|{write|add|delete}|manage
# <priv> ::= {=|+|-}{0|d|x|c|s|r|{w|a|z}|m}+

# m for manage
# w for write
# a for add
# z for delete
# r for read
# s for search
# c for compare
# x for authentication
# d for disclose
# 0 indicates no privileges and is used only by itself (e.g., +0)
# +az is equivalent to +w

# Level         Privileges      Description
# none =        0               no access
# disclose =    d               needed for information disclosure on error
# auth =        dx              needed to authenticate (bind)
# compare =     cdx             needed to compare
# search =      scdx            needed to apply search filters
# read =        rscdx           needed to read search results
# write =       wrscdx          needed to modify/rename
# manage =      mwrscdx         needed to manage 

# to dn.exact="ou=People,dc=edu,dc=test,dc=edu" attrs="userPassword"
# by set="" +wscdx continue
# by anonymous +dx
# by * +0 break
#
# to dn.onelevel="ou=People,dc=edu,dc=test,dc=edu" attrs="userPassword"
# by set="" +wscdx continue
# by anonymous +dx
# by * +0 break
#
# to dn.onelevel="ou=People,dc=edu,dc=test,dc=edu"
# by set="" +wrscdx continue
# by set="" +rscdx continue
# by * +0 break
#
# * Access rights to ou's is given automatically when other rights are
#   given below them
# * 
# * dn.exact="" attrs="entry,ou,objectClass"
# * dn.exact="" attrs="children"
# * dn.onelevel=""

require "ldap"
require 'rubygems'
require 'readline'
require 'yaml'

begin
  if configuration = YAML.load_file("config/ldap.yml")
    @ldaphost = configuration['settings']['ldap_server']['host']
    @binddn = configuration['settings']['ldap_server']['bind_dn']
    
    puts "Connecting to #{@ldaphost} as #{@binddn}...\n"
  else
    puts "ERROR: Could not open LDAP configuration file (config/ldap.yml)"
    exit
  end
rescue
  puts "joo"
end

organisation_name = ARGV.first
puts "******************************************************"
puts "  Initialising organisation: #{organisation_name}"
puts "******************************************************"

organisation_base_template = "dc=edu,dc=%s,dc=fi"
suffix = organisation_base_template % organisation_name

def update_acls(suffix, acl)
  dn = ""
  domain = ""
  samba_domain = ""
  kerberos_realm = ""

  conn = LDAP::SSLConn.new(host=@ldaphost, port=636)
  conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)

  puts "#{@binddn} password:"
  @bindpw = Readline.readline('> ', true)

  conn.bind(@binddn, @bindpw) do
    begin
      old_access_rules = Array.new
      puts "SUFFIX: #{suffix}"

      conn.search("cn=config", LDAP::LDAP_SCOPE_SUBTREE, "(olcSuffix=#{suffix})") {|e|
        @dn = e.dn
        puts "DN: #{@dn}"

        old_access_rules = e.get_values('olcAccess')
      }

      conn.search(suffix, LDAP::LDAP_SCOPE_BASE, "(objectClass=eduOrg)") {|e|
        samba_domain = e.get_values('sambaDomainName')[0]
        kerberos_realm = e.get_values('puavoKerberosRealm')[0]
        domain = e.get_values('puavoDomain')[0]
      }

      puts
      puts "suffix:         #{suffix}"
      puts "Domain:         #{domain}"
      puts "Kerberos realm: #{kerberos_realm}"
      puts "Samba domain:   #{samba_domain}"

      if samba_domain.eql?("") or kerberos_realm.eql?("") or domain.eql?("")
        puts "ERROR: Couldn't figure out domain information!"
        exit
      end

      Readline.readline('OK?', true)

      entry = Array.new

      if old_access_rules
        entry << LDAP.mod(LDAP::LDAP_MOD_DELETE,'olcAccess',old_access_rules)
      end

      conn.modify(@dn, entry) {|e|
        puts e
      }

      counter = 0

      acl.rules.each {|rule|
        entry = Array.new
        puts rule

        entry << LDAP.mod(LDAP::LDAP_MOD_ADD,'olcAccess', ["{#{counter}}#{rule}"])

        conn.modify(@dn, entry) {|e|
          puts e
        }
      }



      rescue LDAP::ResultError
        conn.perror("LDAP connection failed")
        puts "LDAP connection failed"
    end  
  end
end


  

class Rule
  attr_accessor :filter
  attr_accessor :access_rights
  attr_accessor :attr
  attr_accessor :level

  def initialize(data)
    @dn = data[:dn]
    @level = data[:level]
    @filter = data[:filter]
    @attr = data[:attr]
    @who = data[:who]
    if data[:level]
      @level = data[:level]
    else
      @level = "onelevel"
    end
    @access_rights = data[:access_rights]
    @puavo_version = data[:puavo_version]
  end

  def who(filter="")
    filter.split(%r{\s*}).each {|char|
      if !@access_rights.include?(char)
        return
      end
    }

    @who
  end

  def to_s
    ret = ""

    ret += @who.map {|who|
      "by #{who} =#{@access_rights}" # continue"
    }.join(' ')

    ret
  end
end

class DN
  attr_accessor :basedn

  def initialize(dn)
    @basedn = dn

    @rules = Array.new
    @children = Hash.new
  end

  def add_rule(data, leaf=false)
    @leaf = leaf
    attrs = Array.new

    if data[:attrs]
      attrs = data[:attrs].split(',')
    else
      attrs << "@extensibleObject"
    end

    attrs.each {|attr|
      if data[:clauses]
        data[:clauses].each {|clause|
          clause[:who].each {|who|
            @rules << Rule.new({ :dn => @basedn,
                                 :filter => data[:filter],
                                 :attr => attr,
                                 :who => who,
                                 :access_rights => clause[:access_rights],
                                 :leaf => leaf,
                                 :level => data[:level] })
          }
        }
      end
    }
  end

  def add_ou_rule(data, leaf=true)
    add_rule(data, true)
  end

  def get_child(elements)
    if !elements
      return self
    end

    if elements.size() > 0
      rdn = elements.last

      if !@children.has_key?(rdn)
        @children[rdn] = DN.new("#{rdn},#{@basedn}")
      end

      @children[rdn].get_child(elements.first(elements.size()-1))
    else
      self
    end
  end

  # Finds all who clauses in rules and rules of the children matching
  # the access rights specified as parameter. If no parameters are given,
  # all who clauses are returned. This can be used to give access e.g. to
  # subou's based on who has access rights to their child objects.

  def who_clauses(filter="")
    child_clauses = @children.values.map {|child|
      child.who_clauses(filter)
    }.flatten.uniq

    clauses = @rules.map {|rule|
      rule.who(filter)
    }.flatten.uniq

    clauses.concat(child_clauses).flatten.uniq
    clauses.delete(nil)
    clauses
  end

  # Pack attributes

  def compact_attrs
    ret = Array.new
    tmp = Hash.new

    @children.keys.sort.each {|key|
      child = @children[key]

      ret.concat(child.compact_attrs())
    }

    # Go through the rules and create a hash containing arrays of who clauses
    # for each attribute.

    @rules.each {|rule|
      key = "#{rule.filter}-#{rule.level}-#{rule.attr}"

      tmp[key] = Array.new if !tmp.has_key?(key)
      tmp[key] << rule
    }

    if @leaf
      # Give access to ou entries
      
      auth_only_clauses = who_clauses("xd").sort
      read_clauses = who_clauses("r").sort

      # If there are no rules for this entry, but only for children, it means in Puavo
      # that this is an intermediary object that should have no direct children. In that
      # case give no write access to children attribute.

      if !@rules.empty?
        write_clauses = who_clauses("az").concat(who_clauses("w")).sort
      else
        write_clauses = Array.new
        read_clauses.concat(who_clauses("az").concat(who_clauses("w"))).sort
      end
      
      write_clauses.each {|clause|
        read_clauses.delete(clause)
        auth_only_clauses.delete(clause)      
      }

      read_clauses.each {|clause|
        auth_only_clauses.delete(clause)
      }

      write_clauses.uniq.each {|clause|
        key = "-exact-children"
        tmp[key] = Array.new if !tmp.has_key?(key)
        
        rule = Rule.new({ :attr => "children",
                          :who => clause,
                          :access_rights => "wrscdx",
                          :level => "exact" })
        tmp[key] << rule
      }
      
      read_clauses.uniq.each {|clause|
        key = "-exact-children"
        tmp[key] = Array.new if !tmp.has_key?(key)

        tmp[key] << Rule.new({ :attr => "children",
                               :who => clause,
                               :access_rights => "rscdx",
                               :level => "exact" })
      }

      read_clauses.concat(write_clauses).uniq.each {|clause|
        exact_key = "-exact-entry"
        onelevel_key = "-onelevel-entry"
        tmp[exact_key] = Array.new if !tmp.has_key?(exact_key)
        tmp[onelevel_key] = Array.new if !tmp.has_key?(onelevel_key)
        
        rule = Rule.new({ :attr => "entry",
                          :level => "exact",
                          :who => clause,
                          :access_rights => "rscdx"
                        })
        tmp[exact_key] << rule

        rule = Rule.new({ :attr => "entry",
                          :level => "onelevel",
                          :who => clause,
                          :access_rights => "rscdx"
                        })
        tmp[onelevel_key] << rule

        exact_key = "-exact-objectClass"
        onelevel_key = "-onelevel-objectClass"
        tmp[exact_key] = Array.new if !tmp.has_key?(exact_key)
        tmp[onelevel_key] = Array.new if !tmp.has_key?(onelevel_key)
        rule = Rule.new({ :attr => "objectClass",
                          :access_rights => "rscdx",
                          :who => clause,
                          :level => "exact" })
        tmp[exact_key] << rule

        rule = Rule.new({ :attr => "objectClass",
                          :access_rights => "rscdx",
                          :who => clause,
                          :level => "onelevel" })

        tmp[onelevel_key] << rule

        if @basedn =~ /(.*?)=(.*?),/
          rdnkey = $1
          key = "-exact-#{rdnkey}"

          tmp[key] = Array.new if !tmp.has_key?(key)
          rule = Rule.new({ :attr => rdnkey,
                            :level => "exact",
                            :who => clause,
                            :access_rights => "rscdx"
                          })
          tmp[key] << rule
        end
      }
    end

    # Clauses are now grouped by attr, next group together attrs that have exactly the same
    # who clauses. This is done using another Hash that has filter + who clauses as key.

    tmp_packed = Hash.new

    tmp.keys.each {|key|
      attr_group = tmp[key]

      # Loop through attributes and store them again with who clauses
      # 
      # filter-attr1-by clause1 x-by clause2 y
      # filter-attr2-by clause1 x-by clause2 y
      # filter-attr3-by clause2 z-by clause3 x
      #
      # filter="filter" attrs="attr1,attr2" by clause1 x by clause2 y
      # filter="filter" attrs="attr3" by clause2 z by clause3 x

      who = Array.new
      rules = Array.new

      attr_group.each {|rule|
        who << rule.to_s
        rules << rule
      }

      key = "#{attr_group.first.filter}-#{attr_group.first.level}-#{who.uniq.sort.join('-')}"
      tmp_packed[key] = Array.new if !tmp_packed.has_key?(key)

      tmp_packed[key] << {
        :filter => attr_group.first.filter,
        :who => who.uniq.sort,
        :attr => attr_group.first.attr,
        :rules => rules,
        :level => attr_group.first.level
      }
    }

    # Now just combine the stuff to a single Array containing the individual lines

    tmp_packed.keys.sort.each {|key|
      group = tmp_packed[key]

      rule = group.first
      attrs = group.map{|data| data[:attr]}.sort.join(',')

      pieces = Array.new

      pieces << "filter=\"#{rule[:filter]}\"" if rule[:filter]
      pieces << "attrs=\"#{attrs}\"" if attrs.length > 0

      group.each {|data|
        pieces.concat(data[:who])
      }

      ret << "to dn.#{rule[:level]}=\"#{@basedn}\" " + pieces.uniq.join(' ') # + " by * +0 break"
    }

    ret
  end

  def to_s
    puts compact_attrs().join("\n")
  end
end

class ACL
  def initialize(suffix)
    @suffix = suffix
    @ous = Hash.new
    @root = DN.new(suffix)
  end

  def get_dn(elements)
    @root.get_child(elements)
  end

  def add_rule(data)
    rdn = get_dn(data[:dn])
    rdn.add_rule(data)
  end

  def add_ou_rule(data)
    rdn = get_dn(data[:dn])
    rdn.add_ou_rule(data)
  end

  def rules
    @root.compact_attrs
  end

  def to_s
    @root.compact_attrs
  end
end

#suffix = "dc=test,dc=dev,dc=edu"
samba_domain = "EDUTEST"

PEOPLE = "ou=People"
GROUPS = "ou=Groups"
ROLES = "ou=Roles"
SCHOOLS = "ou=Schools"
SCHOOLGROUPS = "ou=SchoolGroups"
SAMBA = "ou=Samba"
HOSTS = "ou=Hosts"
PRINTERS = "ou=Printers"

SET_ORG_OWNER = "set=\"[#{suffix}]/owner* & user\""
SET_ALL_SCHOOL_ADMINS = "set=\"user/puavoAdminOfSchool*\""
SET_THIS_SCHOOL_ADMINS = "set=\"this/puavoSchool & user/puavoAdminOfSchool*\""
ALL_USERS = "dn.onelevel=\"ou=People,#{suffix}\""
ALL_HOSTS = "dn.subtree=\"ou=Hosts,#{suffix}\""
ALL_SERVERS = "dn.onelevel=\"ou=Servers,ou=Hosts,#{suffix}\""
SYNCREPL_ACL = "dn.children=\"ou=Servers,ou=Hosts,#{suffix}\""
SLAVE = "dn.exact=\"uid=slave,o=puavo\""
USERS = "users"

SYSTEM_GROUP_AUTH = "group/puavoSystemGroup/member=\"cn=auth,ou=System Groups,#{suffix}\""
SYSTEM_GROUP_GETENT = "group/puavoSystemGroup/member=\"cn=getent,ou=System Groups,#{suffix}\""
SYSTEM_GROUP_PRINTERS = "group/puavoSystemGroup/member=\"cn=printerqueues,ou=System Groups,#{suffix}\""
SYSTEM_GROUP_SERVERS = "group/puavoSystemGroup/member=\"cn=servers,ou=System Groups,#{suffix}\""
SYSTEM_GROUP_DEVICES = "group/puavoSystemGroup/member=\"cn=devices,ou=System Groups,#{suffix}\""
SYSTEM_GROUP_BOOKMARKS = "group/puavoSystemGroup/member=\"cn=bookmarks,ou=System Groups,#{suffix}\""
SYSTEM_GROUP_ORGINFO = "group/puavoSystemGroup/member=\"cn=orginfo,ou=System Groups,#{suffix}\""
SYSTEM_GROUP_ADDRESSBOOK = "group/puavoSystemGroup/member=\"cn=addressbook,ou=System Groups,#{suffix}\""
SYSTEM_GROUP_USERS = "dn.children=\"ou=People,#{suffix}\""
SYSTEM_GROUP_CHECK_VERSION_2 = "set=\"[#{suffix}]/puavoVersion & [2]\""

ANONYMOUS = "anonymous"
READ_ACCESS = "rscdx"
WRITE_ACCESS = "wrscdx"

UID_PUAVO = "dn.exact=\"uid=puavo,o=Puavo\""
SELF = "self"

acl = ACL.new(suffix)

#acl.add_ou_rule({ :dn => [ PEOPLE ],
#                  :filter => "(puavoEduPersonAffiliation=student)",
#                  :attrs => "userPassword",
#                  :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER],
#                  :access_rights => "azx" })

acl.add_ou_rule({ :dn => [ GROUPS ],
                  :filter => "(objectClass=posixGroup)",
                  :attrs => "cn,displayName,gidNumber,member",
                  :clauses => [{
                                :who => [ "dnattr=member" ], # XXX - performance must be evaluated!
                                :access_rights => READ_ACCESS
                               }],
                  :oauth_tokens => [{ :write => "users" }],
                  :oauth_limits => [{
                                      :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER, ALL_SERVERS],
                                      :access_rights => "az"
                                     }],
                  :ou_clauses => [{ :who => [SELF], :access_rights => READ_ACCESS }]
                })

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :filter => "(puavoLocked=TRUE)",
                  :attrs => "userPassword",
#                  :clauses => [{
#                                :who => [SELF],
#                                 :access_rights => "az"
#                               }],
                  :oauth_tokens => [{ :write => "users" }],
                  :oauth_limits => [{
                                      :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER, ALL_SERVERS],
                                      :access_rights => "az"
                                     }],
                  :ou_clauses => [{ :who => [SELF], :access_rights => READ_ACCESS }]
                })

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :filter => "(!(puavoLocked=TRUE))",
                  :attrs => "userPassword",
                  :clauses => [{
                                 :who => [ANONYMOUS],
                                 :access_rights => "dx" },
#                               {
#                                 :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER, ALL_SERVERS],
#                                 :access_rights => "az" }
                               ],
                  :oauth_tokens => [{ :write => "users" }],
                  :oauth_limits => [{
                                      :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER, ALL_SERVERS],
                                      :access_rights => "az"
                                     }],
                  :ou_clauses => [{ :who => [SELF], :access_rights => READ_ACCESS }]
                })

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :attrs => "uid,puavoId,eduPersonPrincipalName,puavoEduPersonAffiliation,uidNumber,gidNumber,homeDirectory,givenName,sn,displayName,puavoEduPersonReverseDisplayName,preferredLanguage,puavoPreferredDesktop",
                   :clauses => [{
                                 :who => [SELF],
                                 :access_rights => READ_ACCESS }]
                })

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :attrs => "givenName,sn,displayName,puavoEduPersonReverseDisplayName",
                  :oauth_limits => [{
                                 :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER],
                                 :access_rights => WRITE_ACCESS }]
                })

#acl.add_ou_rule({ :dn => [ PEOPLE ],
#                  :attrs => "sambaNTPassword,sambaAcctFlags",
#                  :clauses => [{
#                                 :who => [ALL_SERVERS,SET_ALL_SCHOOL_ADMINS],
#                                 :access_rights => "az" }]
#                })
                

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :attrs => "puavoAdminOfSchool",
                  :oauth_limits => [{
                                 :who => [SET_ORG_OWNER],
                                 :access_rights => WRITE_ACCESS }]
                })

#acl.add_ou_rule({ :dn => [ PEOPLE ],
#                  :attrs => "puavoAdminOfSchool",
#                  :clauses => [{
#                                 :who => [USERS],
#                                 :access_rights => READ_ACCESS }]
#                })

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :filter => "(puavoEduPersonAffiliation=student)",
                  :attrs => "shadowLastChange",
                  :oauth_limits => [{
                                 :who => [SET_ORG_OWNER, SET_ALL_SCHOOL_ADMINS],
                                 :access_rights => WRITE_ACCESS }]
                })

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :attrs => "shadowLastChange",
                  :oauth_limits => [{
                                 :who => [SET_ORG_OWNER, SET_ALL_SCHOOL_ADMINS],
                                 :access_rights => READ_ACCESS }]
                })

# uid=puavo,o=puavo needs search access to find the user DN for simple bind

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :attrs => "uid,puavoId,eduPersonPrincipalName,puavoEduPersonAffiliation",
                  :clauses => [{
                                 :who => [UID_PUAVO],
                                 :access_rights => READ_ACCESS }]
                })

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :attrs => "uid,puavoId,eduPersonPrincipalName,puavoEduPersonAffiliation,uidNumber,gidNumber,homeDirectory,givenName,sn,preferredLanguage,puavoPreferredDesktop",
                  :clauses => [{
                                 :who => [ALL_HOSTS],
                                 :access_rights => READ_ACCESS }]
                })

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :attrs => "puavoId,uid,givenName,sn,displayName,puavoEduPersonReverseDisplayName,puavoEduPersonPersonnelNumber,mail,telephoneNumber",
                  :clauses => [{
                                 :who => [SYSTEM_GROUP_ADDRESSBOOK],
                                 :access_rights => READ_ACCESS }]
                })

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :attrs => "uid,uidNumber,gidNumber,homeDirectory,displayName",
                  :clauses => [{
                                 :who => [SYSTEM_GROUP_GETENT],
                                 :access_rights => READ_ACCESS }]
                })

# Users can set their own mail address and telephone number

acl.add_ou_rule({ :dn => [ PEOPLE ],
                  :attrs => "mail,telephoneNumber",
                  :oauth_limits => [{
                                 :who => [SELF],
                                 :access_rights => WRITE_ACCESS }]
                })

acl.add_ou_rule({ :dn => [ ROLES ],
                  :oauth_limits => [{
                                 :who => [SET_THIS_SCHOOL_ADMINS],
                                 :access_rights => WRITE_ACCESS }]
                })

acl.add_ou_rule({ :dn => [ SAMBA, HOSTS ],
                  :clauses => [{
                                 :who => [ALL_SERVERS],
                                 :access_rights => WRITE_ACCESS }]
                })

acl.add_ou_rule({ :dn => [ PRINTERS, HOSTS ],
                  :clauses => [{
                                 :who => [ALL_SERVERS],
                                 :access_rights => WRITE_ACCESS }]
                })

acl.add_rule({ :dn => [ "sambaDomainName=#{samba_domain}" ],
               :clauses => [{
                              :who => [ ALL_SERVERS ],
                              :access_rights => WRITE_ACCESS }]
             })

acl.add_rule({ :clauses => [{
                              :who => [ USERS ],
                              :access_rights => READ_ACCESS }],
               :level => "exact",
               :attrs => "objectClass,entry"
             })

update_acls(suffix, acl)
