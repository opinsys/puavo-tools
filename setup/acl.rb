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
      "by #{who} +#{@access_rights} continue"
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

  def add_rule(data)
    attrs = Array.new

    if data[:attrs]
      attrs = data[:attrs].split(',')
    else
      attrs << "@extensibleObject"
    end

    attrs.each {|attr|
      data[:who].each {|who|
        @rules << Rule.new({ :dn => @basedn,
                             :filter => data[:filter],
                             :attr => attr,
                             :who => who,
                             :access_rights => data[:access_rights] })
      }
    }
  end

  def get_child(elements)
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

    @children.keys.sort.each {|key|
      child = @children[key]

      ret.concat(child.compact_attrs())
    }

    tmp = Hash.new

    # Go through the rules and create a hash containing arrays of who clauses
    # for each attribute.

    @rules.each {|rule|
      key = "#{rule.filter}-#{rule.level}-#{rule.attr}"

      tmp[key] = Array.new if !tmp.has_key?(key)
      tmp[key] << rule
    }

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

      rule = Rule.new({ :attr => "children",
                        :who => clause,
                        :access_rights => "rscdx",
                        :level => "exact" })
      tmp[key] << rule
    }

    read_clauses.concat(write_clauses).uniq.each {|clause|
      key = "-exact-entry"
      tmp[key] = Array.new if !tmp.has_key?(key)

      rule = Rule.new({ :attr => "entry",
                        :who => clause,
                        :access_rights => "rscdx",
                        :level => "exact" })
      tmp[key] << rule

      key = "-exact-objectClass"
      tmp[key] = Array.new if !tmp.has_key?(key)
      rule = Rule.new({ :attr => "objectClass",
                        :who => clause,
                        :access_rights => "rscdx",
                        :level => "exact" })

      tmp[key] << rule

      if @basedn =~ /(.*?)=(.*?),/
        rdnkey = $1
        key = "-exact-#{rdnkey}"

        tmp[key] = Array.new if !tmp.has_key?(key)
        rule = Rule.new({ :attr => rdnkey,
                          :who => clause,
                          :access_rights => "rscdx",
                          :level => "exact"})
        tmp[key] << rule
      end
    }

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

      ret << "to dn.#{rule[:level]}=\"#{@basedn}\" " + pieces.uniq.join(' ')
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

  def to_s
    @root.compact_attrs
  end
end

suffix = "dc=test,dc=dev,dc=edu"

PEOPLE = "ou=People"
GROUPS = "ou=Groups"
SCHOOLS = "ou=Schools"
SCHOOLGROUPS = "ou=SchoolGroups"
SAMBA = "ou=Samba"
HOSTS = "ou=Hosts"

SET_ORG_OWNER = "set=\"[#{suffix}]/owner* & user\""
SET_ALL_SCHOOL_ADMINS = "set=\"user/puavoAdminOfSchool*\""
SET_THIS_SCHOOL_ADMINS = "set=\"this/puavoSchool & user/puavoAdminOfSchool*\""
ALL_USERS = "dn.onelevel=\"ou=People,#{suffix}\""
ALL_HOSTS = "dn.subtree=\"ou=Hosts,#{suffix}\""
ALL_SERVERS = "dn.onelevel=\"ou=Servers,ou=Hosts,#{suffix}\""
SYNCREPL_ACL = "dn.children=\"ou=Servers,ou=Hosts,#{suffix}\""
SLAVE = "dn.exact=\"uid=slave,o=puavo\""

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

acl = ACL.new(suffix)

acl.add_rule({ :dn => [SCHOOLS, GROUPS],
               :filter => "(objectClass=posixGroup)",
               :attrs => "userPassword",
               :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER],
               :access_rights => "azx" })

acl.add_rule({ :dn => [ PEOPLE ],
               :filter => "(puavoEduPersonAffiliation=student)",
               :attrs => "userPassword",
               :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER],
               :access_rights => "azx" })

acl.add_rule({ :dn => [ PEOPLE ],
               :filter => "(puavoLocked=TRUE)",
               :attrs => "userPassword",
               :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER],
               :access_rights => "az" })

acl.add_rule({ :dn => [ PEOPLE ],
               :filter => "(!(puavoLocked=TRUE))",
               :attrs => "userPassword",
               :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER, ANONYMOUS],
               :access_rights => "dx" })

acl.add_rule({ :dn => [ PEOPLE ],
               :attrs => "givenName,sn,displayName,puavoEduPersonReverseDisplayName",
               :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER],
               :access_rights => "wrscdx" })

acl.add_rule({ :dn => [ PEOPLE ],
               :attrs => "testi",
#               :who => [SET_ALL_SCHOOL_ADMINS, SET_ORG_OWNER],
               :who => ["set=desti", SET_ALL_SCHOOL_ADMINS],
               :access_rights => "rscdx" })

acl.add_rule({ :dn => [ PEOPLE ],
               :attrs => "sambaNTPassword,userPassword,sambaAcctFlags",
               :who => [ALL_SERVERS,SET_ALL_SCHOOL_ADMINS],
               :access_rights => "az" })

acl.add_rule({ :dn => [ SAMBA, HOSTS ],
               :who => [ALL_SERVERS],
               :access_rights => WRITE_ACCESS })

puts acl.to_s
