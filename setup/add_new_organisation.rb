#!/usr/bin/ruby
# -*- coding: utf-8 -*-
#
# Usage: ruby add_new_organisation.rb <organisation name>
#

$LOAD_PATH.unshift( File.join( File.dirname(__FILE__), 'lib' ) )

require 'rubygems'
require 'active_ldap'
require 'optparse'

options = {}
a = OptionParser.new do |opts|
  opts.banner = "Usage: add_new_organisation [options]"

  opts.on("-y", "--yes", "Automatic yes to prompts") do |y|
    options[:yes] = y
  end

  opts.on("-o=ORGANISATION", "Organisation") do |organisation|
    options[:organisation] = organisation
  end

  opts.on("--domain [DOMAIN]", "Domain") do |domain|
    options[:domain] = domain
  end
  opts.on("--organisation_name [ORGANISATION_NAME]", "Organisation name") do |organisation|
    options[:organisation_name] = organisation
  end
  opts.on("--legal_name [LEGAL_NAME]", "Legal name") do |legal_name|
    options[:legal_name] = legal_name
  end
  opts.on("--samba_domain [SAMBA_DOMAIN]", "Samba domain") do |samba_domain|
    options[:samba_domain] = samba_domain
  end
  opts.on("--puppet_host [PUPPET_HOST]", "Puppet host") do |puppet_host|
    options[:puppet_host] = puppet_host
  end
  opts.on("--suffix [SUFFIX]", "Suffix") do |suffix|
    options[:suffix] = suffix
  end

  opts.on("--given_name [GIVEN_NAME]", "Given name") do |given_name|
    options[:given_name] = given_name
  end

  opts.on("--surname [SURNAME]", "Surname") do |surname|
    options[:surname] = surname
  end
  opts.on("--username [USERNAME]", "Username") do |username|
    options[:username] = username
  end
  opts.on("--password [PASSWORD]", "Password") do |password|
    options[:password] = password
  end
  opts.on_tail("-h", "--help", "Show this message") do
    puts opts
    exit
  end
end.parse!

unless options.has_key?(:organisation)
  puts "Required option --organisation missing"
  exit
end

# LDAP configuration
if configurations = YAML.load_file("config/ldap.yml") rescue nil
  ActiveLdap::Base.configurations = configurations
else
  puts "Not found LDAP configuration file (config/ldap.yml)"
  exit
end

require 'ldap_organisation_base'
require 'admin_user'
require 'automount'
require 'database'
require 'samba_group'
require 'samba_sid_group'
require 'organisation'
require 'organizational_unit'
require 'samba'
require 'overlay'
require 'system_group'
require 'users/ldap_base'
require 'users/base_group'
require 'users/school'
require 'users/role'
require 'users/group'
require 'users/user_error'
require 'users/user'
require 'users/samba_domain'
require 'users/ldap_organisation'
require 'kerberos'

def newpass( len )
  chars = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
  newpass = ""
  1.upto(len) { |i| newpass << chars[rand(chars.size-1)] }
  return newpass
end

puppet_host_template = configurations["settings"]["templates"]["puppet_host"]
samba_domain_template = configurations["settings"]["templates"]["samba_domain"]
suffix_template = configurations["settings"]["templates"]["suffix"]
domain_template = configurations["settings"]["templates"]["domain"]

# This needs to be cleaned up once the actual settings and needs
# have been figured out

orgname = options[:organisation]
domain = options.has_key?(:domain) ? options[:domain] : domain_template % orgname.downcase 

suffix = options.has_key?(:suffix) ? options[:suffix] : suffix_template % orgname.downcase
suffix_start = suffix.split(',')[0]
organisation_name = options.has_key?(:organisation_name) ? options[:organisation_name] : orgname 
legal_name = options.has_key?(:legal_name) ? options[:legal_name] : organisation_name

puppet_host = options.has_key?(:puppet_host) ? options[:puppet_host] : puppet_host_template % orgname.downcase
samba_domain = options.has_key?(:samba_domain) ? options[:samba_domain] : samba_domain_template % orgname.upcase
#puts "Usage: $0 orgname [domain_name] [Organisation name] [Legal name] [samba domain] [puppet host] [suffix]"

puts "******************************************************"
puts "  Initialising organisation: #{organisation_name}"
puts "******************************************************"

kerberos_realm = domain.upcase
rootDN = configurations["settings"]["ldap_server"]["bind_dn"]

puts "* Creating database for suffix: #{suffix}"
puts "* Kerberos realm: #{kerberos_realm}"
puts "* Legal name: #{legal_name}"
puts "* Samba: #{samba_domain}"
puts "* Domain: #{domain}"
puts "* Puppet host: #{puppet_host}"
puts "* Suffix start: #{suffix_start}"

Readline.readline('OK?', true) unless options[:yes]
begin
  new_db = Database.new( "olcSuffix" => suffix,
                         "olcRootDN" => rootDN,
                         :samba_domain => samba_domain,
                         :kerberos_realm => kerberos_realm )
  # Save without validation
  new_db.save(false)
rescue => e
  raise e
end

new_db = Database.find(:first, :attribute => 'olcSuffix', :value => suffix)

puts "* Setting up overlay configuration to database"
Overlay.create_overlays(:database => new_db,
                        :kerberos_realm => kerberos_realm)

if ActiveLdap::Base.configurations["settings"]["syncrepl"]["nodes"]
  puts "* Setting up replication configuration"
  new_db.set_replication_settings
end

# Create organisation and set LdapOrganisationBase LDAP connection
puts "* Create organisation root"
organisation = Organisation.create( :owner => configurations["settings"]["ldap_server"]["bind_dn"],
                                    :suffix => suffix,
                                    :puavoDomain => domain,
                                    :puavoKerberosRealm => kerberos_realm,
                                    :o => organisation_name,
                                    :cn => organisation_name,
                                    :description => organisation_name,
                                    :eduOrgLegalName => legal_name,
                                    :puavoPuppetHost => puppet_host,
                                    :sambaDomainName => samba_domain )

puts "* Add organizational units: People, Groups, Hosts, Automount, etc..."
OrganizationalUnit.create_units(organisation)

puts "* Setting up Autofs configuration"
Automount.create_automount_configuration

puts "* Setting up Samba configuration"
Samba.create_samba_configuration(organisation_name, samba_domain, suffix_start)

puts "* Create System Groups"
SystemGroup.create_system_groups

puts "* Add admin users: kdc, kadmin, samba"
AdminUser.create_admin_user

# School
school = School.first
puts "\nCreate new school"
school_name = "Administration"
puts "School name: #{school_name}" 
school = School.create!( :displayName => school_name,
                         :cn => school_name.downcase.gsub(/[^a-z0-9]/, "") )

# Role
puts "Create new role"
role_name = "Maintenance"
puts "Role name: #{role_name}"
role = Role.create!( :displayName => role_name,
                    :puavoSchool => school.dn )

# Group
puts "Create new group"
group_name = "Maintenance"
puts "Group name: #{group_name}"
group = Group.create!( :displayName => group_name,
                      :cn => group_name.downcase.gsub(/[^a-z0-9]/, ""),
                      :puavoSchool => school.dn )

# Added association
role.groups << group

# Create kerberos realm

#`mkdir -p /etc/krb5kdc/masterkeys`
#`chmod 0700 /etc/krb5kdc/masterkeys`

`echo "#{configurations["settings"]["kdc"]["password"]}\\n#{configurations["settings"]["kdc"]["password"]}\\n" | /usr/sbin/kdb5_ldap_util stashsrvpw -f /etc/krb5.secrets "#{configurations["settings"]["kdc"]["bind_dn"]}" 2>/dev/null`
`echo "#{configurations["settings"]["kadmin"]["password"]}\\n#{configurations["settings"]["kadmin"]["password"]}\\n" | /usr/sbin/kdb5_ldap_util stashsrvpw -f /etc/krb5.secrets "#{configurations["settings"]["kadmin"]["bind_dn"]}" 2>/dev/null`

kerberos_masterpw = newpass(20)
puts "Initializing kerberos realm with master key: #{kerberos_masterpw}"

realm = KerberosRealm.new( :ldap_server => configurations["settings"]["ldap_server"],
                           :realm => kerberos_realm,
                           :masterpw => kerberos_masterpw,
                           :suffix => suffix,
                           :domain => domain )

conf = KerberosRealm.create_kerberos_configuration(configurations["settings"]["ldap_server"])

File.open("/etc/krb5kdc/kdc.conf", "w") {|file|
        file.write(conf.kdc_conf)
}

File.open("/etc/krb5.conf", "w") {|file|
        file.write(conf.krb5_conf)
}

File.open("/etc/krb5kdc/kadm5.acl", "w") {|file|
        file.write(conf.kadm5_acl)
}

File.open("/etc/default/krb5-kdc", "w") {|file|
        file.write(conf.daemon_args)
}

realm.create_ldap_tree

puts configurations["settings"]["puppetmaster"]["enable"]

if configurations["settings"]["puppetmaster"]["enable"]
  `mkdir -p #{configurations["settings"]["puppetmaster"]["file_dir"]}/etc/krb5kdc/`
  `mkdir -p #{configurations["settings"]["puppetmaster"]["file_dir"]}/etc/default/`
  `cp /etc/krb5kdc/* #{configurations["settings"]["puppetmaster"]["file_dir"]}/etc/krb5kdc/`
  `cp /etc/krb5.conf #{configurations["settings"]["puppetmaster"]["file_dir"]}/etc/`
  `cp /etc/krb5.secrets #{configurations["settings"]["puppetmaster"]["file_dir"]}/etc/`
  `cp /etc/default/krb5-kdc #{configurations["settings"]["puppetmaster"]["file_dir"]}/etc/default/krb5-kdc`
  `chown -R puppet #{configurations["settings"]["puppetmaster"]["file_dir"]}/*`

  puts "Puppet kerberos files updated"
else
  puts "Puppet configuration disabled"
end

# User
puts "Create organisation owner:"

print "Given name: "
given_name = options.has_key?(:given_name) ? options[:given_name] : STDIN.gets.chomp

print "Surname: "
surname = options.has_key?(:surname) ? options[:surname] : STDIN.gets.chomp
print "Username: "
username = options.has_key?(:username) ? options[:username] : STDIN.gets.chomp
if options.has_key?(:password)
  password = options[:password]
else
  system('stty','-echo');
  print "Password: "
  password = STDIN.gets.chomp
  print "\nPassword confirmation: "
  password_confirmation = STDIN.gets.chomp
  system('stty','echo');
end

user = User.new

user.givenName = given_name
user.sn = surname
user.uid = username
user.new_password = password
user.new_password_confirmation = password_confirmation
user.role_name = role.displayName
user.puavoSchool = school.dn
user.puavoEduPersonAffiliation = "admin"
user_save = false
while user_save != true
  begin
    user.save!
    user_save = true
  rescue Exception => e
    if options[:yes]
      raise e
    else
      puts
      puts e
      puts "Cannot save user, press enter to try again"
      STDIN.gets
    end
  end
end

domain_admin = SambaGroup.find("Domain Admins")
domain_admin.memberUid = user.uid
domain_admin.save!

puts
puts "User was successfully created."
puts "\nSets the user (#{user.uid}) as the owner of the organisation"
ldap_organisation = LdapOrganisation.first
ldap_organisation.owner = Array(ldap_organisation.owner).push user.dn
ldap_organisation.save

