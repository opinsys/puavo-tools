#!/usr/bin/ruby
#
# Create new kerberos configurations by ldap
#
# Usage: ruby reset_kerberos_configuration.rb
#

$LOAD_PATH.unshift( File.join( File.dirname(__FILE__), 'lib' ) )

require 'rubygems'
require 'active_ldap'
require 'optparse'
require 'readline'
require 'kerberos'
#require 'ruby-debug'

# LDAP configuration
if configurations = YAML.load_file("config/ldap.yml") rescue nil
  ActiveLdap::Base.configurations = configurations
else
  puts "Not found LDAP configuration file (config/ldap.yml)"
  exit
end

# Set password for kadmin and kdc users

`echo "#{configurations["settings"]["kdc"]["password"]}\\n#{configurations["settings"]["kdc"]["password"]}\\n" | /usr/sbin/kdb5_ldap_util stashsrvpw -f /etc/krb5.secrets "#{configurations["settings"]["kdc"]["bind_dn"]}" 2>/dev/null`

`echo "#{configurations["settings"]["kadmin"]["password"]}\\n#{configurations["settings"]["kadmin"]["password"]}\\n" | /usr/sbin/kdb5_ldap_util stashsrvpw -f /etc/krb5.secrets "#{configurations["settings"]["kadmin"]["bind_dn"]}" 2>/dev/null`

# Get kerberos configuration from ldap (all organisation)
kerberos_configuration = KerberosSettings.new(:ldap_server => configurations["settings"]["ldap_server"])

kerberos_configuration.write_configurations_to_file

# Check organisations keytab files

# Show diff with new and old files
kerberos_configuration.diff

puts "Generate new keytab file"
kerberos_configuration.generate_new_keytab_file


# Replace kerberos configuration files
puts "Replace kerberos configuration files? (y/n)"
replace = STDIN.gets.chomp
if replace == "y"
  puts "\nStop krb5-kdc and kadmind services\n\n"
  `/etc/init.d/krb5-kdc stop`
  `/etc/init.d/puavo_kadmind stop`

  kerberos_configuration.replace_server_configurations

  kerberos_configuration.replace_keytab_file
  
  puts "\nStart krb5-kdc and kadmind services\n\n"
  `/etc/init.d/krb5-kdc start`
  `/etc/init.d/puavo_kadmind start`
end

