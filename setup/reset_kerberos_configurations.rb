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

require 'ruby-debug'

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
kerberos_configuration = KerberosRealm.create_kerberos_configuration(configurations["settings"]["ldap_server"])

# Generate configuration by ldap data
tmp_directory = File.expand_path('kerberos_tmp')
begin
  File.new(tmp_directory)
rescue Errno::ENOENT
  Dir.mkdir(tmp_directory)
end

# Create new konfiguration files to tmp directory
File.open("#{tmp_directory}/kdc.conf", "w") do |file|
  file.write(kerberos_configuration.kdc_conf)
end

File.open("#{tmp_directory}/krb5.conf", "w") do |file|
  file.write(kerberos_configuration.krb5_conf)
end

File.open("#{tmp_directory}/kadm5.acl", "w") do |file|
  file.write(kerberos_configuration.kadm5_acl)
end

File.open("#{tmp_directory}/krb5-kdc", "w") do |file|
  file.write(kerberos_configuration.daemon_args)
end

# Show diff with new and old files
puts "Show differences: #{tmp_directory}/kdc.conf /etc/krb5kdc/kdc.conf"
print `diff #{tmp_directory}/kdc.conf /etc/krb5kdc/kdc.conf`
puts

puts "Show differences: #{tmp_directory}/krb5.conf /etc/krb5.conf"
print `diff #{tmp_directory}/krb5.conf /etc/krb5.conf`
puts

puts "Show differences: #{tmp_directory}/kadm5.acl /etc/krb5kdc/kadm5.acl"
print `diff #{tmp_directory}/kadm5.acl /etc/krb5kdc/kadm5.acl`
puts

puts "Show differences: #{tmp_directory}/krb5-kdc /etc/default/krb5-kdc"
print `diff #{tmp_directory}/krb5-kdc /etc/default/krb5-kdc`
puts

# Replace kerberos configuration files
puts "Replcae kerberson configuration files? (y/n)"
replace = STDIN.gets.chomp

if replace == "y"
  `mv #{tmp_directory}/kdc.conf /etc/krb5kdc/kdc.conf`
  `mv #{tmp_directory}/krb5.conf /etc/krb5.conf`
  `mv #{tmp_directory}/kadm5.acl /etc/krb5kdc/kadm5.acl`
  `mv #{tmp_directory}/krb5-kdc /etc/default/krb5-kdc`
end

puts "Update keytab file"
`../puppet/files/usr/local/sbin/puavo_update_kdc_settings`
