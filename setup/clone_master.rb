#!/usr/bin/ruby
#
# This script connects to LDAP master and reads all its configuration
# and database data. Data is written to local database.
#

require "erb"
require 'tempfile'
require 'fileutils'
require 'readline'

unless organisation_name = ARGV.first
  puts "Set organisation (clone_master.rb example) or use --all arguments (clone_master.rb --all)"
  exit
end

@binddn = "uid=admin,o=Puavo"

puts "Master server:"
@master_server = Readline.readline('> ', true)

puts "uid=admin,o=puavo password:"
@bindpw = Readline.readline('> ', true)

`/etc/init.d/slapd stop`
`killall -9 slapd`
`rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*`

tempfile = Tempfile.open("ldif")

config = `ldapsearch -LLL -x -H #{ @master_server } -D #{ @binddn } -w #{ @bindpw } -Z -b cn=config`
config.each_line {|line|
  if !/olcDbConfig\:/.match(line) and !/olcDbIndex:/.match(line)
    tempfile.puts line
  end

  if /objectClass: olcHdbConfig/.match(line)
    tempfile.puts "olcDbConfig: {0}set_cachesize 0 10485760 0"
    tempfile.puts "olcDbConfig: {1}set_lg_bsize 2097512"
    tempfile.puts "olcDbConfig: {2}set_flags DB_LOG_AUTOREMOVE"
    tempfile.puts "olcDbIndex: sambaSID pres,eq"
    tempfile.puts "olcDbIndex: sambaSIDList pres,eq"
    tempfile.puts "olcDbIndex: sambaGroupType pres,eq"
    tempfile.puts "olcDbIndex: uniqueMember pres,eq"
    tempfile.puts "olcDbIndex: puavoTag pres,eq"
    tempfile.puts "olcDbIndex: puavoDeviceType pres,eq"
    tempfile.puts "olcDbIndex: puavoHostname pres,eq"
    tempfile.puts "olcDbIndex: uid pres,eq"
    tempfile.puts "olcDbIndex: krbPrincipalName pres,eq"
    tempfile.puts "olcDbIndex: cn,sn,mail pres,eq,approx,sub"
    tempfile.puts "olcDbIndex: objectClass eq"
    tempfile.puts "olcDbIndex: entryUUID eq"
    tempfile.puts "olcDbIndex: entryCSN eq"
  end
}
tempfile.close

config.split("\n").each do |line|
  if line =~ /olcDbDirectory: (.*)/
#    puts "DIR: #{$1}"
    `mkdir #{$1}`
  end
end

puts "Importing cn=config"

system("slapadd -q -l #{tempfile.path} -F /etc/ldap/slapd.d -b 'cn=config'") \
  or raise 'Problem in importing ldap configuration'

contexts = `ldapsearch -LLL -x -H #{@master_server} -D #{@binddn} -w #{@bindpw} -s base -b "" "(objectclass=*)" namingContexts -Z`

@counter = 1;

contexts.split("\n").each do |line|
  if (line =~ /namingContexts: (.*)/)
    suffix = $1.to_s
    if organisation_name == "--all" ||
        suffix[/dc=edu,dc=#{organisation_name},dc=fi/] ||
        suffix== "o=puavo"

      puts "suffix: #{suffix}"
      data = `ldapsearch -LLL -x -H #{ @master_server } -D #{ @binddn } -w #{ @bindpw } -Z -b #{suffix}`

      tempfile = Tempfile.open("data")
      tempfile.puts data
      tempfile.close
      
      system("slapadd -q -l #{tempfile.path} -F /etc/ldap/slapd.d -b '#{suffix}'") \
      or raise 'Problem in importing data'

      system("slapindex -b #{suffix}")
    end
  end
end

`chown -R openldap.openldap /etc/ldap/slapd.d /var/lib/ldap`
`chmod -R 0750 /var/lib/ldap`

`/etc/init.d/slapd start`

system('chown -R openldap.openldap /etc/ldap/slapd.d /var/lib/ldap') \
  or raise 'could not chown /etc/ldap/slapd.d /var/lib/ldap to openldap user'

system('chmod -R 0750 /var/lib/ldap') \
  or raise 'could not chmod /var/lib/ldap'

system('service slapd start') \
  or raise 'slapd start failed'
