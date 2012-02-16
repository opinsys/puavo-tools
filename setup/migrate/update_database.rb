#!/usr/bin/ruby

require "erb"
require "yaml"
require 'tempfile'

def parse_erb(basename)
  ldif_template = File.read("templates/#{basename}.ldif.erb")
  ldif = ERB.new(ldif_template, 0, "%<>")

  tempfile = Tempfile.open(basename)
  tempfile.puts ldif.result
  tempfile.close
  
  return tempfile
end

suffix_template = "dc=%s,dc=example,dc=edu"

unless template_name = ARGV[0]
  puts "Set template and organisation (update_database.rb <template name> <organisation name>)"
  exit
end

unless organisation_name = ARGV[1]
  puts "Set organisation (update_database.rb <template name> <organisation name>)"
  exit
end

@suffix = "dc=edu,dc=%s,dc=fi" % organisation_name.downcase
host = `host ldap1.opinsys.fi`

puts "LDAP-server: ldap1.opinsys.fi (#{host.split(' ')[3]})"
puts "Update LDAP-database: #{@suffix}"
puts "Continue?"
STDIN.gets

tempfile = parse_erb("add_course_branch")
puts tempfile.path
system("ldapadd -Z -h ldap1.opinsys.fi -D uid=admin,o=puavo -W -f #{tempfile.path}")

