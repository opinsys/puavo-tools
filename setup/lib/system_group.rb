class SystemGroup < LdapOrganisationBase
  ldap_mapping( :dn_attribute => "cn",
                :prefix => "ou=System Groups",
                :classes => ['puavoSystemGroup'])

  def self.create_system_groups
    [ { "cn" => "auth",
        "description" => "Services that have only minimal information needed for ldap simple binds (dn, uid)" },
      { "cn" => "getent", "description" => "Services that have access to all information needed for getent" },
      { "cn" => "printerqueues", "description" => "Services that have access to printer queues" },
      { "cn" => "servers", "description" => "Server information" },
      { "cn" => "devices", "description" => "Client devices" },
      { "cn" => "bookmarks", "description" => "Bookmarks" },
      { "cn" => "orginfo", "description" => "Organisation information" },
      { "cn" => "addressbook", "description" => "Addressbook" } ].
      each do |system_group|
      self.create( system_group )
    end
  end
end


