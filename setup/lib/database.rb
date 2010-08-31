require 'id_pool'

class Database < ActiveLdap::Base
  ldap_mapping( :dn_attribute => "olcDatabase",
                :prefix => "",
                :classes => ['olcDatabaseConfig', 'olcHdbConfig'] )

  before_save :set_attribute_values

  def initialize(args)
    ActiveLdap::Base.setup_connection( configurations["first_node"].merge( "base" => "cn=config" ) )
    super
  end

  def set_attribute_values
    self.olcDatabase = 'hdb'
    self.olcDbConfig = ['set_cachesize 0 2097152 0',
                        'set_lk_max_objects 1500',
                        'set_lk_max_locks 1500',
                        'set_lk_max_lockers 1500' ]
    self.olcLastMod = 'TRUE'
    self.olcDbCheckpoint = '512 30'
    self.olcDbIndex = ['uid pres,eq',
                       'cn,sn,mail pres,eq,approx,sub',
                       'objectClass eq' ]
    self.olcDbDirectory = "/var/lib/ldap/db#{next_directory_id}"
    self.olcMirrorMode = 'TRUE'

    # Database ACLs
    suffix = self.olcSuffix
    template = File.read("templates/database_acl.erb")
    self.olcAccess = ERB.new(template, 0, "%<>").result(binding).split("\n")

    # Replication settings
    rootdn = ActiveLdap::Base.configurations["first_node"]["bind_dn"]
    rootpw = ActiveLdap::Base.configurations["first_node"]["password"]
    servers = Array.new
    servers.push ActiveLdap::Base.configurations["first_node"]["host"]
    servers += ActiveLdap::Base.configurations["other_nodes"]["hosts"] if ActiveLdap::Base.configurations["other_nodes"]
    _olcSyncRepl = Array.new
    servers.each_index do |index|
      _olcSyncRepl.push "{#{index}}rid=#{ "%03d" % IdPool.next_id('puavoNextRid') } provider=ldap://#{ servers[index] } " +
        "bindmethod=simple binddn=#{ rootdn } credentials=#{ rootpw } " +
        "searchbase=#{self.olcSuffix} type=refreshAndPersist retry=\"15 +\""
    end
    self.olcSyncRepl = _olcSyncRepl
  end

  def next_directory_id
    id_pool = IdPool.find('IdPool')
    next_id = id_pool.puavoNextDatabaseId
    id_pool.puavoNextDatabaseId = next_id + 1
    id_pool.save
    return "%03d" % next_id
  end
end
