# frozen_string_literal: true

require "ipaddr"
require "yaml"

module M4jTopology
  class Error < StandardError; end

  EXPECTED_ROLES = %w[management trust agents gateway ot simulation].freeze
  EXPECTED_NETWORKS = {
    "management" => {
      "kind" => "host_only",
      "purpose" => "ssh_control_only",
      "members" => EXPECTED_ROLES,
    },
    "trust_enrollment" => {
      "kind" => "virtualbox_internal",
      "purpose" => "workload_identity_enrollment",
      "members" => %w[trust agents gateway ot simulation],
    },
    "agent_lane" => {
      "kind" => "virtualbox_internal",
      "purpose" => "agent_to_gateway_only",
      "members" => %w[agents gateway],
    },
    "control_dmz" => {
      "kind" => "virtualbox_internal",
      "purpose" => "trusted_control_services",
      "members" => %w[trust gateway ot],
    },
    "simulation_lane" => {
      "kind" => "virtualbox_internal",
      "purpose" => "plant_access_only",
      "members" => %w[trust ot simulation],
    },
  }.freeze

  TOP_LEVEL_KEYS = %w[
    schema_version
    deployment_status
    claim_boundary
    box
    bootstrap_nat
    capacity
    addressing
    networks
    nodes
  ].freeze
  BOX_KEYS = %w[name version provider check_update].freeze
  BOOTSTRAP_NAT_KEYS = %w[enabled purpose application_bindings_allowed guest_ssh_port].freeze
  CAPACITY_KEYS = %w[
    max_total_cpus
    max_total_memory_mb
    max_node_cpus
    max_node_memory_mb
  ].freeze
  ADDRESSING_KEYS = %w[ipv4_prefix_length first_node_host_offset].freeze
  NETWORK_KEYS = %w[cidr kind purpose gateway internal_name members].freeze
  NODE_KEYS = %w[hostname cpus memory_mb interfaces].freeze

  module_function

  def mapping!(value, keys, label)
    raise Error, "#{label} must be a mapping" unless value.is_a?(Hash)

    missing = keys - value.keys
    extra = value.keys - keys
    return value if missing.empty? && extra.empty?

    details = []
    details << "missing=#{missing.sort.join(',')}" unless missing.empty?
    details << "extra=#{extra.sort.join(',')}" unless extra.empty?
    raise Error, "#{label} has invalid fields (#{details.join('; ')})"
  end

  def nonempty_string!(value, label)
    unless value.is_a?(String) && !value.empty? && value == value.strip
      raise Error, "#{label} must be a non-empty trimmed string"
    end
    value
  end

  def positive_integer!(value, label)
    raise Error, "#{label} must be a positive integer" unless value.is_a?(Integer) && value.positive?

    value
  end

  def parse_ipv4!(value, label)
    address = IPAddr.new(nonempty_string!(value, label))
    raise Error, "#{label} must be IPv4" unless address.ipv4?

    address
  rescue IPAddr::InvalidAddressError => e
    raise Error, "#{label} is invalid: #{e.message}"
  end

  def load(path)
    raw = YAML.safe_load(
      File.read(path, encoding: "UTF-8"),
      permitted_classes: [],
      permitted_symbols: [],
      aliases: false,
      filename: path.to_s,
    )
    validate!(raw)
    raw
  rescue Errno::ENOENT, Errno::EACCES, Psych::Exception => e
    raise Error, "M4j topology could not be loaded: #{e.message}"
  end

  def validate!(raw)
    topology = mapping!(raw, TOP_LEVEL_KEYS, "M4j topology")
    unless topology["schema_version"] == "aegis-ot-m4j-topology-v1"
      raise Error, "unsupported M4j topology schema"
    end
    unless topology["deployment_status"] == "configuration_only"
      raise Error, "M4j deployment status must remain configuration_only"
    end
    unless topology["claim_boundary"] == "no_live_deployment_or_multi_host_isolation_evidence"
      raise Error, "M4j claim boundary is missing or broadened"
    end

    validate_box!(topology["box"])
    validate_bootstrap_nat!(topology["bootstrap_nat"])
    capacity = validate_capacity!(topology["capacity"])
    addressing = validate_addressing!(topology["addressing"])
    networks, network_objects = validate_networks!(topology["networks"], addressing)
    validate_nodes!(topology["nodes"], networks, network_objects, addressing, capacity)
    topology
  end

  def validate_box!(value)
    box = mapping!(value, BOX_KEYS, "M4j box")
    name = nonempty_string!(box["name"], "M4j box name")
    version = nonempty_string!(box["version"], "M4j box version")
    unless name.match?(%r{\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z})
      raise Error, "M4j box name must be an exact registry owner/name"
    end
    unless version.match?(/\A\d+\.\d+\.\d+\z/)
      raise Error, "M4j box version must be an exact three-part version"
    end
    raise Error, "M4j provider must be virtualbox" unless box["provider"] == "virtualbox"
    raise Error, "M4j box update checks must be disabled" unless box["check_update"] == false
  end

  def validate_bootstrap_nat!(value)
    nat = mapping!(value, BOOTSTRAP_NAT_KEYS, "M4j bootstrap NAT")
    raise Error, "default NAT must remain enabled for Vagrant bootstrap" unless nat["enabled"] == true
    unless nat["purpose"] == "vagrant_bootstrap_only"
      raise Error, "default NAT must be tagged vagrant_bootstrap_only"
    end
    unless nat["application_bindings_allowed"] == false
      raise Error, "application bindings are prohibited on bootstrap NAT"
    end
    raise Error, "bootstrap NAT permits guest SSH only" unless nat["guest_ssh_port"] == 22
  end

  def validate_capacity!(value)
    capacity = mapping!(value, CAPACITY_KEYS, "M4j capacity")
    CAPACITY_KEYS.each do |key|
      positive_integer!(capacity[key], "M4j capacity #{key}")
    end
    if capacity["max_node_cpus"] > capacity["max_total_cpus"] ||
       capacity["max_node_memory_mb"] > capacity["max_total_memory_mb"]
      raise Error, "M4j per-node capacity cannot exceed the total envelope"
    end
    capacity
  end

  def validate_addressing!(value)
    addressing = mapping!(value, ADDRESSING_KEYS, "M4j addressing policy")
    prefix = positive_integer!(addressing["ipv4_prefix_length"], "IPv4 prefix length")
    raise Error, "M4j networks must use /24 prefixes" unless prefix == 24

    first_host = positive_integer!(addressing["first_node_host_offset"], "first node host offset")
    unless first_host >= 2 && first_host + EXPECTED_ROLES.length - 1 < 255
      raise Error, "M4j node host offsets overlap reserved addresses"
    end
    addressing
  end

  def validate_networks!(value, addressing)
    networks = mapping!(value, EXPECTED_NETWORKS.keys, "M4j networks")
    unless networks.keys == EXPECTED_NETWORKS.keys
      raise Error, "M4j networks must use deterministic contract order"
    end

    parsed = {}
    internal_names = []
    networks.each do |name, raw_network|
      network = mapping!(raw_network, NETWORK_KEYS, "M4j network #{name}")
      expected = EXPECTED_NETWORKS.fetch(name)
      unless network["kind"] == expected["kind"] &&
             network["purpose"] == expected["purpose"] &&
             network["members"] == expected["members"]
        raise Error, "M4j network #{name} boundary differs from the closed contract"
      end

      cidr = nonempty_string!(network["cidr"], "M4j network #{name} CIDR")
      parsed_network = parse_ipv4!(cidr, "M4j network #{name} CIDR")
      canonical_cidr = "#{parsed_network}/#{parsed_network.prefix}"
      unless parsed_network.private? &&
             parsed_network.prefix == addressing["ipv4_prefix_length"] &&
             cidr == canonical_cidr
        raise Error, "M4j network #{name} must be a canonical private /24"
      end
      parsed[name] = parsed_network

      gateway = network["gateway"]
      internal_name = network["internal_name"]
      if name == "management"
        parsed_gateway = parse_ipv4!(gateway, "M4j management gateway")
        first_usable = IPAddr.new(parsed_network.to_i + 1, Socket::AF_INET)
        unless parsed_network.include?(parsed_gateway) && parsed_gateway == first_usable
          raise Error, "M4j management gateway must be the first usable subnet address"
        end
        raise Error, "management network cannot have an internal-network name" unless internal_name.nil?
      else
        raise Error, "M4j data lanes must not define a routed gateway" unless gateway.nil?
        internal = nonempty_string!(internal_name, "M4j network #{name} internal name")
        unless internal.match?(/\A[a-z0-9][a-z0-9-]{0,62}\z/)
          raise Error, "M4j network #{name} has an unsafe VirtualBox internal name"
        end
        internal_names << internal
      end
    end

    if internal_names.uniq.length != internal_names.length
      raise Error, "VirtualBox internal network names must be unique"
    end
    parsed.to_a.combination(2) do |(left_name, left), (right_name, right)|
      if left.include?(right.to_range.first) || right.include?(left.to_range.first)
        raise Error, "M4j networks overlap: #{left_name}, #{right_name}"
      end
    end
    [networks, parsed]
  end

  def validate_nodes!(value, networks, network_objects, addressing, capacity)
    nodes = mapping!(value, EXPECTED_ROLES, "M4j nodes")
    raise Error, "M4j nodes must use deterministic role order" unless nodes.keys == EXPECTED_ROLES

    seen_addresses = {}
    total_cpus = 0
    total_memory = 0
    nodes.each_with_index do |(role, raw_node), role_index|
      node = mapping!(raw_node, NODE_KEYS, "M4j node #{role}")
      expected_hostname = "aegis-#{role}"
      unless node["hostname"] == expected_hostname
        raise Error, "M4j node #{role} hostname must be #{expected_hostname}"
      end
      cpus = positive_integer!(node["cpus"], "M4j node #{role} CPUs")
      memory = positive_integer!(node["memory_mb"], "M4j node #{role} memory")
      if cpus > capacity["max_node_cpus"] || memory > capacity["max_node_memory_mb"]
        raise Error, "M4j node #{role} exceeds the per-node capacity envelope"
      end
      raise Error, "M4j node memory must use 256 MiB increments" unless (memory % 256).zero?

      total_cpus += cpus
      total_memory += memory
      expected_interfaces = EXPECTED_NETWORKS.each_with_object([]) do |(network_name, network_contract), names|
        names << network_name if network_contract["members"].include?(role)
      end
      interfaces = mapping!(node["interfaces"], expected_interfaces, "M4j node #{role} interfaces")
      unless interfaces.keys == expected_interfaces
        raise Error, "M4j node #{role} interfaces must use deterministic network order"
      end
      interfaces.each do |network_name, raw_address|
        address = parse_ipv4!(raw_address, "M4j node #{role} #{network_name} address")
        if seen_addresses.key?(address.to_s)
          raise Error, "duplicate M4j node IP: #{address}"
        end
        network = network_objects.fetch(network_name)
        expected_address = IPAddr.new(
          network.to_i + addressing["first_node_host_offset"] + role_index,
          Socket::AF_INET,
        )
        unless network.include?(address) && address == expected_address && raw_address == address.to_s
          raise Error, "M4j node #{role} #{network_name} address is unsafe or nondeterministic"
        end
        seen_addresses[address.to_s] = "#{role}/#{network_name}"
      end
    end

    if total_cpus > capacity["max_total_cpus"] || total_memory > capacity["max_total_memory_mb"]
      raise Error, "M4j nodes exceed the declared total capacity envelope"
    end

    networks.each do |network_name, network|
      configured_members = nodes.each_with_object([]) do |(role, node), members|
        members << role if node["interfaces"].key?(network_name)
      end
      unless configured_members == network["members"]
        raise Error, "M4j network #{network_name} membership and node interfaces disagree"
      end
    end
  end
end

topology_path = File.join(__dir__, "infra", "m4j", "topology.yml")
topology = M4jTopology.load(topology_path)
box = topology.fetch("box")
networks = topology.fetch("networks")

Vagrant.configure("2") do |config|
  config.vm.box = box.fetch("name")
  config.vm.box_version = box.fetch("version")
  config.vm.box_check_update = box.fetch("check_update")
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.provider box.fetch("provider")

  topology.fetch("nodes").each do |role, specification|
    config.vm.define role do |node|
      node.vm.hostname = specification.fetch("hostname")
      specification.fetch("interfaces").each do |network_name, address|
        network = networks.fetch(network_name)
        options = {
          ip: address,
          netmask: "255.255.255.0",
          auto_config: true,
        }
        if network.fetch("kind") == "virtualbox_internal"
          options[:virtualbox__intnet] = network.fetch("internal_name")
        end
        node.vm.network "private_network", **options
      end

      node.vm.provider box.fetch("provider") do |provider|
        provider.name = "aegis-m4j-#{role}"
        provider.cpus = specification.fetch("cpus")
        provider.memory = specification.fetch("memory_mb")
        provider.customize [
          "modifyvm",
          :id,
          "--description",
          "Aegis-OT M4j #{role}; adapter 1 NAT is bootstrap-only; application bindings prohibited",
        ]
      end
    end
  end
end
