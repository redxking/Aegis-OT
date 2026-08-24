Vagrant.configure("2") do |config|
  nodes = {
    "management" => [2, 4096, "192.168.56.10"],
    "trust"      => [2, 4096, "192.168.57.10"],
    "agents"     => [4, 8192, "192.168.58.10"],
    "gateway"    => [4, 8192, "192.168.59.10"],
    "ot"         => [4, 8192, "192.168.59.20"],
    "simulation" => [4, 8192, "192.168.60.10"]
  }

  nodes.each do |name, (cpus, memory, address)|
    config.vm.define name do |node|
      node.vm.box = "generic/ubuntu2204"
      node.vm.hostname = "aegis-#{name}"
      node.vm.network "private_network", ip: address
      node.vm.provider "virtualbox" do |vb|
        vb.cpus = cpus
        vb.memory = memory
      end
    end
  end
end
