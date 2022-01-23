Vagrant.configure("2") do |config|

# wiki
  config.vm.define "wiki" do |cfg|
    cfg.vm.box = "generic/debian11"
    cfg.vm.hostname = "wiki"
    # change the bridged adapter to fit your systems available NIC
    cfg.vm.network "public_network", type: "dhcp", bridge: 'enp1s0'
    cfg.vm.provision :file, source: './installfiles', destination: "/tmp/installfiles"
    cfg.vm.provision :shell, path: "bootstrap.sh"

    cfg.vm.provider "virtualbox" do |vb, override|
      vb.gui = false
      vb.name = "wiki"
      vb.customize ["modifyvm", :id, "--memory", 4096]
      vb.customize ["modifyvm", :id, "--cpus", 4]
      vb.customize ["modifyvm", :id, "--vram", "4"]
      vb.customize ["modifyvm", :id, "--clipboard", "bidirectional"]
      vb.customize ["setextradata", "global", "GUI/SuppressMessages", "all" ]
    end
  end

end
