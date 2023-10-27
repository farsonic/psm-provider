# psm-provider


## Installation
Currently the code is installed directly from Github where there is a Main repo and a Dev repository. Current expections are that the provider is being installed using a Linux or WSL based platform which it has been tested against. You will need to have git tools installed and a functional build system. 

```
git clone https://github.com/farsonic/psm-provider.git 
cd psm-provider
make
```

Once you install the provider it will be hosted locally with the current **Hostname = local** and the **Namespace = provider**. The Name of the provider is **PSM**.

Within your Terraform infrastructure file (ie main.tf) specify the provider with the following syntax. 

```
terraform { 
  required_providers {
   psm = { 
      version = "0.1.81" 
      source = "local/provider/psm"
  }
}
```

You will need to configure the provider to communicate directly with the PSM server either with or without SSL certificate validation using the following definition. 

```
provider "psm" { 
  user = "admin"
  server = "https://PSM_SERVER"
  password = "PSM_PASSWORD"
  insecure = true
}
```

## Usage examples

### VRF Instance
VRF's provide isolation of routing tables as well as networks within the platform. The following definition will configure a new VRF instance capability within the DPU, however the underlying switch will also need to have the VRF configuration in place also. 

```
resource "psm_vrf" "customerABC" { 
  name = "CustomerXYZ"
}
```


### Network 
Within PSM a network definition defines the name of the network and the VLAN that will be redirected to a DPU. The following resource definition will create a network called "Database Network" which redirect VLAN 123 traffic to the DPU. The VLAN will need to be configured on at least one switch in the network to be successfully propagated to the DPU. 

```
resource "psm_network" "network" {
  name     = "Database Network"
  tenant   = "default" 
  vlan_id  = 123
}
```

### IP Collections
PSM allows the user to create groups of IP Addresses called IP Collections. These are then used within Security Policies (and elsewhere) to define the source and destination IP Addresses used for matches. 

```
resource "psm_ipcollection" "ipcollections" {
  name     = "DatabaseServers"
  addresses = "10.10.10.0/24" 
}
```

### Security Policies 
Security policies are attached to either an individual network or to the VRF. If attached to a VRF then the policy is inherited by networks associated with that particular VRF. If the tenant and/or the policy_distribution_target is not defined these will default to the default VRF. The from IP_Collections will need to be defined prior to them being mapped within the rule. When pushing a security policy you can configure a definition wihtout any rules and then add rules. Rules will be applied in order, so order matters. Rules will need at least a pair of to/from_ip_addresses and/or to/from_ip_collections. 

```
resource "psm_rules" "ApplicationA_Stack" {
  policy_name                = "ApplicationStack"
  tenant                     = "default"
  policy_distribution_target = "default"
  rule {
      rule_name = "AllowSSHTraffic"
      description = "This rule allows SSH traffic from public IPs"
      from_ip_addresses   = ["10.9.0.0/24"]
      to_ip_addresses     = ["10.10.0.0/23", "10.99.1.1/32"]
      from_ip_collections = ["network2","network1"]
      to_ip_collections   = ["network4"]
      apps = ["SSH"]
      action = "permit"
    }
}
```

Currently there is no ability to add individual protocol/port entries (watch this space) as well as ability to define custom application definitions. 

### Advanced usage 

Combine this all together and define your networks, subnets and firewall policies into a single definition within terraform. There is currently constraints around the order of execution, so ensure your networks and IP Collections are defined before you atempt to assign them to a security policy. 

```
locals {
  networks = {
    network1 = {
      name   = "network1"
      description = "My network"
      department = "Production"
      vlan   = 123
      subnet = "10.45.45.0/28"
      vrf = "default"
    },
    network2 = {
      name   = "network2"
      description = "My network"
      department = "Development"
      vlan   = 456
      subnet = "10.56.78.0/24"
      vrf = "default"
    }
    network4 = {
      name   = "network4"
      description = "My network"
      department = "Development"
      vlan   = 479
      subnet = "10.58.178.0/24"
      vrf = "default"
    }
    network7 = {
      name   = "network7"
      description = "My network"
      department = "Development"
      vlan   = 477
      subnet = "10.8.177.0/24"
      vrf = "CustomerABC"
    }
    HomeLAN = {
      name   = "HomeLAN"
      description = "Home Network"
      department = "Production"
      vlan   = 199
      subnet = "192.168.0.0/24"
      vrf = "default"
    }
    DEMO = {
      name   = "DEMONETWORK"
      description = "DEMO Network"
      department = "Development"
      vlan   = 1119
      subnet = "192.168.19.0/24"
      vrf = "default"
    }
  }
  firewall_rules = [
    {
      name = "webservertraffic"
      description = "All the webserver traffic"
      from_collection = ["network1", "network2"]
      to_collection   = ["network4", "network7"]
      apps = ["AH", "GRE"]
      action = "permit"
    },
    {
      name = "telnet"
      description = "All the Telnet traffic"
      from_collection = ["network1", "network2"]
      to_collection   = ["network4", "network7", "network1"]
      apps = ["TELNET"]
      action = "permit"
    },
    {
      name = "sshtraffic"
      description = "SSH traffic"
      from_collection = ["network1", "network2"]
      to_collection   = ["network4", "network7"]
      apps = ["SSH"]
      action = "permit"
    },
    {
      name = "bgptraffic"
      description = "All the BGP traffic"
      from_collection = ["network1", "network2"]
      to_collection   = ["network4", "network7"]
      apps = ["BGP"]
      action = "permit"
    },
    {
      name = "webtraffic"
      description = "All the WEB traffic"
      from_collection = ["network1", "network2","DEMONETWORK"]
      to_collection   = ["network4", "network7"]
      apps = ["HTTPS"]
      action = "permit"
    },
    {
      name = "DefaultPolicy"
      description = "Default "
      from_addresses = ["any"]
      to_addresses   = ["any"]
      apps = ["ALL_TCP","ALL_UDP"]
      action = "deny"
    }
  ]
}

resource "psm_vrf" "customerABC" { 
  name = "CustomerXYZ"
}


resource "psm_network" "network" {
  for_each = local.networks
  name     = each.value.name
  tenant   = each.value.vrf
  vlan_id  = each.value.vlan
}

resource "psm_ipcollection" "ipcollections" {
  for_each = local.networks
  name     = each.value.name
  addresses = [each.value.subnet]

  depends_on = [psm_network.network]
}

resource "psm_rules" "default_vrf_policy" {
  policy_name                = "test"
  tenant                     = "default"
  policy_distribution_target = "default"

  dynamic "rule" {
    for_each = local.firewall_rules
    content {
      rule_name           = rule.value.name
      description         = rule.value.description
      from_ip_collections = lookup(rule.value, "from_collection", [])
      to_ip_collections   = lookup(rule.value, "to_collection", [])
      from_ip_addresses   = lookup(rule.value, "from_addresses", [])
      to_ip_addresses     = lookup(rule.value, "to_addresses", [])
      apps                = rule.value.apps
      action              = rule.value.action
    }
  }

  depends_on = [psm_ipcollection.ipcollections]
}
```
