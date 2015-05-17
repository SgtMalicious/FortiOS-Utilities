#!/usr/bin/env python

import sys

try:
    from collections import OrderedDict
except ImportError:
    try:
        from ordereddict import OrderedDict
    except ImportError:
        sys.stderr.write("Unable to import the OrderedDict module. Exiting...\n")
        sys.exit(1)

class fgPolicyDump():
    """Dummy class for a FortiOS Policy"""
    def __init__(self,id=None):
        if id == None:
                raise ValueError,"missing policy information"

        self.id = id
        self.disabled = False

    def set_disable(self):
        self.disabled = True


class fgSubPolicyDump(fgPolicyDump):
    """Dummy class for a FortiOS Identity Policy"""
    def __init__(self,id=None):
        fgPolicyDump.__init__(self, id)


class fgIdentityPolicy(fgSubPolicyDump):
    """Class for a FortiOS Identity Policy"""
    def __init__(self,id=None):
        fgSubPolicyDump.__init__(self, id)

        self.utm = False
        self.groups = []
        self.services = []
        self.portal = []

    def add_service(self,service):
        self.services.append(service.replace('"',''))

    def set_utm(self):
        self.utm = True

    def add_group(self,group):
        self.groups.append(group.replace('"',''))

    def add_portal(self,portal):
        self.portal.append(portal.replace('"',''))


class fgPolicy(fgPolicyDump):
    """Class for a FortiOS Policy"""
    def __init__(self,id=None):
        fgPolicyDump.__init__(self, id)

        self.src_zone = []
        self.dst_zone = []

        self.webauth = False
        self.traffic = False
        self.log = False
        self.schedule = False
        self.attack = False
        self.nat = "-"

        self.action = "Deny"

        self.src_addr = []
        self.dst_addr = []
        self.svc = []

        self.subpolicies = []

    def set_srcintf(self,src):
        self.src_zone.append(src.replace('"',''))

    def set_dstintf(self,dst):
        self.dst_zone.append(dst.replace('"',''))

    def set_nat(self,type):
        self.nat = type.capitalize()

    def set_action(self,action):
        self.action = action.capitalize()

    def add_svc(self,service):
        self.svc.append(service.replace('"',''))

    def add_src(self,addr):
        self.src_addr.append(addr.replace('"',''))

    def add_dst(self,addr):
        self.dst_addr.append(addr.replace('"',''))

    def set_traffic(self):
        self.traffic = True

    def set_log(self):
        self.log = True

    def set_webauth(self):
        self.webauth = True

    def set_attack(self):
        self.attack = True

    def set_schedule(self):
        self.schedule = True

    def add_subpolicy(self, subpolicy):
        self.subpolicies.append(subpolicy)

def print_policy(policies=[]):

    print "[1;34m%5s %-15s %-15s %-25s %-25s %-15s %-15s %-10s %-4s %s[m" % ("ID","From","To","Src-address","Dst-address","Service","Action","State","ASTL","NAT")
    for p in policies:
        print "%5s %-15s %-15s %-25s %-25s %-15s %-15s %-18s %s%s%s%s %s" % (p.id,p.src_zone[0][0:15],p.dst_zone[0][0:15],p.src_addr[0][0:25],p.dst_addr[0][0:25],p.svc[0][0:15],p.action,"[31mdisabled[m" if p.disabled else "[32menabled[m","X" if p.attack else "-","X" if p.schedule else "-","X" if p.traffic else "-","X" if p.log else "-",p.nat)

        array_max = max(len(p.src_zone),len(p.dst_zone),len(p.src_addr),len(p.dst_addr),len(p.svc))
        if len(p.src_zone) < array_max:
            p.src_zone += [''] * (array_max - len(p.src_zone))
        if len(p.dst_zone) < array_max:
            p.dst_zone += [''] * (array_max - len(p.dst_zone))
        if len(p.src_addr) < array_max:
            p.src_addr += [''] * (array_max - len(p.src_addr))
        if len(p.dst_addr) < array_max:
            p.dst_addr += [''] * (array_max - len(p.dst_addr))
        if len(p.svc) < array_max:
            p.svc += [''] * (array_max - len(p.svc))

        for i in range(1,array_max):
            print "      %-15s %-15s %-25s %-25s %-15s" % (p.src_zone[i][0:15],p.dst_zone[i][0:15],p.src_addr[i][0:25],p.dst_addr[i][0:25],p.svc[i])

def dump_policy(p):

    print "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % (p.id,','.join(p.src_zone),','.join(p.dst_zone),','.join(p.src_addr),','.join(p.dst_addr),','.join(p.svc),p.action,"disabled" if p.disabled else "enabled","X" if p.attack else "-","X" if p.schedule else "-","X" if p.traffic else "-","X" if p.log else "-",p.nat)

    for sub in p.subpolicies:
        if isinstance(sub, fgIdentityPolicy):
            print "\t%s\t%s\t%s\t%s\t%s" % (p.id+'.'+sub.id, ','.join(sub.groups), ','.join(sub.portal), "X" if sub.utm else "-","disabled" if p.disabled else "enabled")

if __name__ == '__main__':

    if not len(sys.argv) >= 4:
        sys.stderr.write("Usage: %s <fg config> [ <vdom> | none ] [ dump | <policy id> | <from zone> <to zone> ]\n" % sys.argv[0])
        sys.exit(1)

    config = []
    policy_list = []

    vdom = sys.argv[2]

    in_vdom = 0
    with_vdom = 0
    in_policy = False

    sys.stdout.write("Loading configuration...")

    try:
        fd = open(sys.argv[1],'r')
        line = fd.readline()

        if int(line[:-1].split(':')[2].split('=')[1]):
            with_vdom = 1

        for line in fd.readlines():
            if with_vdom and line[:-1] == "edit "+vdom:
                in_vdom += 1

            #if line[:-1] == "config firewall policy6" for v6 policies
            if line[:-1] == "config firewall policy" and ( not with_vdom or in_vdom == 2 ): # for vdom config, first 'edit <vdom>' is blank config
                in_policy = True

            if line[:-1] == "end" and in_policy:
                config.append(line.strip())
                break

            if in_policy:
                config.append(line.strip())

        fd.close()
        config.pop() # pop "end" off
    except:
        sys.stderr.write("\nFATAL: unable to open file %s\n" % sys.argv[1] )
        sys.exit(1)

    config_iter = iter(config)

    in_policy = False
    in_subpolicy = False

    subconfig = False
    subconfig_type = None

    for line in config_iter:

        if subconfig:

            if line == "end":
                # end of sobpolicy
                subconfig = False
                continue

            if subconfig_type == 'identity-based-policy':

                if line == "next":
                    policy.add_subpolicy(subpolicy)
                    in_subpolicy = False
                    continue

                [cmd,args] = line.split(None,1)

                if cmd == "edit" and in_subpolicy:
                    # skip sub sib policy blocks ?
                    continue

                if cmd == "edit":
                    in_subpolicy = True
                    subpolicy = fgIdentityPolicy(args)
                    continue

                if cmd == "set":

                    [option,opt_args] = args.split(None,1)

                    if option == "utm-status":
                        if opt_args == "enable":
                            subpolicy.set_utm()
                    elif option == "groups":
                        for grp in opt_args.split('" "'):
                            subpolicy.add_group(grp)
                    elif option == "service":
                        for svc in opt_args.split('" "'):
                            subpolicy.add_service(svc)
                    elif option == "sslvpn-portal":
                        for portal in opt_args.split('" "'):
                            subpolicy.add_portal(portal)
                    elif option == "status":
                        if opt_args == "disable":
                            policy.set_disable()

        else:

            if line == "next":
                policy_list += [policy]
                in_policy = False
                continue

            [cmd,args] = line.split(None,1)

            if cmd == "edit" and in_policy:
                # skip sub policy blocks
                continue

            if cmd == "edit":
                in_policy = True
                policy = fgPolicy(args)
                #if policy_dict.has_key(policy.id):
                #	sys.stderr.write("Duplicate policy id entry detected: %s\n" % policy.id)
                continue

            if cmd == "set":

                [option,opt_args] = args.split(None,1)

                if option == "srcintf":
                    for intf in opt_args.split('" "'):
                        policy.set_srcintf(intf)
                elif option == "dstintf":
                    for intf in opt_args.split('" "'):
                        policy.set_dstintf(intf)
                elif option == "srcaddr":
                    for addr in opt_args.split('" "'):
                        policy.add_src(addr)
                elif option == "dstaddr":
                    for addr in opt_args.split('" "'):
                        policy.add_dst(addr)
                elif option == "service":
                    for svc in opt_args.split('" "'):
                        policy.add_svc(svc)
                elif option == "action":
                    policy.set_action(opt_args)
                elif option == "nat":
                    policy.set_nat('S')
                elif option == "ippool":
                    policy.set_nat('D')
                elif option == "identity-based":
                    policy.set_webauth()
                    policy.set_action(policy.action + "~")
                elif option == "schedule":
                    if opt_args != '"always"':
                        policy.set_schedule()
                elif option == "utm-status":
                    if opt_args == "enable":
                        policy.set_attack()
                elif option == "per-ip-shaper" or option == "traffic-shaper":
                    policy.set_traffic()
                elif option == "logtraffic":
                    if opt_args == "all":
                        policy.set_log()
                elif option == "status":
                    if opt_args == "disable":
                        policy.set_disable()

            if cmd == "config":
                if args != 'firewall policy':
                    subconfig = True
                    subconfig_type = args

    sys.stdout.write("complete. %s policies loaded.\n" % len(policy_list))

    print "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % ("ID","From","To","Src-address","Dst-address","Service","Action","State","Attack","Schedule","Traffic Shaping","Logging","NAT")

    if sys.argv[3].isdigit():
        found = False
        for policy in policy_list:
            if policy.id == sys.argv[3]:
                found = True
                if len(policy.subpolicies) > 0:
                    print "%s\t%s\t%s\t%s\t%s\t%s" % ("", "(ID)","(Groups)","(Portal)","(Attack)","(State)")
                dump_policy(policy)
        if not found:
            print "No such policy."

    if sys.argv[3] == "dump":
        if subconfig_type is not None:
            print "%s\t%s\t%s\t%s\t%s\t%s" % ("", "(ID)","(Groups)","(Portal)","(Attack)","(State)")
        for policy in policy_list:
            dump_policy(policy)

    if len(sys.argv) == 5:
        policies = []
        for policy in policy_list:
            for s_intf in policy.src_zone:
                for d_intf in policy.dst_zone:
                    if s_intf.lower() == sys.argv[3].lower() and d_intf.lower() == sys.argv[4].lower():
                        policies.append(policy)

        print_policy(policies)