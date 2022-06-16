#!/usr/bin/env python3

import sys

try:
	from collections import OrderedDict
except ImportError:
	try:
		from ordereddict import OrderedDict
	except ImportError:
		sys.stderr.write("Unable to import the OrderedDict module. Exiting...\n")
		sys.exit(1)

class fgPolicy(object):
	"""Class for a FortiOS Policy"""
	def __init__(self,id=None):
		if id == None:
				raise ValueError("missing policy information")

		self.id = id
		self.src_zone = []
		self.dst_zone = []

		self.webauth = False
		self.traffic = False
		self.log = False
		self.schedule = False
		self.attack = False
		self.nat = ""

		self.action = "Deny"

		self.disabled = False

		self.src_addr = []
		self.dst_addr = []
		self.svc = []

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
	
	def set_disable(self):
		self.disabled = True

	def set_attack(self):
		self.attack = True

	def set_schedule(self):
		self.schedule = True

def print_policy(policies=[]):

	print("[1;34m%(id)5s %(from)-15s %(to)-15s %(src)-25s %(dst)-25s %(svc)-15s %(act)-15s %(st)-10s %(astl)-4s %(nat)s[m" % {'id':"ID",'from':"From",'to':"To",'src':"Src-address",'dst':"Dst-address",'svc':"Service",'act':"Action",'st':"State",'astl':"ASTL",'nat':"NAT"})
	for p in policies:
		print("%(id)5s %(from)-15s %(to)-15s %(src)-25s %(dst)-25s %(svc)-15s %(act)-15s %(st)-18s %(a)s%(s)s%(t)s%(l)s %(nat)s" % {'id':p.id,'from':p.src_zone[0][0:15],'to':p.dst_zone[0][0:15],'src':p.src_addr[0][0:25],'dst':p.dst_addr[0][0:25],'svc':p.svc[0][0:15],'act':p.action,'st':"[31mdisabled[m" if p.disabled else "[32menabled[m",'a':"X" if p.attack else "-",'s':"X" if p.schedule else "-",'t':"X" if p.traffic else "-",'l':"X" if p.log else "-",'nat':p.nat})
		
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
			print("      %(from)-15s %(to)-15s %(src)-25s %(dst)-25s %(svc)-15s" % {'from':p.src_zone[i][0:15],'to':p.dst_zone[i][0:15],'src':p.src_addr[i][0:25],'dst':p.dst_addr[i][0:25],'svc':p.svc[i]})

def dump_policy(p):

	print(p.id,'\t',','.join(p.src_zone),'\t',','.join(p.dst_zone),'\t',','.join(p.src_addr),'\t',','.join(p.dst_addr),'\t',','.join(p.svc),'\t',p.action,'\t',"disabled" if p.disabled else "enabled",'\t',"X" if p.attack else "-",'\t',"X" if p.schedule else "-",'\t',"X" if p.traffic else "-",'\t',"X" if p.log else "-",'\t',p.nat)

if __name__ == '__main__':

	if not len(sys.argv) >= 4:
		sys.stderr.write("Usage: %s <fg config> [ <vdom> | none ] [ dump | available | <policy id> | <from zone> <to zone> ]\n" % sys.argv[0])
		sys.exit(1)

	if sys.argv[0][-4] == '6':
		policy_for_6_or_4 = "config firewall policy6"
	else:
		policy_for_6_or_4 = "config firewall policy"

	config = []
	policy_dict = OrderedDict()

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

			if line[:-1] == policy_for_6_or_4 and ( not with_vdom or in_vdom == 2 ): # for vdom config, first 'edit <vdom>' is blank config
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

	for line in config_iter:

		if line == "end":
			# skip sub policy blocks
			continue

		if line == "next":
			policy_dict[policy.id] = policy
			in_policy = False
			continue

		try:
			[cmd,args] = line.split(None,1)
		except ValueError:
			# wrapped comment or garbage
			next

		if cmd == "edit" and in_policy:
			# skip sub policy blocks
			continue

		if cmd == "edit":
			in_policy = True;
			policy = fgPolicy(args)
			if policy.id in policy_dict:
				sys.stderr.write("Duplicate policy id entry detected: %s\n" % policy.id)
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
			elif option == "internet-service-src-id":
				for addr in opt_args.split('" "'):
					policy.add_src('Internet Service: '+addr)
			elif option == "dstaddr":
				for addr in opt_args.split('" "'):
					policy.add_dst(addr)
			elif option == "internet-service-dst-id":
				for addr in opt_args.split('" "'):
					policy.add_dst('Internet Service: '+addr)
			elif option == "service":
				for svc in opt_args.split('" "'):
					policy.add_svc(svc)
			elif option == "action":
				policy.set_action(opt_args)
			elif option == "nat":
				policy.set_nat('S')
			elif option == "ippool":
				policy.set_nat('D')
			elif option == "identity-based" or option == "groups":
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

	sys.stdout.write("complete. %s policies loaded.\n" % len(policy_dict))

	if sys.argv[3].isdigit():	
		try:
			print_policy([policy_dict[sys.argv[3]],])
		except KeyError:
			print("No such policy.")

	if sys.argv[3] == "dump":
		print("ID\tFrom\tTo\tSrc-address\tDst-address\tService\tAction\tState\tAttack\tSchedule\tTraffic Shaping\tLogging\tNAT")
		for policy in policy_dict:
			dump_policy(policy_dict[policy])

	if sys.argv[3] == "available":
		for policy_id in range(1, int(next(reversed(policy_dict)))+1):
			if str(policy_id) in policy_dict:
				if policy_dict[str(policy_id)].disabled:
					print("[1;34mAvailable:[m ",policy_id)
			else:
				print("     [32mFree:[m ",policy_id)

	if len(sys.argv) == 5:
		policies = []
		for policy in policy_dict:
			for s_intf in policy_dict[policy].src_zone:
				for d_intf in policy_dict[policy].dst_zone:
					if s_intf.lower() == sys.argv[3].lower() and d_intf.lower() == sys.argv[4].lower():
						policies.append(policy_dict[policy])

		print_policy(policies)

# vim: ts=4 sw=4 nowrap
