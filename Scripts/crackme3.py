import angr

proj = angr.Project('crackme0x03')

state = proj.factory.entry_state(
	add_options={
		angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
		angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
	}
)

simgr = proj.factory.simulation_manager(state)

win_branch = 0x804848A
lose_branch = 0x804847C
simgr.explore(find=win_branch, avoid=lose_branch)

if simgr.found:
	context = simgr.found[0]
	password = context.solver.eval(context.regs.eax)
	
	deob_sim = proj.factory.simulation_manager(context)
	print_add = 0x8048467
	deob_sim.explore(find=print_add)
	if deob_sim.found:
		context = deob_sim.found[0]
		pString = context.regs.eax
		message = context.mem[pString].string.concrete
		print(password, message.decode('utf-8'))
			
			
			
			

