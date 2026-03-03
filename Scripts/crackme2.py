import angr

proj = angr.Project('./crackme0x02')

state = proj.factory.entry_state()

simgr = proj.factory.simulation_manager(state)

simgr.explore(find=0x8048453, avoid=0x8048461)

print()
if simgr.found:
	solution = simgr.found[0]
	eax_val = solution.regs.eax
	eax_val = solution.solver.eval(eax_val)
	print(eax_val, hex(eax_val))
