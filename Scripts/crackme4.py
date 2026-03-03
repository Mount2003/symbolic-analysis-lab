import angr
import sys

project = angr.Project('crackme0x04')

context = project.factory.entry_state(
	add_options={
		angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
		angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
	}
)

main_path =  project.factory.simulation_manager(context)

win_add = 0x80484DC
lose_add = 0x80484FB 
main_path.explore(find=win_add, avoid=lose_add)

if main_path.found:
	if len(main_path.found) > 1:
		print('There are more than one way to reach this address. Check them.')
		sys.exit(0) #Exit with success status code
	
	main_context = main_path.found[0]
	
	add_ebp = main_context.regs.ebp
	
	pPassword = main_context.solver.eval(main_context.mem[add_ebp + 8].uint32_t.resolved, cast_to=int)
	
	my_rules = []
	for i in range(3):
		sym_byte = main_context.memory.load(pPassword + i, 1)
		my_rules.append(sym_byte >= ord('0'))
		my_rules.append(sym_byte <= ord('5'))
	
	if main_context.solver.satisfiable(extra_constraints=my_rules):
		print("Found solutions matching the 0-5 range!")
		results = main_context.solver.eval_upto(sym_pass_buf, 5, extra_constraints=my_rules, cast_to=bytes)
		print(results)
	else:
		print("No solutions exist in this path for the 0-5 range.")
		
	
	sym_pass_buf = main_context.memory.load(pPassword, 3)
	
	if not main_context.solver.unique(sym_pass_buf):
		print('There are multiple valid values for this symbolic object.')
		
		valid_passwords = main_context.solver.eval_upto(sym_pass_buf, 20, cast_to=bytes)
		
		for password in valid_passwords:
			print(password.hex(), password, password.split(b'\x00')[0].decode('utf-8', errors='ignore'))
		
		print()
		something = str(main_context.posix.dumps(0))
		print(something[2:4])
	
	
	
	
