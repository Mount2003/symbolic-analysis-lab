import angr
import sys
import claripy

project = angr.Project('Tokyowesterns_rev_rev_rev-a0b0d214b4aeb9b5dd24ffc971bd391494b9f82e2e60b4afc20e9465f336089f')

base_context = project.factory.entry_state(
	add_options={
		angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
		angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
	}
)

base_path = project.factory.simulation_manager(base_context)

win_add = 0x804867C
lose_add = 0x804868E
base_path.explore(find=win_add, avoid=lose_add)

if base_path.found:
	context1 = base_path.found[0]
	
	result_bv = context1.memory.load(context1.regs.ebp - 45, 33) 
	
	result = context1.solver.eval(result_bv, cast_to=bytes)
	
	stdin_value = context1.posix.dumps(0)
	
	print(result)
	print(result.hex())
	print(stdin_value)
	print(stdin_value.hex())
	


