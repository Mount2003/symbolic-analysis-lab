import angr
import sys
import claripy
		
def skip_scanf_and_run_method(project, state, image_base, start_rva):
	start_rva = 0x87D # This is the instruction after scanf (skipping scanf entirely)
	
	sim = project.factory.simulation_manager(state)
	sim.explore(find=start_rva + image_base)
	state_start = sim.found[0]

	sym_rbp = state_start.regs.rbp

	flag1 = claripy.BVS("flag1", 18 * 8) # This is the generic way to define a symbolic variable
	flag2 = claripy.BVS("flag2", 18 * 8)

	state_start.memory.store(sym_rbp - 128, flag1)
	state_start.memory.store(sym_rbp - 96, flag2)

	for i in range(17):
		state_start.solver.add(flag1.get_byte(i) >= 0x20)
		state_start.solver.add(flag1.get_byte(i) <= 0x7F)
		state_start.solver.add(flag2.get_byte(i) >= 0x20)
		state_start.solver.add(flag2.get_byte(i) <= 0x7F)

	template = "shaktictf{"
	for i, let in enumerate(template):
		state_start.solver.add(flag1.get_byte(i) == ord(f"{let}"))
		
	possibilities = [flag2.get_byte(i) == ord('}') for i in range(17)]
	state_start.add_constraints(claripy.Or(*possibilities))
	state_start.add_constraints(flag1.get_byte(17) == 0, flag2.get_byte(17) == 0)
	
	return flag1, flag2, state_start, project

class MyScanf(angr.SimProcedure):
	def run(self, fmt, ptr1, ptr2):
		flag1 = self.state.solver.BVS("flag1", 18 * 8) # This is the more specific way of defining a symbolic variable. This would attach the symbolic variable definition to the current context/universe.
		flag2 = self.state.solver.BVS("flag2", 18 * 8)
		
		self.state.globals['g_flag1'] = flag1
		self.state.globals['g_flag2'] = flag2
		
		self.state.memory.store(ptr1, flag1)
		self.state.memory.store(ptr2, flag2)
		
		for i in range(17):
			self.state.solver.add(flag1.get_byte(i) >= 0x20)
			self.state.solver.add(flag1.get_byte(i) <= 0x7F)
			self.state.solver.add(flag2.get_byte(i) >= 0x20)
			self.state.solver.add(flag2.get_byte(i) <= 0x7F)
		
		template = "shaktictf{"
		for i, let in enumerate(template):
			self.state.solver.add(flag1.get_byte(i) == ord(f"{let}"))
		
		possibilities = [flag2.get_byte(i) == ord('}') for i in range(17)]
		self.state.add_constraints(claripy.Or(*possibilities))
		self.state.add_constraints(flag1.get_byte(17) == 0, flag2.get_byte(17) == 0)
		
		return self.state.solver.BVV(2, self.state.arch.bits) # Return 2. It looks complicated because you are currently in the symbolic world.

def hook_and_run_scanf_method(project, state, image_base, start_rva):
	scanf_va = image_base + 0x700
	start_va = image_base + start_rva
	
	project.hook(addr=scanf_va, hook=MyScanf())
	
	sim = project.factory.simulation_manager(state)
	sim.explore(find=start_va)
	state = sim.found[0]
	
	flag1 = state.globals['g_flag1']
	flag2 = state.globals['g_flag2']
	
	return flag1, flag2, state, project

project = angr.Project('moon')

state_0 = project.factory.entry_state(
	add_options={
		angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
		angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
	}
)

image_base = project.loader.main_object.mapped_base

start_rva = 0x87D 

# ---------------------------------------------------------------------------------------------------
#flag1, flag2, state, project = skip_scanf_and_run_method(project, state_0, image_base, start_rva)
flag1, flag2, state, project = hook_and_run_scanf_method(project, state_0, image_base, start_rva)
# ---------------------------------------------------------------------------------------------------
# Two ways to manipulate functions...

win_rva = image_base + 0xBFD
lose_rva_list = [0x8A8, 0xBE9, 0xBD3]
sim = project.factory.simulation_manager(state)
sim.explore(find=win_rva, avoid=[rva + image_base for rva in lose_rva_list])

if sim.found:
	state = sim.found[0]
	combined = flag1.concat(flag2)
	solutions = state.solver.eval_upto(combined, 20, cast_to=bytes)
	
	for sol in solutions:
		print(sol.decode('ascii'))
	
	
	
	
	
