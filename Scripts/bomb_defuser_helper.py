import angr
import claripy
import sys

def initialize_environment(project, start_va):
	state = project.factory.blank_state(
		addr=start_va,
		add_options={
			angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
			angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
			angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY
		}
	)
	p_stack = state.heap.allocate(4096) & ~0xF
	state.regs.rsp = p_stack + 4096
	
	p_input = state.heap.allocate(80)
	sym_flag = claripy.BVS('input', 80 * 8)
	state.memory.store(p_input, sym_flag)
	state.regs.rdi = p_input 
	
	return state, p_input, sym_flag

class MySixNumberReader(angr.SimProcedure):
	def run(self, p_source, p_array):
		for i in range(6):
			curr_sym_int = self.state.solver.BVS(f'int_{i}', 4 * 8)
			self.state.solver.add(curr_sym_int > 0)
			
			self.state.globals[f'g_int_{i}'] = curr_sym_int
			
			p_curr_stack = p_array + (i * 4)
			self.state.memory.store(p_curr_stack, curr_sym_int)
			
		return self.state.solver.BVV(6, self.state.arch.bits)

class MySScanf(angr.SimProcedure):
	def __init__(self, callback=None):
		super().__init__()
		self.callback = callback
	
	def run(self):
		p_input = self.arg(0)
		p_fmt = self.arg(1)
		
		fmt = self.state.mem[p_fmt].string.concrete.decode('utf-8')
		var_amnt = len(fmt.split())
		sym_var_list = []
		for i in range(1, var_amnt + 1):
			p_buf = self.arg(1 + i)
			sym_var = self.state.solver.BVS(f'var{i}', 32)
			self.state.memory.store(p_buf, sym_var, endness=self.state.arch.memory_endness)
			sym_var_list.append(sym_var)
		
		if self.callback:
			self.callback(self.state, sym_var_list)
		
		self.state.globals['sym_var_list'] = sym_var_list
		return self.state.solver.BVV(var_amnt, self.state.arch.bits)	
		
def debug_unsat(sim):
	result = 'unsat'
	state = sim.unsat[0]
	print(state.solver.unsat_core())
	for i, c in enumerate(state.solver.constraints):
		print(f'[{i}] {c}')
	if len(state.solver.constraints):
		print()
	return result

def extract_solution(sim):
	state = sim.found[0]
	solution = []
	for sym_var in state.globals['sym_var_list']:
		# Another way of doing this
		#val = state.solver.eval(sym_var, cast_to=bytes)[::-1]
		#val = int.from_bytes(val, byteorder='little')
		val = state.solver.eval(sym_var, cast_to=int)
		solution.append(val)
	return ' '.join(str(val) for val in solution)
		
		
