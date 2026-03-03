import angr
import claripy
import sys
from helper import initialize_environment, MySixNumberReader, MySScanf, debug_unsat, extract_solution

def phase_1(project, image_base):
	start_va = 0x15A7 + image_base
	state, p_input, sym_flag = initialize_environment(project, start_va)
	
	sim = project.factory.simulation_manager(state, save_unsat=True)
	
	win_va = image_base + 0x15BF
	lose_va = image_base + 0x15C4
	sim.explore(find=win_va, avoid=lose_va)
	
	if sim.found:
		state = sim.found[0]
		flag = state.solver.eval(sym_flag, cast_to=bytes)
		return flag.decode('ascii')
	
	else:
		return debug_unsat(sim)

def phase_2(project, image_base):
	start_va = 0x15CB + image_base
	state, p_input, sym_flag = initialize_environment(project, start_va)
	
	project.hook(addr=0x1C11 + image_base, hook=MySixNumberReader())
	
	win_va = image_base + 0x162D
	lose_va = image_base + 0x1BE5
	sim = project.factory.simulation_manager(state, save_unsat=True)
	sim.explore(find=win_va, avoid=lose_va)
	
	if sim.found:
		state = sim.found[0]
		result = []
		for i in range(6):
			curr_sym_int = state.globals[f'g_int_{i}']
			val = state.solver.eval(curr_sym_int, cast_to=bytes)
			result.append(int.from_bytes(val, byteorder=sys.byteorder))
		return ' '.join(str(val) for val in result)
		 
	else:
		return debug_unsat(sim)

def phase_3(project, image_base):
	win_va = 0x16CE + image_base
	bomb_va = 0x1BE5 + image_base
	sscanf_va = 0x12C0 + image_base
	start_va = 0x1639 + image_base
	
	state, p_input, sym_flag = initialize_environment(project, start_va)
	
	project.hook(addr=sscanf_va, hook=MySScanf())
	
	sim = project.factory.simulation_manager(state, save_unsat=True)
	sim.explore(find=win_va, avoid=bomb_va)
	
	if sim.found:
		return extract_solution(sim)
		
	else:
		return debug_unsat(sim)
		
def phase_4(project, image_base):
	start_va = 0x174B + image_base
	sscanf_va = 0x12C0 + image_base
	bomb_va = 0x1BE5 + image_base
	win_va = 0x17BA + image_base
	
	state, p_input, sym_flag = initialize_environment(project, start_va)
	
	project.hook(addr=sscanf_va, hook=MySScanf())
	
	sim = project.factory.simulation_manager(state, save_unsat=True)
	sim.explore(find=win_va, avoid=bomb_va)
	
	if sim.found:
		return extract_solution(sim)
		
	else:
		return debug_unsat(sim)

def phase_5(project, image_base):
	start_va = 0x17C4 + image_base
	bomb_va = 0x1BE5 + image_base
	sscanf_va = 0xd12C0 + image_base
	win_va = 0x184A + image_base 
	
	state, p_input, sym_flag = initialize_environment(project, start_va)
	
	sscanf = MySScanf(callback=lambda s, v: s.add_constraints(v[0] >= 0, v[0] < 15))
	project.hook(addr=sscanf_va, hook=sscanf)
	
	sim = project.factory.simulation_manager(state, save_unsat=True)
	sim.explore(find=win_va, avoid=bomb_va)
	
	if sim.found:
		return extract_solution(sim)
		
	else:
		return debug_unsat(sim)

def phase_6(project, image_base):
	start_va = 0x185B + image_base
	sscanf_va = 0x12C0 + image_base
	bomb_va = 0x1BE5 + image_base
	debug_va = 0x1906 + image_base # 0x1906, 0x1945
	win_va = 0x1971 + image_base
	
	state, p_input, sym_flag = initialize_environment(project, start_va)
	
	def phase_6_constraints(state, sym_var_list):
		image_base = state.project.loader.main_object.mapped_base
		for i in range(len(sym_var_list)):
			state.add_constraints(sym_var_list[i] >= 1, sym_var_list[i] <= 6)
			for j in range(i + 1, len(sym_var_list)):
				state.add_constraints(sym_var_list[i] != sym_var_list[j])	
		def shortcut(state, sym_var_list):
			p_node_head = image_base + 0x5200
			node_vals = []
			while True:
				data = state.memory.load(p_node_head, 16, endness = state.arch.memory_endness)
				data = state.solver.eval(data, signed=False, cast_to=bytes)[::-1]
				
				val = int.from_bytes(data[:4], byteorder=sys.byteorder)
				index = int.from_bytes(data[4:8], byteorder=sys.byteorder)
				p_node_next = int.from_bytes(data[8:], byteorder=sys.byteorder)
				
				node_vals.append((index, val))
				p_node_head = p_node_next
				
				check = state.memory.load(p_node_head, 8, endness=state.arch.memory_endness)
				if not state.solver.eval(check, signed=False, cast_to=int):
					break
			
			node_vals = sorted(node_vals, key=lambda node: node[1], reverse=True)
			for i in range(6):
				state.add_constraints(sym_var_list[i] == node_vals[i][0])
				
		#shortcut(state, sym_var_list)
		
	project.hook(addr=sscanf_va, hook=MySScanf(callback=phase_6_constraints))	
	
	sim = project.factory.simulation_manager(state, save_unsat=True)
	
	while len(sim.active) > 0:
		sim.explore(find=debug_va, avoid=bomb_va)
		sim.drop(stash='avoid')
		sim.drop(stash='unsat')
		
	valid_states = sim.found
	for state in valid_states:
		sim = project.factory.simulation_manager(state)
		sim.explore(find=win_va, avoid=bomb_va)
		if sim.found:
			return extract_solution(sim)

if __name__ == "__main__":
	project = angr.Project('bomb')
	image_base = project.loader.main_object.mapped_base
	
	#flag1 = phase_1(project, image_base)
	#print(f'"{flag1}" (Phase 1)')
	
	#flag2 = phase_2(project, image_base)
	#print(f'"{flag2}" (Phase 2)')
	
	#flag3 = phase_3(project, image_base)
	#print(f'"{flag3}" (Phase 3)')

	#flag4 = phase_4(project, image_base)
	#print(f'"{flag4}" (Phase 4)')
	
	#flag5 = phase_5(project, image_base)
	#print(f'"{flag5}" (Phase 5)')
	
	flag6 = phase_6(project, image_base)
	print(f'"{flag6}" (Phase 6)')
	 
	 
	 












































