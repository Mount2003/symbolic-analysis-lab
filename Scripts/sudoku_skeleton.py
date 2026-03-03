from z3 import *
import sys
import itertools


""" Sudoku board example
_ _ _ _ 1 _ _ 3 _
_ _ 9 _ _ 5 _ _ 8
8 _ 4 _ _ 6 _ 2 5
_ _ _ _ _ _ 6 _ _
_ _ 8 _ _ 4 _ _ _
1 2 _ _ 8 7 _ _ _
3 _ _ 9 _ _ 2 _ _
_ 6 5 _ _ 8 _ _ _
9 _ _ _ _ _ _ _ _
"""

# Create a solver
s = Solver()

def solve(puzzle_file):
    # Create the sudoku board / matrix
    board = [[0] * 9 for _ in range(9)]
    	
    # Add sudoku board
    with open(puzzle_file, 'r') as f:
        f = f.readlines()
    for row, line in enumerate(f):
    	for column, cell in enumerate(line.split()):
    		board[row][column] = Int(f"cells{row}{column}")
    		if cell != '_':
    	        	s.add(board[row][column] == cell)

    # Add cell constraints
    for row in board:
    	for entry in row:
    		s.add(entry >= 1, entry <= 9)

    # Add column contraints
    for j in range(9):
    	column = []
    	for i, row in enumerate(board):
    		column.append(board[i][j])
    	s.add(Distinct(*column))

    # Add row contraints
    for row in board:
    	s.add(Distinct(*row))
    
    # Add 3x3 small squares constraints
    for i in range(0, 9, 3):
    	for j in range(0, 9, 3):
    		box = []
    		for steps_i in range(3):
	    		for steps_j in range(3):
	    			box.append(board[i + steps_i][j + steps_j])
    		s.add(Distinct(*box))	 
    
    # Check for satisfiability
    if s.check() == sat:
        m = s.model()
        # Print solution
        print('my solution:')
        for row in board:
        	print(' '.join(str(m[cell].as_long()) for cell in row))

    else:
        print('Not solvable')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Where is my puzzle? Please enter a path to the puzzle file.')
        sys.exit(1)
    solve(sys.argv[1])
