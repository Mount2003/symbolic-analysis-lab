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
    cells = [ [ Int(f'z_{i + 1}_{j + 1}') for j in range(9) ] for i in range(9) ]

    # Add sudoku board
    for i, line in enumerate(open(puzzle_file, 'r').read().replace(' ', '').split('\n')):
        for j, value in enumerate(line):
            if value != '_':
                s.add(cells[i][j] == value)

    # Add cell constraints
    for j in range(9):
        for i in range(9):
            s.add(And(1 <= cells[i][j], cells[i][j] <= 9))

    # Add column contraints
    for x in range(9):
        s.add(Distinct(cells[i]))

    # Add row contraints
    for y in range(9):
        s.add(Distinct([cells[i][j] for i in range(9)]))
    
    # Add 3x3 small squares constraints
    for j in range(0,9,3):
        for i in range(0,9,3):
            s.add(Distinct([cells[i + x][j + y] for x, y in itertools.product(range(3), range(3))]))
    
    # Check for satisfiability
    if s.check() == sat:
        m = s.model()
        # Print solution
        print('my solution:')
        for j in range(9):
            print(' '.join([str(m.evaluate(cells[i][j])) for i in range(9)]))
    else:
        print('Not solvable')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Where is my puzzle? Please enter a path to the puzzle file.')
        sys.exit(1)
    solve(sys.argv[1])