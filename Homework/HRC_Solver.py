from z3 import *

#############################################################
#	HRC_Solver.py											#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Reverse Engineering 3: Hand Rolled Cryptex				#
#		Math Solver											#
#	02/21/2024												#
#############################################################


def question2():
	s = Solver()
	a = BitVec('a',4)
	s.add(~(a) ^ 0xc9 == 0x3)
	print(s.check())
	print(s.model())

question2()