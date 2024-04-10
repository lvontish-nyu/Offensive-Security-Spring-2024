from z3 import *

#############################################################
#	BoD_fun2.py												#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Reverse Engineering 2: Bridge of Death 					#
#		fun_2 Solver										#
#	02/14/2024												#
#############################################################



a = Int('a')
b, c = Reals('b, c')
#g = Int('g')
s = Solver()
s.add(b == 0)
s.add(c == 20)
s.add(a == b + (c-b)/2)
print(s.check())
print(s.model())