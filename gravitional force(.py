def gravitional_force(mass):
     return mass*gravity
 
x=int(input("mass"))
gravity=9.81
z=gravitional_force(x)
print(z)