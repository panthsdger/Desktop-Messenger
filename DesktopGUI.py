import random
from appJar import gui
def none():
    1 == 1

frame = gui()
frame.addLabel("user", "Username: ")
frame.setLabelBg("user", "gray")
frame.addEntry("userdata")
frame.addLabel("pass", "Password: ")
frame.setLabelBg("pass", "gray")
frame.addSecretEntry("passdata")
frame.addButton("Submit", none())
frame.go()
