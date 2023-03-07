def caesarShift(str, amount):
    output = ""

    for i in range(0, len(str)):
        c = str[i]
        code = ord(c)
        if ((code >= 65) and (code <= 90)):
            c = chr(((code - 65 + amount) % 26) + 65)
        output = output + c

    return output


def encode(plaintext):
    global rotors, reflector, ringSettings, ringPositions, plugboard
    # Enigma Rotors and reflectors
    rotor1 = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
    rotor1Notch = "Q"
    rotor2 = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
    rotor2Notch = "E"
    rotor3 = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
    rotor3Notch = "V"
    rotor4 = "ESOVPZJAYQUIRHXLNFTGKDCMWB"
    rotor4Notch = "J"
    rotor5 = "VZBRGITYUPSDNHLXAWMJQOFECK"
    rotor5Notch = "Z"

    rotorDict = {"1": rotor1, "2": rotor2, "3": rotor3, "4": rotor4, "5": rotor5}
    rotorNotchDict = {"1": rotor1Notch, "2": rotor2Notch, "3": rotor3Notch, "4": rotor4Notch, "5": rotor5Notch}

    reflectorB = {"A": "Y", "Y": "A", "B": "R", "R": "B", "C": "U", "U": "C", "D": "H", "H": "D", "E": "Q",
                  "Q": "E",
                  "F": "S", "S": "F", "G": "L", "L": "G", "I": "P", "P": "I", "J": "X", "X": "J", "K": "N",
                  "N": "K",
                  "M": "O", "O": "M", "T": "Z", "Z": "T", "V": "W", "W": "V"}
    reflectorC = {"A": "F", "F": "A", "B": "V", "V": "B", "C": "P", "P": "C", "D": "J", "J": "D", "E": "I",
                  "I": "E",
                  "G": "O", "O": "G", "H": "Y", "Y": "H", "K": "R", "R": "K", "L": "Z", "Z": "L", "M": "X",
                  "X": "M",
                  "N": "W", "W": "N", "Q": "T", "T": "Q", "S": "U", "U": "S"}

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    rotorANotch = False
    rotorBNotch = False
    rotorCNotch = False

    if reflector == "UKW-B":
        reflectorDict = reflectorB
    else:
        reflectorDict = reflectorC

    # A = Left,  B = Mid,  C=Right
    rotorA = rotorDict[rotors[0]]
    rotorB = rotorDict[rotors[1]]
    rotorC = rotorDict[rotors[2]]
    rotorANotch = rotorNotchDict[rotors[0]]
    rotorBNotch = rotorNotchDict[rotors[1]]
    rotorCNotch = rotorNotchDict[rotors[2]]

    rotorALetter = ringPositions[0]
    rotorBLetter = ringPositions[1]
    rotorCLetter = ringPositions[2]

    rotorASetting = ringSettings[0]
    offsetASetting = alphabet.index(rotorASetting)
    rotorBSetting = ringSettings[1]
    offsetBSetting = alphabet.index(rotorBSetting)
    rotorCSetting = ringSettings[2]
    offsetCSetting = alphabet.index(rotorCSetting)

    rotorA = caesarShift(rotorA, offsetASetting)
    rotorB = caesarShift(rotorB, offsetBSetting)
    rotorC = caesarShift(rotorC, offsetCSetting)

    if offsetASetting > 0:
        rotorA = rotorA[26 - offsetASetting:] + rotorA[0:26 - offsetASetting]
    if offsetBSetting > 0:
        rotorB = rotorB[26 - offsetBSetting:] + rotorB[0:26 - offsetBSetting]
    if offsetCSetting > 0:
        rotorC = rotorC[26 - offsetCSetting:] + rotorC[0:26 - offsetCSetting]

    ciphertext = ""

    # Converplugboard settings into a dictionary
    plugboardConnections = plugboard.upper().split(" ")
    plugboardDict = {}
    for pair in plugboardConnections:
        if len(pair) == 2:
            plugboardDict[pair[0]] = pair[1]
            plugboardDict[pair[1]] = pair[0]

    plaintext = plaintext.upper()
    for letter in plaintext:
        encryptedLetter = letter

        if letter in alphabet:
            # Rotate Rotors - This happens as soon as a key is pressed, before encrypting the letter!
            rotorTrigger = False
            # Third rotor rotates by 1 for every key being pressed
            if rotorCLetter == rotorCNotch:
                rotorTrigger = True
            rotorCLetter = alphabet[(alphabet.index(rotorCLetter) + 1) % 26]
            # Check if rotorB needs to rotate
            if rotorTrigger:
                rotorTrigger = False
                if rotorBLetter == rotorBNotch:
                    rotorTrigger = True
                rotorBLetter = alphabet[(alphabet.index(rotorBLetter) + 1) % 26]

                # Check if rotorA needs to rotate
                if (rotorTrigger):
                    rotorTrigger = False
                    rotorALetter = alphabet[(alphabet.index(rotorALetter) + 1) % 26]

            else:
                # Check for double step sequence!
                if rotorBLetter == rotorBNotch:
                    rotorBLetter = alphabet[(alphabet.index(rotorBLetter) + 1) % 26]
                    rotorALetter = alphabet[(alphabet.index(rotorALetter) + 1) % 26]

            # Implement plugboard encryption!
            if letter in plugboardDict.keys():
                if plugboardDict[letter] != "":
                    encryptedLetter = plugboardDict[letter]

            # Rotors & Reflector Encryption
            offsetA = alphabet.index(rotorALetter)
            offsetB = alphabet.index(rotorBLetter)
            offsetC = alphabet.index(rotorCLetter)

            # Wheel 3 Encryption
            pos = alphabet.index(encryptedLetter)
            let = rotorC[(pos + offsetC) % 26]
            pos = alphabet.index(let)
            encryptedLetter = alphabet[(pos - offsetC + 26) % 26]

            # Wheel 2 Encryption
            pos = alphabet.index(encryptedLetter)
            let = rotorB[(pos + offsetB) % 26]
            pos = alphabet.index(let)
            encryptedLetter = alphabet[(pos - offsetB + 26) % 26]

            # Wheel 1 Encryption
            pos = alphabet.index(encryptedLetter)
            let = rotorA[(pos + offsetA) % 26]
            pos = alphabet.index(let)
            encryptedLetter = alphabet[(pos - offsetA + 26) % 26]

            # Reflector encryption!
            if encryptedLetter in reflectorDict.keys():
                if reflectorDict[encryptedLetter] != "":
                    encryptedLetter = reflectorDict[encryptedLetter]

            # Back through the rotors
            # Wheel 1 Encryption
            pos = alphabet.index(encryptedLetter)
            let = alphabet[(pos + offsetA) % 26]
            pos = rotorA.index(let)
            encryptedLetter = alphabet[(pos - offsetA + 26) % 26]

            # Wheel 2 Encryption
            pos = alphabet.index(encryptedLetter)
            let = alphabet[(pos + offsetB) % 26]
            pos = rotorB.index(let)
            encryptedLetter = alphabet[(pos - offsetB + 26) % 26]

            # Wheel 3 Encryption
            pos = alphabet.index(encryptedLetter)
            let = alphabet[(pos + offsetC) % 26]
            pos = rotorC.index(let)
            encryptedLetter = alphabet[(pos - offsetC + 26) % 26]

            # Implement plugboard encryption!
            if encryptedLetter in plugboardDict.keys():
                if plugboardDict[encryptedLetter] != "":
                    encryptedLetter = plugboardDict[encryptedLetter]

        ciphertext = ciphertext + encryptedLetter

    return ciphertext


'''# Main Program Starts Here
print("  ##### Enigma Encoder #####")
print("")
plaintext = input("Enter text to encode or decode:\n")
ciphertext = encode(plaintext)

print("\nEncoded text: \n " + ciphertext)'''

from tkinter import *
from tkinter.messagebox import *
from PIL import ImageTk, Image
import pyglet, os

#pyglet.font.add_file("C:/USERS/HP/APPDATA/LOCAL/MICROSOFT/WINDOWS/FONTS/EnigmaSans.ttf")
pyglet.font.add_file("./enigma/EnigmaSans/EnigmaSans.ttf")
#Enigma = pyglet.font.load("Enigma Enigma", 14)
def show_answer():
    # ----------------- Enigma Settings -----------------
    global rotors, reflector, ringSettings, ringPositions, plugboard, sequence
    rotors = Rotors.get()
    reflector = Reflector.get()
    ringSettings = RingSettings.get()
    ringPositions = RingPositions.get()
    plugboard = Plugboard.get()
    sequence = Sequence.get()

    Ans = encode(sequence)
    Answer.insert(0, Ans)

def clear():
    Rotors.delete(0, 'end')
    Reflector.delete(0, 'end')
    RingSettings.delete(0, 'end')
    RingPositions.delete(0, 'end')
    Plugboard.delete(0, 'end')
    Sequence.delete(0, 'end')
    Answer.delete(0, 'end')

main = Tk()

frame = Frame(main)
frame.columnconfigure(0, weight=1)
frame.columnconfigure(1, weight=1)

frame1 = Frame(main)
frame1.columnconfigure(0, weight=1)
frame1.columnconfigure(1, weight=1)

frame2 = Frame(main)
frame2.columnconfigure(0, weight=1)
frame2.columnconfigure(1, weight=1)
frame2.columnconfigure(2, weight=1)

'''frameheader = Frame(main)
frameheader.columnconfigure(0,weight=1)

frameinputs = Frame(main)
frameinputs.columnconfigure(0, weight=1)
frameinputs.columnconfigure(1, weight=1)'''

img = Image.open("./ieeebs.png")
resize_image = img.resize((200, 50))
img1 = Image.open("./ieeenitk.png")
resize_image1 = img1.resize((200, 50))
img2 = Image.open("./fotor_2023-2-4_18_33_46.png")
resize_image2 = img2.resize((200, 50))
new_image= ImageTk.PhotoImage(resize_image)
new_image1= ImageTk.PhotoImage(resize_image1)
new_image2= ImageTk.PhotoImage(resize_image2)
Label(frame2, image=new_image).grid(row=0, column=0, padx=30, pady=10)
Label(frame2, image=new_image1).grid(row=0, column=2, padx=30, pady=10)
Label(frame2, image=new_image2).grid(row=0, column=1, padx=30, pady=10)

frame2.pack(fill='x', pady=20)

'''img3 = Image.open("C:/Users/hp/Pictures/frameheader.jpg")
resize_image3 = img3.resize((920, 37))
new_image3 = ImageTk.PhotoImage(resize_image3)
Label(frameheader, image=new_image3).grid(row=0, column=0, sticky=W+E)

frameheader.pack(fill='x')'''
Label(main, text="CONGRATULATIONS ON MAKING IT THIS FAR! YOU ARE ONLY ONE STEP AWAY NOW!", font=('Enigma Sans', 14)).pack()
Label(main, text="").pack()

'''img4 = Image.open("C:/Users/hp/Pictures/row1.jpg")
resize_image4 = img4.resize((360, 25))
new_image4 = ImageTk.PhotoImage(resize_image4)
img5 = Image.open("C:/Users/hp/Pictures/row2.jpg")
resize_image5 = img5.resize((400, 24))
new_image5 = ImageTk.PhotoImage(resize_image5)
img6 = Image.open("C:/Users/hp/Pictures/row3.jpg")
resize_image6 = img6.resize((270, 24))
new_image6 = ImageTk.PhotoImage(resize_image6)
img7 = Image.open("C:/Users/hp/Pictures/row4.jpg")
resize_image7 = img7.resize((285, 25))
new_image7 = ImageTk.PhotoImage(resize_image7)
img8 = Image.open("C:/Users/hp/Pictures/row5.jpg")
resize_image8 = img8.resize((650, 25))
new_image8 = ImageTk.PhotoImage(resize_image8)
img9 = Image.open("C:/Users/hp/Pictures/row6.jpg")
resize_image9 = img9.resize((165, 24))
new_image9 = ImageTk.PhotoImage(resize_image9)
img10 = Image.open("C:/Users/hp/Pictures/row7.jpg")
resize_image10 = img10.resize((80, 20))
new_image10 = ImageTk.PhotoImage(resize_image10)

Label(frameinputs, image=new_image4).grid(row=0, column=0, sticky=W, padx='37')
Label(frameinputs, image=new_image5).grid(row=1, column=0, sticky=W, padx='37')
Label(frameinputs, image=new_image6).grid(row=2, column=0, sticky=W, padx='37')
Label(frameinputs, image=new_image7).grid(row=3, column=0, sticky=W, padx='37')
Label(frameinputs, image=new_image8).grid(row=4, column=0, sticky=W, padx='37')
Label(frameinputs, image=new_image9).grid(row=5, column=0, sticky=W, padx='37')
Label(frameinputs, image=new_image10).grid(row=6, column=0, sticky=W, padx='37', pady='3')

frameinputs.pack(fill='x')'''

Label(frame, text = "Enter rotors configuration (XXX)", font=('Enigma Sans', 12)).grid(row=0, column=0, sticky=W, padx=40)
Label(frame, text = "Enter reflector configuration (XXX-X)", font=('Enigma Sans', 12)).grid(row=1, column=0, sticky=W, padx=40)
Label(frame, text = "Enter ring settings (XXX)", font=('Enigma Sans', 12)).grid(row=2, column=0, sticky=W, padx=40)
Label(frame, text = "Enter ring positions (XXX)", font=('Enigma Sans', 12)).grid(row=3, column=0, sticky=W, padx=40)
Label(frame, text = "Enter plugboard configuration (XX XX XX XX XX XX XX XX XX XX)", font=('Enigma Sans', 12)).grid(row=4, column=0, sticky=W, padx=40)
Label(frame, text = "Enter sequence", font=('Enigma Sans', 12)).grid(row=5, column=0, sticky=W, padx=40)
Label(frame, text = "ANSWER", font=('Enigma Sans', 12)).grid(row=6, column=0, sticky=W, padx=40)

Rotors = Entry(frame)
Reflector = Entry(frame)
RingSettings = Entry(frame)
RingPositions = Entry(frame)
Plugboard = Entry(frame)
Sequence = Entry(frame)
Answer = Entry(frame, bg='Light Green')

Rotors.grid(row=0, column=1, sticky=W+E, padx=40)
Reflector.grid(row=1, column=1, sticky=W+E, padx=40)
RingSettings.grid(row=2, column=1, sticky=W+E, padx=40)
RingPositions.grid(row=3, column=1, sticky=W+E, padx=40)
Plugboard.grid(row=4, column=1, sticky=W+E, padx=40)
Sequence.grid(row=5, column=1, sticky=W+E, padx=40)
Answer.grid(row=6, column=1, sticky=W+E, padx=40)

frame.pack(fill='x')

'''img11 = Image.open("C:/Users/hp/Pictures/reveal.jpg")
resize_image11 = img11.resize((80, 20))
new_image11 = ImageTk.PhotoImage(resize_image11)
img12 = Image.open("C:/Users/hp/Pictures/clear.jpg")
resize_image12 = img12.resize((65, 20))
new_image12 = ImageTk.PhotoImage(resize_image12)'''

#Button(main, text='Quit', command=main.quit).grid(row=4, column=0, sticky=W, pady=4)
#Button(main, text='Show', command=show_answer).grid(row=7, column=1, sticky=W, pady=8)
Button(frame1, text='REVEAL!', height=2, width=8, font=('Enigma Sans', 10), command=show_answer).grid(row=0, column=0, sticky=W, padx=20)
Button(frame1, text='CLEAR', height=2, width=8, font=('Enigma Sans', 10), command=clear).grid(row=0, column=1, sticky=E, padx=20)
#Button(frame1, image=new_image11, height=40, width=100, command=show_answer).grid(row=0, column=0, sticky=W, padx=20)
#Button(frame1, image=new_image12, height=40, width=100, command=clear).grid(row=0, column=1, sticky=E, padx=20)
frame1.pack(pady=20)

main.geometry("900x450")
main.title("IEEE Mystify 2023 | Repetition Returns Results")

mainloop()

print(os.getcwd())