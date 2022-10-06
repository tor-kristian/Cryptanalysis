"""
This is an exam just as it was submitted

Cryptanalysis of a LFSR based stream cipher. Stream cipher binary key-stream si is produced by a Linear Feedback Shift Register (LFSR) of 
length 41 with generating polynomial x^41+x^3+ 1. The LFSR outputs read from the right most cell. 
The plain-text (English text) without punctuation marks and spaces is encoded by teleprinter codeCCITT2 in Letter Shift, 
provided in the course Lecture Notes. For instance, character A is encoded by 11000, character B by 10011,.., character Z by 10001.  
The plain-textrepresented by bits mi is encrypted as ci=si(xor)mi. The encryption algorithm is on the figure below. 

GivenN-bit cipher-text [c1,c2,...,cN] and a set of possible probable words andphrases: 
 General sta↵, Political asylum, Armoured brigade, Parliament, Ambassador, Assumption, Uranium mines, recover the plain-text and the initial state 
 of the LFSR byimplementing the following steps.
 (1) Try probable words and phrases one after the other in all positions in the plain-text.
 (2) For each guess recover an interval of the key-stream of length 41. 
 Use its subin-terval of length 41 as an LFSR state.
 (3) Clock the LFSR back and forth to decrypt the cipher-text.
 (4) With index of coincidence decide if the decryption may be a plain-text (Englishtext). 
 If yes, then reconstruct the plain-text by adding spaces and the punctuation.
 (5) Find the LFSR initial state.
"""


import copy

cipher = [1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0,1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0,0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1,0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1,1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0,1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1,0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1,0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0,0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1,1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1,0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1,1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0,1, 0, 0]

N = len(cipher)


encryption_p = {
'A': 0b11000, 
'B': 0b10011, 
'C': 0b01110, 
'D': 0b10010,
'E': 0b10000, 
'F': 0b10110, 
'G': 0b01011, 
'H': 0b00101, 
'I': 0b01100, 
'J': 0b11010, 
'K': 0b11110, 
'L': 0b01001, 
'M': 0b00111, 
'N': 0b00110, 
'O': 0b00011, 
'P': 0b01101, 
'Q': 0b11101, 
'R': 0b01010, 
'S': 0b10100, 
'T': 0b00001,
'U': 0b11100, 
'V': 0b01111, 
'W': 0b11001, 
'X': 0b10111, 
'Y': 0b10101, 
'Z': 0b10001,

"CR": 0b00010,
"NL": 0b01000,
"LS": 0b11111,
"FS": 0b11011,
"SP": 0b00100,
"BL": 0b00000
}

encList = [None]*(2**5)

for i in encryption_p:
    encList[encryption_p[i]] = i


# Convert int to bitlist of length n+1
def intToBitList(int,length):
    out = []

    for k in range(length-1,-1,-1):
        out.append((int >> k) & 1)
    return out


# Convert a list of bits to int
def bitlistToInt(bitList):
    out = 0
    for j in bitList:
        out = (out << 1) | j
    return out


# lfsr "iterations" times for given "initialstate"
def lfsr(initialstate,iterations):
    output = []
    for i in range(iterations):
        output.append(initialstate[-1])
        last = int(initialstate[37]) ^ int(initialstate[40])
        initialstate = [last] + initialstate[:-1]

    return output


# lfsr for the length of the ciphertext
def lfsrFull(initialstate):
    output = []
    for i in range(N):
        output.append(initialstate[-1])
        last = int(initialstate[37]) ^ int(initialstate[40])
        initialstate = [last] + initialstate[:-1]

    return output


# Given probable words in ciphertext
probableWords = ["Generalstaff", "Politicalasylum", "Armouredbrigade","Parliament","Ambassador","Assumption","Uraniummine"]


general = []

# found probable words
for i in probableWords[1]:
    elem = encryption_p[i.upper()]
    general = general + intToBitList(elem,5)


# list to store potential initialstates
potential = []
for j in range(0,N-len(general)+1):

    lfsrCheck = []
    
    # XOR the cipher text, with the probable word
    for i in range(0,len(general)):
        lfsrCheck.append(general[i]^cipher[j+i])
        
    # Reverse the list of lfsr bits, to get correct order of Si when using the lfsr 
    lfsrCheck = lfsrCheck[::-1]

    # Check every part of the XORed part, run in through the LFSR, XOR Si and Mi, to check if it correspond to Ci. Add all potential initial states to a lsit
    for k in range(len(lfsrCheck)-40):
        check = lfsrCheck[k:41+k]
       
        si = lfsr(check,41)
        
        xor = []
        for i in range(len(si)):
            xor.append(si[i]^general[i])
                       
        if (xor) == cipher[j:41+j]:
            potential.append([check,j])


# Found state below that prints POLITICAL ASYLUM AND NO INTEREST IN POLITICAL MATTERS 
# [0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1]
# Total of 46 letters, which is the last 46 letters. I am therefore missing the first 40 letters or 200 bits

for i in potential:
    
    si = lfsrFull(i[0])
    
    output = []
    for k in range(len(si)-i[1]):
        output.append(si[k]^cipher[k+i[1]])
    
    plain = ""
    rem = len(output)%5
    
    for j in range(0,len(output)-rem,5):
        ele = [output[j],output[j+1],output[j+2],output[j+3],output[j+4]]
        plain += encList[bitlistToInt(ele)]
    if "POLITICALASYLUM" in plain:
        #print(plain)
        pass

# State found to print political asylum
clockbackstate = [0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1]

# Starting index of the state
clocks = 200

# Function to clock the LFSR backwards
def clockBack(initial,clocks): 
    state = copy.deepcopy(initial)
    for i in range(clocks):
        first = state[1:len(state)]
        last = state[0] ^ state[38]

        state = first + [last]
    return state

# Clocking the state used to find the part of the plaintext 200 times backwards to find the initial state
initialFinal = clockBack(clockbackstate,200)

# List used to store the bits of the plaintext
plainText = []

# Run the initialstate through the LFSR to get output S
lfsrLast = lfsrFull(initialFinal)

for i in range(N):
    plainText.append(lfsrLast[i] ^ cipher[i])

plainFinal = ""

# Split into 5-bit groups, and get letters from the CCITT2
for i in range(0,N,5):
    ele = [plainText[i],plainText[i+1],plainText[i+2],plainText[i+3],plainText[i+4]]
    plainFinal += encList[bitlistToInt(ele)]

print(initialFinal)
print(plainFinal)

# Plaintext     = APPARENTLY NUREYEV HAD NO INTENTION OF SEEKING POLITICAL ASYLUM AND NO INTEREST IN POLITICAL MATTERS.
# Initial state = [0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0]