# Meet in the middle attack on SPN for given plain-text/cipher-text pairs x, y described in Stinson’s ”Cryptography, theory and practice”, second edition, pages 74-79:
# Algorithm recovers the 32-bit key.

# All plaintext,ciphertext pairs (x,y)
x1 = [0,0,0,0,0,0,0,1,0,1,1,1,0,0,1,0] 
y1 = [1,0,0,0,1,1,0,1,1,0,1,0,1,0,1,1]
      
x2 = [0,1,1,0,0,0,0,1,1,1,1,0,1,0,0,0] 
y2 = [1,1,0,0,0,0,1,0,0,0,1,1,1,1,0,1]
     
x3 = [1,1,0,1,1,1,0,0,0,1,1,1,1,1,0,1] 
y3 = [0,0,0,0,1,1,0,0,0,0,1,1,1,0,1,0]

x4 = [0,0,1,1,0,0,0,0,1,0,0,1,0,1,1,1] 
y4 = [1,0,0,0,1,0,0,1,0,0,1,0,0,0,1,0]


# S-box
sbox1 = [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7]

# Inverse S-box
sboxinv = [14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5]

#Permutation
permutation = [1,5,9,13,2,6,10,14,3,7,11,15,4,8,12,16]


# Convert a list of bits to int
def bitlistToInt(bitList):
    out = 0
    for j in bitList:
        out = (out << 1) | j
    return out

# Convert int to bitlist of length n+1
def intToBitList(int,length):
    out = []

    for k in range(length,-1,-1):
        out.append((int >> k) & 1)
    return out
    

# S-box function    
def sBox(lst):
    out = []
    for i in range(0,16,4):
        bits = [lst[i],lst[i+1],lst[i+2],lst[i+3]]
        
        tmp = bitlistToInt(bits)
        swap = sbox1[tmp]

        for k in range(3,-1,-1):
            out.append((swap >> k) & 1)
    return out

# Inverse S-box function
def inverseS(lst):
    out = []
    for i in range(0,16,4):
        bits = [lst[i],lst[i+1],lst[i+2],lst[i+3]]
        
        tmp = bitlistToInt(bits)
        swap = sboxinv[tmp]

        for k in range(3,-1,-1):
            out.append((swap >> k) & 1)
    return out

# Permutation function
def permute(lst):
    out = []
    n = len(lst)
    for i in range(n):
        out.append(lst[permutation[i]-1])
    return out

# Regular round in SPN
def regularRound(inp,roundKey):
    xor1 = bitlistToInt(inp) ^ bitlistToInt(roundKey)
    xor1 = intToBitList(xor1,15)
    out = permute(sBox(xor1))

    return out

# First irregular round in SPN
def irregularRound1(inp,roundKey):
    xor1 = bitlistToInt(inp) ^ bitlistToInt(roundKey)
    xor1 = intToBitList(xor1,15)
    out = sBox(xor1)

    return out

# Second irregular round in SPN
def irregularRound2(inp,roundKey):
    xor1 = bitlistToInt(inp) ^ bitlistToInt(roundKey)
    xor1 = intToBitList(xor1,15)

    return xor1

# Inverse of last round N
def irregularD(key,out):
    ireg = inverseS(out)
    return intToBitList(bitlistToInt(ireg) ^ bitlistToInt(key),15)

# Inverse of round N-1
def irregularD2(key,out):
    return intToBitList((bitlistToInt(key) ^ bitlistToInt(out)),15)

# Inverse of regular round
def regularD(key,out):
    back = inverseS(permute(out))
    return intToBitList((bitlistToInt(key) ^ bitlistToInt(back)),15) 

# Full encryption
def encrypt(inp,key):
    k1 = key[0:16]
    k2 = key[4:20]
    k3 = key[8:24]
    k4 = key[12:28]
    k5 = key[16:32]

    return irregularRound2(irregularRound1(regularRound(regularRound(regularRound(inp,k1),k2),k3),k4),k5)

# Full decryption
def decrypt(out,key):
    k1 = key[0:16]
    k2 = key[4:20]
    k3 = key[8:24]
    k4 = key[12:28]
    k5 = key[16:32]

    return regularD(k1,regularD(k2,regularD(k3,(irregularD(k4,irregularD2(k5,out))))))
    
# Meet-in-the middle attack
def fullRound(inp1,out1,inp2,out2):
    
    # List to store all computations
    one = [[] for x in range(2**12)]

    # Compute first two rounds and add to index K(1) ∩ K(2) as integer in the list "one"
    for i in range(2**20):
        k = intToBitList(i,19)
        (one[bitlistToInt(k[8:20])]).append([k,regularRound(regularRound(inp1,k[0:16]),k[4:20])])
    
    # Last three rounds
    for i in range(2**24):
        k = intToBitList(i,23)
        k5 = k[8:24]
        k4 = k[4:20]
        k3 = k[0:16]
        
        # Compute last three rounds
        two = regularD(k3,irregularD(k4,irregularD2(k5,out1)))

        # Check for match at index K(1) ∩ K(2) as integer
        for j in one[bitlistToInt(k[0:12])]:
            if two == j[1]:
                # Compute K = K(1) ∪ K(2)
                bigK = j[0][0:8] + k
                
                # Check if encryption using K, works for three of the given plaintext,ciphertext pairs 
                if (encrypt(inp1,bigK) == out1) and (encrypt(inp2,bigK) == out2) and (encrypt(x3,bigK) == y3):
                    print(bigK,"answer")
                    return bigK
        
            

fullRound(x1,y1,x2,y2)


