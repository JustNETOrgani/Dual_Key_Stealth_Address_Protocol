# Python implementation of the Dual-key Stealth Address by JustNETOrgani.
# OOP

import sha3
import ecdsa
import os
import sys
from ecdsa import SigningKey, VerifyingKey
from ecdsa.util import randrange
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.curves import SECP256k1
from random import randint
from ecpy.curves import Curve, Point


# ECC Constants begin.
# Based on secp256k1, http://www.oid-info.com/get/1.3.132.0.10

_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141     # Modolus or EC order
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141     # Order of G
_h = 0x01   # Co-factor

curve_secp256k1 = ecdsa.ellipticcurve.CurveFp(_p, _a, _b)
generator_secp256k1 = ecdsa.ellipticcurve.Point(curve_secp256k1, _Gx, _Gy, _r)
oid_secp256k1 = (1, 3, 132, 0, 10)
SECP256k1 = ecdsa.curves.Curve("SECP256k1", curve_secp256k1, generator_secp256k1, oid_secp256k1)
curve = curve_secp256k1
cv = Curve.get_curve('secp256k1')
Generator = Point(_Gx, _Gy, cv)
Q = _r                          #   Finite field Modulus.

#   Ecc Constants declarations.


def random_secret(): 
    '''
    Method to generate private key.
    '''           
    global byte_array

    byte_array = os.urandom(32)
        
    joinArray = "".join([str(i) for i in byte_array])
    convert_to_int = int(joinArray)
    
    encode_int = int(hex(convert_to_int), 16)

    return (encode_int%Q)


def get_point_pubkey(point):
    '''
    Converts point to hex format.
    '''
    if point.y & 1:
        key = '03' + '%064x' % point.x
    else:
        key = '02' + '%064x' % point.x
    return key


def genSecrets():
    '''
    Generation of private keys begin.
    '''
    secretKeys = ['v', 'b', 'r']         # Secrets initialization

    for index in range(len(secretKeys)):
        secretKeys[index] = random_secret()
    #print("Value of v is:", secretKeys[0])
    #print("Value of b is:", secretKeys[1])
    #print("Value of r is:", secretKeys[2])
    v, b, r = int(secretKeys[0]), int(secretKeys[1]), int(secretKeys[2])
    return v, b, r


# These are done by transaction Receiver (Bob).

def ViewPubKey(v):
    '''
    Get the public key point. ---- Scan public key for receiver (V).
    secret here is small v and V Scan/View public key for receiver Bob.
    '''
    V = (v * Generator)               
    #print("The value of V is", V)
    pubkey = get_point_pubkey(V)
    print("The First Stealth address is: ", pubkey)
    return V, v


def SpendPubKey(b):
    '''
    Second public key  ----- Spend public key for receiver (B)
    B and V do not appear on the Blockchain. Only Transaction initiator and Receiver know them.
    '''
    B = (b * Generator)
    pubkey = get_point_pubkey(B)
    print("The Second Stealth address is: ", pubkey)      
    return B, b

    
#   To be done by Transaction Initiator (Alice)
def BigRforSender(r):
    '''
    This is done by transaction Initiator (Alice)
    Creating R for the Transaction initiator.
    This is R ---- R - r.G
    '''
    R = (r * Generator)     
    oneTym = get_point_pubkey(R)
    print("Transaction Initiator's one-time-nonce is: ", oneTym)
    print('')      
    return R, r


def Diffie_HelmanProtocol(V, v, R, r):
    '''
    Diffie-Helman Key exchange protocol begins.
    At the end of the protocol, ASharedSec == BSharedSec (c--shared secret) must be same.
    '''
    # For Transaction initiator (Alice)

    px =V.x
    py =V.y 
    VPoint = Point(px,py,cv)
    ASharedSec = cv.mul_point(r,VPoint)
    ASharedSecHash = sha3.keccak_256((str(cv.mul_point(r, VPoint))).encode())
    AsharedSecInHexForm = ASharedSecHash.hexdigest()

    
    # For Transaction receiver (Bob)

    px =R.x
    py =R.y 
    RPoint = Point(px,py,cv)
    BSharedSec = cv.mul_point(v, RPoint)                             
    BSharedSecHash = sha3.keccak_256((str(cv.mul_point(v, RPoint))).encode())
    BsharedSecInHexForm = BSharedSecHash.hexdigest()
    

    if AsharedSecInHexForm == BsharedSecInHexForm:      # Confirming Shared secret is same for both Alice and Bob.
        print("Alice's secret is ", AsharedSecInHexForm)
        print("Bob's secret is ", BsharedSecInHexForm)
        print('')
        #print("Alice's secret Hash is: ", ASharedSecHash)
        #print("Bob's secret Hash is: ", BSharedSecHash)
        print('')
        print("The Secret is the same for both Alice and Bob.")
        print('')
    else:
        print("The Secret is not the same.")
    return VPoint, RPoint

    # Diffie-Helman Key-Exchange Protocol ends here.


def stealthAddforBlockchain(b, v, RPoint, r, VPoint, B):
    '''
    To be done by Transaction Initiator (Alice).

    # Generation of the publicly visible Address that will appear on the Blockchain begins.

    # H(r.V).G+B = H(v.R).G+b.G ---- Can be done by: Sender, Receiver and Auditor.
    '''

    # Doing second part first. 
    pubVisAddPrep = cv.mul_point(int(((sha3.keccak_256((str(cv.mul_point(v, RPoint))).encode())).hexdigest()), 16), Generator)
    pubVisAddPrepSec = cv.mul_point(b, Generator)
    pubVisAddress = cv.add_point(pubVisAddPrep, pubVisAddPrepSec)           # Address Point
    pubVisAddressHex = (sha3.keccak_256((str(pubVisAddress)).encode())).hexdigest()
    print("The Publicly visible Stealth address to appear on Blockchain is: ", pubVisAddressHex)

    # Verifying for first part.
    pubVisAddPrep_2 = cv.mul_point(int(((sha3.keccak_256((str(cv.mul_point(r, VPoint))).encode())).hexdigest()), 16), Generator)
    pubVisAddress_2 = cv.add_point(pubVisAddPrep_2, B)                       # Address Point
    pubVisAddressHex_2 = (sha3.keccak_256((str(pubVisAddress_2)).encode())).hexdigest()
    print("The Publicly visible Stealth address to appear on Blockchain is: ", pubVisAddressHex_2)
    print('')

    if pubVisAddressHex == pubVisAddressHex_2:
        print("The Same stealth adddress is publicly visible on the Blockchain.")
    else:
        print("Mismatch publicly visible address on the Blockchain.")
    
    # Generation of the publicly visible Address that will appear on the Blockchain ends here.



def ReceiverTransReceipt(v, RPoint, b):
    '''
    Receiver retrieving transaction using his private key begins. It is Ephemeral private key.
    The auditor & transaction initiator are not able to retrieve transactions because they do not know b. 
    Only the recipient knows b and can compute sk = H(v.R)+b mod Q
    c + b = H(v.R)+b          # Hash (Scaler multi. and Point) to get a number then do add priv. key. 
    '''
    print('')
    KeyPrepMul = (sha3.keccak_256((str((cv.mul_point(v, RPoint)))).encode()))   
    KeyPrepHex = KeyPrepMul.hexdigest()
    EphemeralPrivKey = KeyPrepHex + hex(b)
    print("Transaction Receiver can get transactions using: ", EphemeralPrivKey)

    # Generation of Ephemeral Private key ends.


def main():
    '''
    Main Application Execution.
    '''
    print('')
    print("******************* Stealth Address - Python Implementation *********************")
    print('')

#   Step 1: Generation of secrets
    v, b, r = genSecrets()

#   Step 2: Generation of View or Scan public key.
    V, v = ViewPubKey(v)

#   Step 3: Generation of Spend public key.
    B, b = SpendPubKey(b)

#   Step 4: One-time secret generation by Transaction Initiator (Alice).
    R, r = BigRforSender(r)

#   Step 5: Activation of Diffie-Helman Protocol.
    VPoint, RPoint = Diffie_HelmanProtocol(V, v, R, r)

#   Step 6: Creation of Stealth address visible in Blockchain.
    stealthAddforBlockchain(b, v, RPoint, r, VPoint, B)

#   Step 7: Transaction receiver retrieves transactions.
    ReceiverTransReceipt(v, RPoint, b)
    

#   Execution/Run time.
if __name__ == '__main__':
    main()

