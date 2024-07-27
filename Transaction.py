# -*- coding: utf-8 -*-
"""
Created on Wed Jun 19 14:45:09 2024

@author: M Golding-Quigley
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils


#==============================================================================
#   Transaction Class
#==============================================================================

class Transaction:
 
    def __init__ (self, sender_hash, recipient_hash, sender_public_key, amount, 
                  fee, nonce, signature, txid):
       
        self.sender_hash = sender_hash
        self.recipient_hash = recipient_hash
        self.sender_public_key = sender_public_key
        self.amount = amount
        self.fee = fee
        self.nonce = nonce
        self.signature = signature
        self.txid = txid
  
        
    def verify (self, sender_balance, sender_previous_nonce):
        '''
        Verifies transaction attributes are valid
        Raises exceptions if attributes are invalid
        
        Parameters
        ----------
        sender_balance: int
            Balance in senders wallet
            
        sender_previous_nonce: int
            Nonce generated for senders previous transaction
            -1 if no such transaction exists
            
        Returns
        -------
        None
            
        See Also
        --------
        checkInt(): Checks object is of type, int
        
        SHA1(): Generates SHA1 hash
        
        SHA256(): Generates SHA256 hash of transaction data
        
        '''
        
        # Verifies sender_hash and recipient_hash are both 20 bytes long
        if len(self.sender_hash) != 20 or len(self.recipient_hash) != 20:
            raise ValueError('bytes object expected of size 20')
          
        # Verifies sender_hash is the SHA-1 hash of sender_public_key
        assert self.sender_hash == SHA1(self.sender_public_key), 'invalid sender hash'
        
        # Verifies amount is a whole number 
        checkInt(self.amount)
        
        # Verifies amount is between 1 and sender_balance inclusive
        if not 1 <= self.amount <= sender_balance:
            if sender_balance < self.amount:
                raise ValueError('insufficient balance')
            else:
                raise ValueError(
                    f'transaction amount must be in range [1,{sender_balance}]'
                    )
        
        # Verifies fee is a whole number 
        checkInt(self.fee)
        
        # Verifies fee is between 0 and amount inclusive
        if not 0 <= self.fee <= self.amount:
            raise ValueError(
                f'transaction fee must be in range [0,{self.amount}]'
                )

        # Verifies nonce is sender_previous_nonce + 1
        if self.nonce != sender_previous_nonce + 1:
            raise ValueError('invalid nonce')

        # Verifies txid is the the hash of the other fields in Transaction
        assert self.txid == SHA256([self.sender_hash, self.recipient_hash,
                                self.sender_public_key, self.amount, self.fee,
                                self.nonce, self.signature]), 'invalid txid'
        
        # Verifies signature is a valid signature
        serialization.load_der_public_key(
                self.sender_public_key).verify(
                    self.signature, SHA256(
                        [self.recipient_hash, 
                         self.amount, 
                         self.fee, 
                         self.nonce]), 
                    ec.ECDSA(utils.Prehashed(hashes.SHA256())))

        return 
    
    
#==============================================================================
#   Functions
#==============================================================================

def create_signed_transaction (sender_private_key, recipient_hash, 
                               amount, fee, nonce):
    '''
    Generates new instance of the transaction class
    
    Parameters
    ----------
    sender_private_key: ECPrivateKey object
        Senders private key
            
    recipient_hash: bytes object
        Recipients wallet address hash
    
    amount: int
        Amount to be sent
    
    fee: int
        Chosen fee for the transaction
    
    nonce: int
        Transaction nonce
        
    Returns
    -------
    Transaction
        Instance of the Transaction class
            
    See Also
    --------
    sign(): Generates valid signature for the transaction using the 
            senders private key 
    
    SHA1(): Generates SHA1 hash
    
    SHA256(): Generates SHA256 hash of transaction data
    
    '''   
    # DER encoded public key
    sender_public_key = sender_private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.DER, 
                        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    # Sender hash                                            
    sender_hash = SHA1(sender_public_key)
    
    # Signature
    txdata = [recipient_hash, amount, fee, nonce]
    signature = sign(sender_private_key, txdata)
    
    # TXID
    txdata = [sender_hash, recipient_hash, sender_public_key, amount, fee, 
              nonce, signature]
    txid = SHA256(txdata)
    
    
    # Creates Transaction
    transaction = Transaction(sender_hash, recipient_hash, sender_public_key, 
                              amount, fee, nonce, signature, txid)
    
    return transaction


def SHA1(x):
    '''
    Generates SHA1 hash
        
    Parameters
    ----------
    x: bytes 
        Object to be hashed
            
    Returns
    -------
    bytes
        SHA1 hash of x
        
    '''
    digest = hashes.Hash(hashes.SHA1())
    digest.update(x)
    return digest.finalize()


def SHA256(txdata):
    '''
    Generates and concatenates SHA256 hash of transaction data
        
    Parameters
    ----------
    txdata: list 
        Objects to be hashed consisting of bytes objects and unsigned integers
            
    Returns
    -------
    bytes
        SHA256 hash of transaction data
        
    '''
    digest = hashes.Hash(hashes.SHA256())
    for i in txdata:
        if isinstance(i, int):
            i = i.to_bytes(8, byteorder = 'little', signed = False)
        digest.update(i)
    return digest.finalize()


def sign(private_key, txdata):
    '''
    Generates signature for the transaction
    
    Parameters
    ----------
    private_key: ECPrivateKey object
        Senders private key
            
    txdata: list 
        Objects to be hashed consisting of bytes objects and unsigned integers
        
    Returns
    -------
    signature_hash
        Hash of transaction data signed with EC private key
    
    '''  
    sighash = SHA256(txdata)

    signature_hash = private_key.sign(sighash,
    ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return signature_hash


def checkInt (obj):
    '''
    Verifies object is of type, int
        Raises exceptions if invalid type
        
    Parameters
    ----------
    obj: any
        Object of any type to be tested
            
    Returns
    -------
    None
        
    '''
    if not isinstance(obj, int):
        raise TypeError(
            f"int expected, got '{type(obj).__name__}'")


#==============================================================================
#   Additional Callable Function
#==============================================================================

def check_address(hash):
    if len(hash) != 40:
        return False

    try:
        int(hash,16)
        return True
    except:
        return False



