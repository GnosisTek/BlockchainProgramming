# -*- coding: utf-8 -*-
"""
Created on Mon Jun 24 15:23:33 2024

@author: M Golding-Quigley
"""
import unittest

from Transaction import Transaction
from Transaction import create_signed_transaction
from Transaction import SHA256
from Transaction import sign

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import exceptions


#==============================================================================
#   Functions
#==============================================================================

def valid_transaction(amount, fee, nonce):
    '''
    Generates a valis transaction
        
    Parameters
    ----------
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
    
    '''

    transaction = create_signed_transaction(
                        ec.generate_private_key(
                            ec.SECP256K1()), 
                        bytes.fromhex("5c1499a0484ace2f731b0afb83241e15f0e168ca"),
                        amount,
                        fee,
                        nonce)
    return transaction


#==============================================================================
#   Test Class
#==============================================================================

class TransactionTest(unittest.TestCase):
    

    def test_create_signed_transaction(self):
        '''Tests create_signed_transaction succeeds'''
        
        transaction = valid_transaction(5, 1, 6)
        
        self.assertEqual(transaction.verify(8, 5), None)
    
    
    def test_invalid_txid_exception(self):
        '''Tests exception is raised due to invalid txid if fee is modified'''
        
        transaction = valid_transaction(5, 1, 6)
        
        transaction.fee = 2
        
        self.assertRaisesRegex(AssertionError, "invalid txid",
                       transaction.verify, 8, 5)

    
    def test_invalid_signature_exception1(self):
        '''Tests exception is raises due to invalid signature if amount is
            changed and valid txid is generated'''
        
        transaction = valid_transaction(5, 1, 6)
        
        transaction.amount = 6
        
        txdata = [transaction.sender_hash, transaction.recipient_hash,
                  transaction.sender_public_key, transaction.amount, 
                  transaction.fee, transaction.nonce, transaction.signature]
        
        transaction.txid = SHA256(txdata)
        
        self.assertRaises(exceptions.InvalidSignature, transaction.verify, 8, 5)
        
    
    def test_insuffient_balance_exception(self):
        '''Tests exception is thrown due to insuffient balance'''
        
        transaction = valid_transaction(5, 1, 6)
        
        self.assertRaises(ValueError, transaction.verify, 4, 5)
        
    
    def test_invalid_nonce_exception(self):
        '''Tests exception is thrown due to invalid sender_nonce'''
        
        transaction = valid_transaction(5, 1, 6)
        
        self.assertRaises(ValueError, transaction.verify, 10, 6)
        
    
    def test_invalid_signature_exception2(self):
        '''Tests exception is thrown due to invalid signature if signature is 
            replaced by that of another transaction'''
        
        transaction = valid_transaction(5, 1, 6)
        
        new_private_key = ec.generate_private_key(ec.SECP256K1())
        
        txdata = [transaction.recipient_hash, transaction.amount,
                  transaction.fee, transaction.nonce]
        
        transaction.signature = sign(new_private_key, txdata)
        
        txdata = [transaction.sender_hash, transaction.recipient_hash,
                  transaction.sender_public_key, transaction.amount, 
                  transaction.fee, transaction.nonce, transaction.signature]
        
        transaction.txid = SHA256(txdata)
        self.assertRaises(exceptions.InvalidSignature, transaction.verify, 8, 5)
  
    
    def test_valid_transaction_verification(self):
        '''Tests that a valid transaction verifies correctly'''

        transaction = Transaction(
                            bytes.fromhex("3df8f04b3c159fdc6631c4b8b0874940344d173d"),
                            bytes.fromhex("5c1499a0484ace2f731b0afb83241e15f0e168ca"),
                            bytes.fromhex("3056301006072a8648ce3d020106052b8104000a" +
                                          "03420004886ed03cb7ffd4cbd95579ea2e202f1d" +
                                          "b29afc3bf5d7c2c34a34701bbb0685a7b535f1e6" +
                                          "31373afe8d1c860a9ac47d8e2659b74d437435b0" +
                                          "5f2c55bf3f033ac1"),
                            10,
                            2,
                            5,
                            bytes.fromhex("3046022100f9c076a72a2341a1b8cb68520713e1" +
                                          "2f173378cf78cf79c7978a2337fbad141d022100" +
                                          "ec27704d4d604f839f99e62c02e65bf60cc93ae1"
                                          "735c1ccf29fd31bd3c5a40ed"),
                            bytes.fromhex("ca388e0890b71bd1775460d478f26af3776c9b4f" +
                                          "6c2b936e1e788c5c87657bc3"))

        self.assertEqual(transaction.verify(20, 4), None)
    
        
unittest.main(exit=False)
