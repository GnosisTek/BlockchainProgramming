# -*- coding: utf-8 -*-
"""
Created on Wed Jul 10 22:55:23 2024

@author: M Golding-Quigley
"""
import multiprocessing as mp
from cryptography.hazmat.primitives import hashes

#==============================================================================
#   UserState Class
#==============================================================================

class UserState:
    def __init__(self, balance, nonce):
        
        self.balance = balance
        self.nonce = nonce

#==============================================================================
#   Block Class
#==============================================================================
        
class Block:
    def __init__(self, previous, height, miner, transactions, timestamp, 
                 difficulty, block_id, nonce):
        
        self.previous = previous
        self.height = height
        self.miner = miner
        self.transactions = transactions
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.block_id = block_id
        self.nonce = nonce
        
        
    def verify_and_get_changes(self, difficulty, previous_user_states):
        '''
        Verifies block attributes are valid
        Raises exceptions if attributes are invalid
        Generates updated userstates 
        
        Parameters
        ----------
        difficulty: int
            Difficulty of the block
            
        previous_user_states: dict
            Dictionary mapping userhash to previous corresponding UserState 
            
        Returns
        -------
        new_user_states: dict
            Dictionary mapping userhash to updated UserStates
            
        See Also
        --------
        generateDigest(): Generates SHA256 hash of block data
        
        getUserState(): Fetches most recent UserState corresponding with
                        the userhash
                        
        '''

        MINER_REWARD = 10000

        # Verifies difficulties are equivalent
        assert self.difficulty == difficulty, 'block difficulty mismatch'
        
        # Verifies block_id is the valid hash of the fields
        transaction_ids = b''.join([i.txid for i in self.transactions])
        assert self.block_id == generateDigest([self.previous, self.miner, transaction_ids,
                                        self.timestamp, self.difficulty,
                                        self.nonce]).finalize(), 'invalid block ID'

        # Verifies the number of transactions do not exceed the maximum allowed    
        if len(self.transactions) > 25:
            raise ValueError('maximum transactions exceeded, max: 25')
        
        # Verifies miner hash is 20 bytes long
        if len(self.miner) != 20:
            raise ValueError('bytes object expected of size 20')

        # Verifies block_id meets proof of work requirements    
        target = 2 ** 256 // difficulty
        assert int.from_bytes(self.block_id, 'big') <= target, 'invalid proof of work'
            
        # Verifies each transaction and updates the new userstate after the
        # transaction
        new_user_states = dict()
        
        for i in self.transactions:
            
            # Fetches previous user state verifies the transaction
            userstate_sender = getUserState(i.sender_hash, 
                                            previous_user_states, 
                                            new_user_states) 
            i.verify(userstate_sender.balance, userstate_sender.nonce)
            
            userstate_recipient = getUserState(i.recipient_hash, 
                                               previous_user_states, 
                                               new_user_states)   
            
            # Updates sender state
            userstate_sender.balance -= i.amount
            userstate_sender.nonce += 1
            new_user_states.update({i.sender_hash: userstate_sender})
            
            # Updates recipient state
            userstate_recipient.balance += (i.amount - i.fee)
            new_user_states.update({i.recipient_hash: userstate_recipient})
            
        
        # Calculates total fees for transaction in the block and fetches miners
        # userstate
        fees = sum([i.fee for i in self.transactions])
        userstate_miner = getUserState(self.miner, 
                                        previous_user_states, 
                                        new_user_states) 

        # Updates miner state
        userstate_miner.balance += (fees + MINER_REWARD)
        new_user_states.update({self.miner: userstate_miner})
                
        return new_user_states
    

#==============================================================================
#   Functions
#==============================================================================

def getUserState(userhash, previous_user_states, new_user_states):
    '''
    Fetches most recent userstate associated with userhash  
    If no previous state exists, one is instantiated
    
    Parameters
    ----------
    userhash: bytes object
        Wallet address hash
    
    previous_user_states: dict
        Dictionary mapping userhash to corresponding UserState from previous 
        block
    
    new_user_states: dict
        Dictionary mapping userhash to corresponding UserState from current 
        block
            
    Returns
    -------
    userstates: UserState object
        Most recent userstate associated with userhash
        
    '''
    if userhash in new_user_states:
        userstate = new_user_states[userhash]
    elif userhash in previous_user_states:
        userstate = previous_user_states[userhash]
    else: 
        userstate = UserState(0, -1)
    return userstate
        

def mine_block(previous, height, miner, transactions, timestamp, difficulty):
    '''
    Mines new block
    
    Parameters
    ----------
    previous: bytes object
        32 byte block_id of previous block
        
    height: int
        The number of preceeding blocks in the blockchain
        
    miner: bytes object
        Wallet address hash of miner
        
    transactions: list
        List of Transaction objects contained in the block
        
    timestamp: int
        Unix Time of mining block

    difficulty: int
        Difficulty of the block
            
    Returns
    -------
    block: Block object
        Instance of the block class corresponding to the mined block
            
    See Also
    --------
    generate_block_id(): Generates block_id
    
    generate_block_id_optimised(): Generates block_id using multiprocessing
                    
    '''
    
    transaction_ids = b''.join([i.txid for i in transactions])
    
    blockdata = [previous, miner, transaction_ids, timestamp, difficulty]
    
    #**************************************************************************
    # SET TO TRUE FOR SERIAL PROCESSING AND FALSE FOR MULTIPROCESSING
    #**************************************************************************
    if True:
        block_id, nonce = generate_block_id(blockdata)
    else:
        block_id, nonce = generate_block_id_optimised(blockdata)
        
    
    block = Block(previous, height, miner, transactions, timestamp, difficulty,
                  block_id, nonce)
    
    return block


def generate_block_id(blockdata):
    '''
    Generates and concatenates SHA256 hash of block data
    Calculates nonce that satisfies target conditions
        
    Parameters
    ----------
    blockdata: list 
        Objects to be hashed consisting of bytes objects and unsigned integers
            
    Returns
    -------
    digest: bytes
        SHA256 hash of block data
        
    nonce: int
        Nonce value that satisfies target conditions with given difficulty
        
    See Also
    --------
    generateDigest(): Generates hash digest of blockdata without nonce
           
    '''
    target = 2 ** 256 // blockdata[4]
    
    digest = generateDigest(blockdata)
    
    # Proof of work implementation
    nonce = 0
    while True:
        digest_nonce = digest.copy()
        digest_nonce.update(nonce.to_bytes(8, byteorder = 'little', signed = False))
        if not int.from_bytes(digest_nonce.finalize(), 'big') > target:
            break        
        nonce += 1    
    
    digest.update(nonce.to_bytes(8, byteorder = 'little', signed = False))
    return digest.finalize(), nonce


def generateDigest(blockdata):
    '''
    Generates and concatenates SHA256 hash digest of block data
        
    Parameters
    ----------
    blockdata: list 
        Objects to be hashed consisting of bytes objects and unsigned integers
            
    Returns
    -------
    digest
        Hash digest of block data
        
    '''
    digest = hashes.Hash(hashes.SHA256())
    for i in blockdata:
        if isinstance(i, int):
            if blockdata.index(i) != 4:
                size = 8
            else:
                size = 16
            i = i.to_bytes(size, byteorder = 'little', signed = False)
        digest.update(i)
    return digest


#==============================================================================
#   Multiprocessing
#==============================================================================

def worker (initial_nonce, step, target, blockdata, result):
    '''
    Generates and concatenates SHA256 hash of block data
    Worker function for multiprocessing in generate_block_id_optimised()
        
    Parameters
    ----------
    initial_nonce: int
        Starting nonce for proof of work
        
    step: int
        Step to subsequent nonces
        
    target: int
        Max value for blockid
        
    blockdata: list 
        Objects to be hashed consisting of bytes objects and unsigned integers
    
    result: list
        List that is either empty or contains the resulting blockid and nonce
            
    Returns
    -------
    None
    
    See Also
    --------
    generateDigest(): Generates hash digest of blockdata without nonce
        
    '''
    
    # Checks result has not already been found
    if len(result) != 0:
        return
    nonce = initial_nonce
    digest = generateDigest(blockdata)
    
    # Proof of work implementation
    while True:
        digest_nonce = digest.copy()
        digest_nonce.update(nonce.to_bytes(8, byteorder = 'little', signed = False))
        if not int.from_bytes(digest_nonce.finalize(), 'big') > target:
            digest.update(nonce.to_bytes(8, byteorder = 'little', signed = False))
            result.append(digest.finalize())
            result.append(nonce)
            return
        nonce += step         


def generate_block_id_optimised(blockdata):
    '''
    Generates and concatenates SHA256 hash of block data
    Calculates nonce that satisfies target conditions using multiprocessing
        
    Parameters
    ----------
    blockdata: list 
        Objects to be hashed consisting of bytes objects and unsigned integers
            
    Returns
    -------
    digest: bytes
        SHA256 hash of block data
        
    nonce: int
        Nonce value that satisfies target conditions with given difficulty
        
    '''
    
    target = 2 ** 256 // blockdata[4]
    
    cpus = mp.cpu_count()

    manager = mp.Manager()
    result = manager.list()    
    processes = [mp.Process(target=worker, args=(i, cpus, target, blockdata, result)) for i in range(cpus)]

    for p in processes:
        p.start()
        
    for p in processes:
        p.join()

    return result[0], result[1]