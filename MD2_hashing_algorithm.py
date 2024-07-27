# -*- coding: utf-8 -*-
"""
Created on Wed May  1 14:33:30 2024

@author: M Golding-Quigley
"""


def S():
    '''
    Defines MD2 constants.
    
    Returns
    -------
    arr
        Array of constants, S, from MD2 definition
    
    '''
    S = [41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
         98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
         30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
         190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
         169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
         128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
         255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
         79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
         69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
         27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
         85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
         44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
         106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
         120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
         242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
         49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20]
    return S    


def convertToAscii(msg):
    '''
    Converts each character of the message
    to its corresponding ASCII code.
    
    Parameters
    ----------
    msg: str
        Message to be hashed
        
    Returns
    -------
    arr
        Array of ASCII code bytes representing 
        each character in msg
        
    Example
    -------
    >>> convertToAscii('abc')
    [97, 98, 99]
    
    '''
    msg = [ord(ch) for ch in msg]
    return msg


def addPadding(msg):
    '''
    Appends padding to the msg array, ensuring
    that it's size is congruent to 0, mod 16.
    i-bytes of value i are appended. This is
    performed regardless of whether the initial 
    array, msg, is already congruent to 0, mod 16.
    Between 1-16 bytes are appended.
    
    Parameters
    ----------
    msg: arr
        Array of ASCII code bytes
        
    Returns
    -------
    arr
        Array of ASCII code bytes with appended
        padding. Size is congruent to 0, mod 16
        
    Examples
    --------
    >>> addPadding([72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100])
    [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 5, 5, 5, 5, 5]
    
    
    >>> addPadding([76, 111, 118, 101, 32, 105, 115, 32, 116, 104, 101, 32,\
                    119, 97, 121])
    [76, 111, 118, 101, 32, 105, 115, 32, 116, 104, 101, 32, 119, 97, 121, 1]
    
    
    >>> addPadding([84, 114, 97, 110, 115, 99, 101, 110,\
                    100, 83, 97, 109, 115, 97, 114, 97])                        # doctest: +NORMALIZE_WHITESPACE
    [84, 114, 97, 110, 115, 99, 101, 110, 100, 83, 97, 109, 115, 97, 114,
     97, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
    
    '''
    padsize = 16 - (len(msg) % 16)
    pad = padsize * [padsize]
    msg += pad
    return msg


def checksumAppend(msg):
    '''
    Generates and appends a checksum to the array, msg, to aid in 
    error detection
    
    Parameters
    ----------
    msg: arr
        Array of ASCII code bytes with size congruent
        to 0, mod 16
        
    Returns
    -------
    arr
        Array of ASCII code bytes with 16 byte checksum appended
        
    See Also
    --------
    S(): MD2 constants
        
    Examples
    --------
    >>> checksumAppend([72, 101, 108, 108, 111, 32, 119, 111, 114,\
                        108, 100, 5, 5, 5, 5, 5])                               # doctest: +NORMALIZE_WHITESPACE
    [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 5, 5, 5, 5, 5,
     148, 68, 103, 161, 177, 96, 140, 14, 156, 49, 144, 176, 40, 23, 5, 41]
    
    '''
    C = [0] * 16
    L = 0
    for i in range (int(len(msg) / 16)):
        for j in range (16):
            c = msg[i*16+j]
            C[j] = C[j] ^ S()[c ^ L]
            L = C[j]
    return msg + C


def mdDigest(msg):
    '''
    Generates the 48 byte message digest buffer. The first 16 bytes
    represent the hash of msg
    
    Parameters
    ----------
    msg: arr
        Array of ASCII code bytes with size congruent
        to 0, mod 16 
        
    Returns
    -------
    arr
        Array of the 48-byte message digest buffer
        
    See Also
    --------
    S(): MD2 constants
        
    Examples
    --------
    >>> mdDigest([66, 101, 32, 104, 97, 112, 112, 121, 8, 8, 8, 8, 8, 8,\
                  8, 8, 121, 188, 52, 191, 29, 86, 224, 70, 95, 39, 18,\
                  43, 60, 218, 149, 64])                                        # doctest: +NORMALIZE_WHITESPACE
    [67, 15, 194, 124, 38, 197, 140, 20, 208, 60, 212, 250, 64, 118, 80, 205,
     246, 189, 183, 206, 24, 149, 188, 118, 65, 126, 239, 13, 202, 86, 152, 32,
     145, 238, 163, 43, 35, 30, 49, 185, 198, 238, 215, 225, 59, 200, 74, 33]

    '''
    N = int(len(msg) / 16) # Number of 16-byte blocks
    
    X = 48 * [0] # Initialising 48-byte buffer
    
    for i in range(N):
        for j in range(16):
            X[16+j] = msg[i*16+j]
            X[32+j] = (X[16+j] ^ X[j])
    
        t = 0
        for j in range(18):
            for k in range(48):
                t = X[k] ^ S()[t]
                X[k] = t
            t = (t + j) % 256
    return X


def MD2(msg):
    '''
    Generates the 128-bit message digest hash of 
    the string, msg.
    
    Parameters
    ----------
    msg: str
        Message to be hashed
        
    Returns
    -------
    str:
        Hash of the string, msg
        
    See Also
    --------
    convertToAscii(): Converts message to ASCII code
    
    addPadding(): Adds padding to the message
    
    checksumAppend(): Appends checksum
    
    mdDigest(): Generates message digest
        
    Examples
    --------
    >>> MD2("")
    '8350e5a3e24c153df2275c9f80692773'
    
    >>> MD2 ("a")
    '32ec01ec4a6dac72c0ab96fb34c0b5d1'
    
    >>> MD2 ("abc")
    'da853b0d3f88d99b30283a69e6ded6bb'
    
    >>> MD2 ("message digest")
    'ab4f496bfb2a530b219ff33031fe06b0'
    
    >>> MD2 ("abcdefghijklmnopqrstuvwxyz")
    '4e8ddff3650292ab5a4108c3aa47940b'
    
    >>> MD2 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    'da33def2a42df13975352846c30338cd'
    
    >>> MD2 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
    'd5976f79d83d3a0dc9806c3c66f3efd8'
    
    '''
    msg = checksumAppend( addPadding (convertToAscii (msg)))
    # Concatenates first 16 elements of the message digest
    # in hexidecimal form as a string 
    hash = "".join(map(lambda x: "{:02x}".format(x), mdDigest(msg)[0:16]))
    return hash





#==============================================================================
#   DOCTEST
#==============================================================================

'''
if __name__ == "__main__":
    import doctest
    doctest.testmod()
'''
