module AES.Internal
( setupForTransform
, ecb
, encryptInit
, decryptInit
, rotate
, fieldMult
)
where

import Prelude hiding (round)

import qualified Data.Bits as B (shiftL, shiftR, xor, (.&.))
import Data.Bits()
import qualified Data.List as L (concat, map, transpose)
import Data.Word (Word8)

import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (append, pack, unpack)

import qualified Common

---------------------------------
-- Block Cipher Mode Functions --
---------------------------------

ecb :: Int
    -> (Int -> [[Word8]] -> [[Word8]] -> [[Word8]])
    -> [[Word8]]
    -> [Word8]
    -> ByteString
    -> ByteString
ecb _ _ _ [] encrypted = encrypted
ecb maxRound f roundKeys bytes encrypted = ecb maxRound f roundKeys bytes' encrypted'
  where state = stateInit $ take 16 bytes
        bytes' = drop 16 bytes
        encrypted' = BS.append encrypted $ stateToByteStr $ f maxRound roundKeys state

--------------------
-- Init Functions --
--------------------

setupForTransform :: ByteString -> (Int, [[Word8]])
setupForTransform k = (maxRound, roundKeys)
  where key = keyInit k
        roundKeys = keySchedule key
        maxRound = length key + 6

-- Turns ByteString representing key into matrix e.g. 128 bit keys have form
-- | b1  b2  b3  b4  |
-- | b5  b6  b7  b8  |
-- | b8  b9  b10 b11 |
-- | b12 b13 b14 b15 |
-- 192 bit keys have 6 rows, 256 have 8 rows
keyInit :: ByteString -> [[Word8]]
keyInit bytes = key
  where flatKey = BS.unpack bytes
        key = Common.flatListToMatrix 4 flatKey []

-- Turns ByteString representing 128 bit block into matrix e.g.
-- | b1 b5 b9  b13 |
-- | b2 b6 b10 b14 |
-- | b3 b7 b11 b15 |
-- | b4 b8 b12 b16 |
-- Notice this matrix is the _transpose_ of how the key was interpreted
stateInit :: [Word8] -> [[Word8]]
stateInit byteList = state
  where matrix = Common.flatListToMatrix 4 byteList []
        state = L.transpose matrix

--------------------------------
-- Rijndael Encrypt Functions --
--------------------------------

-- Round 0: starts the encryption, adds the first round key
encryptInit :: Int -> [[Word8]] -> [[Word8]] -> [[Word8]]
encryptInit maxRound roundKeys state = encryptRound 1 maxRound roundKeys state'
  where state' = addRoundKey 0 roundKeys state

-- Rounds 1 to Nr-1
encryptRound :: Int -> Int -> [[Word8]] -> [[Word8]] -> [[Word8]]
encryptRound round maxRound roundKeys state
  | round == maxRound = encryptFinalize round roundKeys state
  | otherwise         = encryptRound (round+1) maxRound roundKeys state'
  where transform = mixColumns . shiftRows . subBytes
        state' = addRoundKey round roundKeys $ transform state

-- Round Nr: final transformation
encryptFinalize :: Int -> [[Word8]] -> [[Word8]] -> [[Word8]]
encryptFinalize round roundKeys state = state'
  where transform = shiftRows . subBytes
        state' = addRoundKey round roundKeys $ transform state

-- Non-linear transformation mapping state to sbox(state)
subBytes :: [[Word8]] -> [[Word8]]
subBytes = L.map subWord

-- Shifts rows according to
-- | b1  b2  b3  b4  |      | b1  b2  b3  b4  |
-- | b5  b6  b7  b8  |  ->  | b6  b7  b8  b5  |
-- | b8  b9  b10 b11 |      | b10 b11 b8  b9  |
-- | b12 b13 b14 b15 |      | b15 b12 b13 b14 |
shiftRows :: [[Word8]] -> [[Word8]]
shiftRows [] = []
shiftRows (x:xs) = x : shiftRows shifted
  where shifted = L.map rotate xs

-- Mixes columns based on below affine transformation
mixColumns :: [[Word8]] -> [[Word8]]
mixColumns state = L.transpose mixed
  where transposed = L.transpose state
        col0 = affineTransform $ head transposed
        col1 = affineTransform $ transposed !! 1
        col2 = affineTransform $ transposed !! 2
        col3 = affineTransform $ transposed !! 3
        mixed = [col0] ++ [col1] ++ [col2] ++ [col3]

--------------------------------
-- Rijndael Decrypt Functions --
--------------------------------

-- Round Nr: starts the decryption, adds the last round key
decryptInit :: Int -> [[Word8]] -> [[Word8]] -> [[Word8]]
decryptInit maxRound roundKeys state = decryptRound (maxRound-1) roundKeys state'
  where state' = addRoundKey maxRound roundKeys state

-- Rounds Nr-1 to 1
decryptRound :: Int -> [[Word8]] -> [[Word8]] -> [[Word8]]
decryptRound 0 roundKeys state = decryptFinalize roundKeys state
decryptRound round roundKeys state = decryptRound (round-1) roundKeys state'
  where transform = invSubBytes . invShiftRows
        state' = invMixColumns $ addRoundKey round roundKeys $ transform state

-- Round 0: final transformation
decryptFinalize :: [[Word8]] -> [[Word8]] -> [[Word8]]
decryptFinalize roundKeys state = state'
  where transform = invSubBytes . invShiftRows
        state' = addRoundKey 0 roundKeys $ transform state

-- Non-linear transformation mapping state to invSbox(state)
invSubBytes :: [[Word8]] -> [[Word8]]
invSubBytes = L.map invSubWord

-- Shifts rows according to
-- | b1  b2  b3  b4  |      | b1  b2  b3  b4  |
-- | b6  b7  b8  b5  |  ->  | b5  b6  b7  b8  |
-- | b10 b11 b8  b9  |      | b9  b10 b11 b12 |
-- | b15 b12 b13 b14 |      | b13 b14 b15 b16 |
invShiftRows :: [[Word8]] -> [[Word8]]
invShiftRows [] = []
invShiftRows l = undoShifts l !! 3
  where undoShifts = iterate rotate . reverse . shiftRows. reverse . rotate

-- Mixes columns based on below inverse affine transformation
invMixColumns :: [[Word8]] -> [[Word8]]
invMixColumns state = L.transpose mixed
  where transposed = L.transpose state
        col0 = invAffineTransform $ head transposed
        col1 = invAffineTransform $ transposed !! 1
        col2 = invAffineTransform $ transposed !! 2
        col3 = invAffineTransform $ transposed !! 3
        mixed = [col0] ++ [col1] ++ [col2] ++ [col3]

-------------------------------------
-- Rijndael Key Schedule Functions --
-------------------------------------

-- Expands the key where each row is a "word" (4 bytes) and the number of rows is
-- 128 --> 44
-- 192 --> 52
-- 256 --> 60
keySchedule :: [[Word8]] -> [[Word8]]
keySchedule key = keyScheduleCore i numRows key key nk
  where numBytes = length key * 4
        nk = numBytes `div` 4
        i = nk
        nr = nk + 6
        numRows = 4 * (nr + 1)

-- Performs the bulk of the key expansion.
keyScheduleCore :: Int -> Int -> [[Word8]] -> [[Word8]] -> Int -> [[Word8]]
keyScheduleCore i numRows key derived nk
  | i == numRows    = derived
  | otherwise       = keyScheduleCore (i+1) numRows key (derived ++ [final]) nk
  where temp = derived !! (i-1)
        transformed = coreTransform i nk temp
        final = Common.xorList (derived !! (i-nk)) transformed

-- Transforms the current word per Rijndael.
coreTransform :: Int -> Int -> [Word8] -> [Word8]
coreTransform i nk word
  | i `mod` nk == 0           = fullTransform
  | nk > 6 && i `mod` nk == 4 = partialTransform
  | otherwise                 = word
  where fullTransform = Common.xorByte (subWord(rotate word)) (rcon (i `div` nk))
        partialTransform = subWord word

-- Substitutes an entire vector based on the sbox
subWord :: [Word8] -> [Word8]
subWord = L.map subByte

-- Substitutes an entire vector based on the inverse sbox
invSubWord :: [Word8] -> [Word8]
invSubWord = L.map invSubByte

-- Rotates a list by 1, e.g., [1,2,3] -> [2,3,1]
rotate :: [a] -> [a]
rotate [] = []
rotate (x:xs) = xs ++ [x]

-- Returns the round constant
rcon :: (Integral a) => a -> Word8
rcon 1 = 1
rcon 2 = 2
rcon 3 = 4
rcon 4 = 8
rcon 5 = 16
rcon 6 = 32
rcon 7 = 64
rcon 8 = 128
rcon 9 = 27
rcon 10 = 54
rcon _ = 0

------------------------------
-- Other Rijndael Functions --
------------------------------

-- xors the state with the current round key
addRoundKey :: Int -> [[Word8]] -> [[Word8]] -> [[Word8]]
addRoundKey round roundKeys state = Common.xorMatrix state roundKey
  where lowIdx = 4 * round
        highIdx = 4 * round + 3
        roundKey = L.transpose $ drop lowIdx $ take (highIdx + 1) roundKeys

-- Returns a byte based on Rijndael sbox.
subByte :: Word8 -> Word8
subByte = subByteHelper sbox

-- Returns a byte based on Rijndael inverse sbox.
invSubByte :: Word8 -> Word8
invSubByte = subByteHelper invSbox

subByteHelper :: [[Word8]] -> Word8 -> Word8
subByteHelper matrix a = (matrix !! row) !! col
  where row = fromIntegral $ B.shiftR a 4 ::Int -- left most half byte
        col = fromIntegral a B..&. 15 ::Int -- right most half byte

sbox :: [[Word8]]
sbox = [row0,row1,row2,row3,row4,row5,row6,row7,row8,row9,row10,row11,row12,row13,row14,row15]
  where row0 = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118]
        row1 = [202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192]
        row2 = [183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21]
        row3 = [4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117]
        row4 = [9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132]
        row5 = [83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207]
        row6 = [208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 002, 127, 80, 60, 159, 168]
        row7 = [81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210]
        row8 = [205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115]
        row9 = [96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219]
        row10 = [224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121]
        row11 = [231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8]
        row12 = [186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138]
        row13 = [112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158]
        row14 = [225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223]
        row15 = [140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]

invSbox :: [[Word8]]
invSbox = [row0,row1,row2,row3,row4,row5,row6,row7,row8,row9,row10,row11,row12,row13,row14,row15]
  where row0 = [82, 009, 106, 213, 048, 054, 165, 056, 191, 064, 163, 158, 129, 243, 215, 251]
        row1 = [124, 227, 057, 130, 155, 047, 255, 135, 52, 142, 067, 68, 196, 222, 233, 203]
        row2 = [84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 011, 66, 250, 195, 78]
        row3 = [8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37]
        row4 = [114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146]
        row5 = [108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132]
        row6 = [144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6]
        row7 = [208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107]
        row8 = [58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115]
        row9 = [150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110]
        row10 = [71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 027]
        row11 = [252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244]
        row12 = [31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 095]
        row13 = [96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239]
        row14 = [160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97]
        row15 = [23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125]

----------------------
-- Helper Functions --
----------------------

-- We only need to implement multiplication by 2 and 3 in GF(2^8) for encryption,
-- 9, 11, 13, and 14 for decryption.
-- Multiplication by 2 is equivalent to bit shifting by one and adding (xor)
-- 0x1b (27) if the high bit was set.
-- 3 x b = (2 xor 1) b = (2 x b) xor b
fieldMult :: Word8 -> Word8 -> Word8
fieldMult 2 b
  | highBitSet = shifted `B.xor` 27 -- 27 = x^4 + x^3 + x + 1 
  | otherwise  = shifted
  where shifted = b `B.shiftL` 1
        highBitSet = b B..&. 128 == 128
fieldMult 3 b = B.xor b (fieldMult 2 b) -- 3 x b = (2 x b) xor b
fieldMult 9 b =  B.xor b (fieldMult 2 (fieldMult 2 (fieldMult 2 b)))
fieldMult 11 b = B.xor b (fieldMult 2 (B.xor b (fieldMult 2 (fieldMult 2 b))))
fieldMult 13 b = B.xor b (fieldMult 2 (fieldMult 2 (B.xor b (fieldMult 2 b))))
fieldMult 14 b = fieldMult 2 (B.xor b (fieldMult 2 (B.xor b (fieldMult 2 b))))
fieldMult _ _ = 0

-- Performs an affine transformation on the param vector based on the matrix
-- | 2 3 1 1 |
-- | 1 2 3 1 |
-- | 1 1 2 3 |
-- | 3 1 1 2 |
-- Addition is xor and multiplication is in GF(2^8).
affineTransform :: [Word8] -> [Word8]
affineTransform vector = [bOne] ++ [bTwo] ++ [bThree] ++ [bFour]
  where bOne =   fieldMult 2 (head vector) `B.xor`
                 fieldMult 3 (vector !! 1) `B.xor`
                 vector !! 2 `B.xor`
                 vector !! 3
        bTwo =   head vector `B.xor`
                 fieldMult 2 (vector !! 1) `B.xor`
                 fieldMult 3 (vector !! 2) `B.xor`
                 vector !! 3
        bThree = head vector `B.xor`
                 vector !! 1 `B.xor`
                 fieldMult 2 (vector !! 2) `B.xor`
                 fieldMult 3 (vector !! 3)
        bFour =  fieldMult 3 (head vector) `B.xor`
                 vector !! 1 `B.xor`
                 vector !! 2 `B.xor`
                 fieldMult 2 (vector !! 3)

-- Performs an affine transformation on the param vector based on the matrix
-- | 14 11 13  9 |
-- | 9  14 11 |3 |
-- | 13 9  14 11 |
-- | 11 13 9  14 |
-- Addition is xor and multiplication is in GF(2^8).
invAffineTransform :: [Word8] -> [Word8]
invAffineTransform vector = [bOne] ++ [bTwo] ++ [bThree] ++ [bFour]
  where bOne =   fieldMult 14 (head vector) `B.xor`
                 fieldMult 11 (vector !! 1) `B.xor`
                 fieldMult 13 (vector !! 2) `B.xor`
                 fieldMult 9  (vector !! 3)
        bTwo =   fieldMult 9  (head vector) `B.xor`
                 fieldMult 14 (vector !! 1) `B.xor`
                 fieldMult 11 (vector !! 2) `B.xor`
                 fieldMult 13 (vector !! 3)
        bThree = fieldMult 13 (head vector) `B.xor`
                 fieldMult 9  (vector !! 1) `B.xor`
                 fieldMult 14 (vector !! 2) `B.xor`
                 fieldMult 11 (vector !! 3)
        bFour =  fieldMult 11 (head vector) `B.xor`
                 fieldMult 13 (vector !! 1) `B.xor`
                 fieldMult 9  (vector !! 2) `B.xor`
                 fieldMult 14 (vector !! 3)

-- Returns a bytestring based on the state matrix.
stateToByteStr :: [[Word8]] -> ByteString
stateToByteStr matrix = byteStr
  where flatList = L.concat $ L.transpose matrix
        byteStr = BS.pack flatList