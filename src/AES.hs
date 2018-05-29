module AES
( keygenIO
, encryptIO
, decryptIO
, keygen
, encrypt
, decrypt
)
where

import qualified System.Random as R (newStdGen, RandomGen, randomR)
import qualified Data.ByteString.Lazy as BS (ByteString, pack, readFile, unpack, writeFile)
import qualified Data.Bits as B (Bits, shiftL, shiftR, xor, (.&.))
import qualified Data.List as L (concat, map, transpose)
import qualified Data.Word as W (Word8)

-- Based on FIPS 197: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
-- TODO:
-- modes (ECB, CBC)

------------------
-- IO Functions --
------------------

keygenIO :: Int -> String -> IO ()
keygenIO size filename = do
  g <- R.newStdGen
  let key = keygen g size
  case key of
    Nothing -> putStrLn "wrong file size"
    Just k -> BS.writeFile filename k

encryptIO :: String -> String -> String -> IO ()
encryptIO keyFile fileIn fileOut = do
  k <- BS.readFile keyFile
  m <- BS.readFile fileIn
  let encrypted = encrypt k m
  BS.writeFile fileOut encrypted

decryptIO :: String -> String -> String -> IO ()
decryptIO keyFile fileIn fileOut = do
  k <- BS.readFile keyFile
  c <- BS.readFile fileIn
  let decrypted = decrypt k c
  BS.writeFile fileOut decrypted

-------------------
-- API Functions --
-------------------

-- Generates number in [2^(n-1)], 2^n - 1], turns into ByteString
keygen :: (R.RandomGen a) => a -> Int -> Maybe BS.ByteString
keygen g size = case size of
  s 
    | s `elem` [128, 192, 256] -> Just key
    | otherwise -> Nothing
    where num = fst $ R.randomR(2^(size-1), 2^size - 1) g :: Integer
          bytes = intToWord8List num []
          key = BS.pack bytes

-- Encrypts message m with key k
encrypt :: BS.ByteString -> BS.ByteString -> BS.ByteString
encrypt k m = stateToByteStr encrypted
  where (maxRound, roundKeys, state) = setupForTransform k m
        encrypted = encryptInit maxRound roundKeys state

-- Decrypts message m with key k
decrypt :: BS.ByteString -> BS.ByteString -> BS.ByteString
decrypt k m = stateToByteStr decrypted
  where (maxRound, roundKeys, state) = setupForTransform k m
        decrypted = decryptInit maxRound roundKeys state

--------------------
-- Init Functions --
--------------------

setupForTransform :: BS.ByteString -> BS.ByteString -> (Int, [[W.Word8]], [[W.Word8]])
setupForTransform k m = (maxRound, roundKeys, state)
  where key = keyInit k
        roundKeys = keySchedule key
        maxRound = length key + 6
        state = stateInit m

-- Turns ByteString representing key into matrix e.g. 128 bit keys have form
-- | b1  b2  b3  b4  |
-- | b5  b6  b7  b8  |
-- | b8  b9  b10 b11 |
-- | b12 b13 b14 b15 |
-- 192 bit keys have 6 rows, 256 have 8 rows
keyInit :: BS.ByteString -> [[W.Word8]]
keyInit bytes = key
  where flatKey = BS.unpack bytes
        key = flatListToMatrix 4 flatKey []

-- Turns ByteString representing 128 bit block into matrix e.g.
-- | b1 b5 b9  b13 |
-- | b2 b6 b10 b14 |
-- | b3 b7 b11 b15 |
-- | b4 b8 b12 b16 |
-- Notice this matrix is the _transpose_ of how the key was interpreted
stateInit :: BS.ByteString -> [[W.Word8]]
stateInit byteStr = state
  where byteList = BS.unpack byteStr
        matrix = flatListToMatrix 4 byteList []
        state = L.transpose matrix

--------------------------------
-- Rijndael Encrypt Functions --
--------------------------------

-- Round 0: starts the encryption, adds the first round key
encryptInit :: Int -> [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
encryptInit maxRound roundKeys state = encryptRound 1 maxRound roundKeys state'
  where state' = addRoundKey 0 roundKeys state

-- Rounds 1 to Nr-1
encryptRound :: Int -> Int -> [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
encryptRound round maxRound roundKeys state
  | round == maxRound = encryptFinalize round roundKeys state
  | otherwise         = encryptRound (round+1) maxRound roundKeys state'
  where transform = mixColumns . shiftRows . subBytes
        state' = addRoundKey round roundKeys $ transform state

-- Round Nr: final transformation
encryptFinalize :: Int -> [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
encryptFinalize round roundKeys state = state'
  where transform = shiftRows . subBytes
        state' = addRoundKey round roundKeys $ transform state

-- Non-linear transformation mapping state to sbox(state)
subBytes :: [[W.Word8]] -> [[W.Word8]]
subBytes = L.map subWord

-- Shifts rows according to
-- | b1  b2  b3  b4  |      | b1  b2  b3  b4  |
-- | b5  b6  b7  b8  |  ->  | b6  b7  b8  b5  |
-- | b8  b9  b10 b11 |      | b10 b11 b8  b9  |
-- | b12 b13 b14 b15 |      | b15 b12 b13 b14 |
shiftRows :: [[W.Word8]] -> [[W.Word8]]
shiftRows [] = []
shiftRows (x:xs) = x : shiftRows shifted
  where shifted = L.map rotate xs

-- Mixes columns based on below affine transformation
mixColumns :: [[W.Word8]] -> [[W.Word8]]
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
decryptInit :: Int -> [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
decryptInit maxRound roundKeys state = decryptRound (maxRound-1) roundKeys state'
  where state' = addRoundKey maxRound roundKeys state

-- Rounds Nr-1 to 1
decryptRound :: Int -> [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
decryptRound 0 roundKeys state = decryptFinalize roundKeys state
decryptRound round roundKeys state = decryptRound (round-1) roundKeys state'
  where transform = invSubBytes . invShiftRows
        state' = invMixColumns $ addRoundKey round roundKeys $ transform state

-- Round 0: final transformation
decryptFinalize :: [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
decryptFinalize roundKeys state = state'
  where transform = invSubBytes . invShiftRows
        state' = addRoundKey 0 roundKeys $ transform state

-- Non-linear transformation mapping state to invSbox(state)
invSubBytes :: [[W.Word8]] -> [[W.Word8]]
invSubBytes = L.map invSubWord

-- Shifts rows according to
-- | b1  b2  b3  b4  |      | b1  b2  b3  b4  |
-- | b6  b7  b8  b5  |  ->  | b5  b6  b7  b8  |
-- | b10 b11 b8  b9  |      | b9  b10 b11 b12 |
-- | b15 b12 b13 b14 |      | b13 b14 b15 b16 |
invShiftRows :: [[W.Word8]] -> [[W.Word8]]
invShiftRows [] = []
invShiftRows l = undoShifts l !! 3
  where undoShifts = iterate rotate . reverse . shiftRows. reverse . rotate

-- Mixes columns based on below inverse affine transformation
invMixColumns :: [[W.Word8]] -> [[W.Word8]]
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
keySchedule :: [[W.Word8]] -> [[W.Word8]]
keySchedule key = keyScheduleCore i numRows key key nk
  where numBytes = length key * 4
        nk = numBytes `div` 4
        i = nk
        nr = nk + 6
        numRows = 4 * (nr + 1)

-- Performs the bulk of the key expansion.
keyScheduleCore :: Int -> Int -> [[W.Word8]] -> [[W.Word8]] -> Int -> [[W.Word8]]
keyScheduleCore i numRows key derived nk
  | i == numRows    = derived
  | otherwise       = keyScheduleCore (i+1) numRows key (derived ++ [final]) nk
  where temp = derived !! (i-1)
        transformed = coreTransform i nk temp
        final = xorList (derived !! (i-nk)) transformed []

-- Transforms the current word per Rijndael.
coreTransform :: Int -> Int -> [W.Word8] -> [W.Word8]
coreTransform i nk word
  | i `mod` nk == 0           = fullTransform
  | nk > 6 && i `mod` nk == 4 = partialTransform
  | otherwise                 = word
  where fullTransform = xorByte (subWord(rotate word)) (rcon (i `div` nk))
        partialTransform = subWord word

-- Substitutes an entire vector based on the sbox
subWord :: [W.Word8] -> [W.Word8]
subWord = L.map subByte

-- Substitutes an entire vector based on the inverse sbox
invSubWord :: [W.Word8] -> [W.Word8]
invSubWord = L.map invSubByte

-- Rotates a list by 1, e.g., [1,2,3] -> [2,3,1]
rotate :: [a] -> [a]
rotate (x:xs) = xs ++ [x]

-- Returns the round constant
rcon :: (Integral a) => a -> W.Word8
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

------------------------------
-- Other Rijndael Functions --
------------------------------

-- xors the state with the current round key
addRoundKey :: Int -> [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
addRoundKey round roundKeys state = xorMatrix state roundKey []
  where lowIdx = 4 * round
        highIdx = 4 * round + 3
        roundKey = L.transpose $ drop lowIdx $ take (highIdx + 1) roundKeys

-- Returns a byte based on Rijndael sbox.
subByte :: W.Word8 -> W.Word8
subByte = subByteHelper sbox

-- Returns a byte based on Rijndael inverse sbox.
invSubByte :: W.Word8 -> W.Word8
invSubByte = subByteHelper invSbox

subByteHelper :: [[W.Word8]] -> W.Word8 -> W.Word8
subByteHelper matrix a = (matrix !! row) !! col
  where row = fromIntegral $ B.shiftR a 4 ::Int -- left most half byte
        col = fromIntegral a B..&. 15 ::Int -- right most half byte

sbox :: [[W.Word8]]
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

invSbox :: [[W.Word8]]
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
fieldMult :: W.Word8 -> W.Word8 -> W.Word8
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

-- Performs an affine transformation on the param vector based on the matrix
-- | 2 3 1 1 |
-- | 1 2 3 1 |
-- | 1 1 2 3 |
-- | 3 1 1 2 |
-- Addition is xor and multiplication is in GF(2^8).
affineTransform :: [W.Word8] -> [W.Word8]
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
invAffineTransform :: [W.Word8] -> [W.Word8]
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

-- Xors every elemnt in list with param.
xorByte :: B.Bits a => [a] -> a -> [a]
xorByte (x:xs) e = z:xs
  where z = x `B.xor` e

-- Xors every element in list X with corresponding element in list Y.
xorList :: B.Bits a => [a] -> [a] -> [a] -> [a]
xorList [] _ acc = acc
xorList _ [] acc = acc
xorList (x:xs) (y:ys) acc =
  let z = x `B.xor` y
  in xorList xs ys (acc ++ [z])

-- Xors every element in matrix X with corresponding element in matrix Y.
xorMatrix :: B.Bits a => [[a]] -> [[a]] -> [[a]] -> [[a]]
xorMatrix [] _ acc = acc
xorMatrix _ [] acc = acc
xorMatrix (x:xs) (y:ys) acc =
  let r' = xorList x y []
  in xorMatrix xs ys (acc ++ [r'])

-- Applies function f to the nth row in the state matrix.
applyFunToNthRowMatrix :: Int -> ([a] -> [a]) -> [[a]] -> [[a]]
applyFunToNthRowMatrix n f state = pre ++ [modified] ++ post
  where row = state !! n
        pre = take n state
        modified = f row
        post = drop (n+1) state

-- Applies function f to the nth column in the state matrix.
applyFunToNthColMatrix :: Int -> ([a] -> [a]) -> [[a]] -> [[a]]
applyFunToNthColMatrix n f state = L.transpose applied
  where transposed = L.transpose state
        applied = applyFunToNthRowMatrix n f transposed

-- Applies function f to the a_ij th element in the state matrix.
applyFunToElemMatrix :: Int -> Int -> (a -> a) -> [[a]] -> [[a]]
applyFunToElemMatrix i j f state = pre ++ [row'] ++ post
  where row = state !! i
        pre = take i state
        element = row !! j
        element' = f element
        row' = take j row ++ [element'] ++ drop (j+1) row
        post = drop (i+1) state

-- Returns a bytestring based on the state matrix.
stateToByteStr :: [[W.Word8]] -> BS.ByteString
stateToByteStr matrix = byteStr
  where flatList = L.concat $ L.transpose matrix
        byteStr = BS.pack flatList

-- Returns a list in matrix form based on rowLen.
flatListToMatrix :: Int -> [a] -> [[a]] -> [[a]]
flatListToMatrix _ [] matrix = matrix
flatListToMatrix rowLen l matrix = flatListToMatrix rowLen l' matrix'
  where row = take rowLen l
        l' = drop rowLen l
        matrix' = matrix ++ [row]

-- Returns a Word8 list where each element in the list represents
-- a byte, e.g. 42310 -> [165, 70], or 0xA546.
intToWord8List :: Integer -> [W.Word8] -> [W.Word8]
intToWord8List 0 acc = acc
intToWord8List i acc = intToWord8List i' (byte:acc)
  where i' = B.shiftR i 8
        byte = fromIntegral i