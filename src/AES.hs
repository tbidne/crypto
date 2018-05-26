module AES
( keygenIO
, encryptIO
, keygen
, encrypt
)
where

import qualified System.Random as R
import qualified Data.ByteString.Lazy as BS
import qualified Data.Bits as B
import qualified Data.List as L
import qualified Data.Word as W

-- TODO
-- encrypt

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

-- generates number in [2^(n-1)], 2^n - 1], turns into ByteString
keygen :: (R.RandomGen a) => a -> Int -> Maybe BS.ByteString
keygen g size = case size of
  s 
    | s `elem` [128, 192, 256] -> Just key
    | otherwise -> Nothing
    where num = fst $ R.randomR(2^(size-1), 2^size - 1) g :: Integer
          bytes = intToWord8List num []
          key = BS.pack bytes

encrypt :: BS.ByteString -> BS.ByteString -> BS.ByteString
encrypt k m = stateToByteStr encrypted
  where key = keyInit k
        state = stateInit m
        rounds = 0
        encrypted = encryptInit rounds key state

decrypt :: BS.ByteString -> BS.ByteString -> BS.ByteString
decrypt k m = stateToByteStr decrypted
  where key = keyInit k
        state = stateInit m
        rounds = 1
        decrypted = decryptInit rounds key state

--------------------
-- Init Functions --
--------------------

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
-- Notice this matrix is the _transpose_ of what you'd normally expect
stateInit :: BS.ByteString -> [[W.Word8]]
stateInit byteStr = state
  where byteList = BS.unpack byteStr
        matrix = flatListToMatrix 4 byteList []
        state = L.transpose matrix

--------------------------------
-- Rijndael Encrypt Functions --
--------------------------------

encryptInit :: Int -> [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
encryptInit rounds key state = encryptRound rounds key state

encryptRound :: Int -> [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
encryptRound 0 key state = encryptFinalize key state
encryptRound rounds key state =
  let modify = mixColumns . shiftRows . subBytes
  in encryptRound (rounds-1) key $ addRoundKey key $ modify state

encryptFinalize :: [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
encryptFinalize key state = state

subBytes :: [[W.Word8]] -> [[W.Word8]]
subBytes state = state

shiftRows :: [[W.Word8]] -> [[W.Word8]]
shiftRows state = state

mixColumns :: [[W.Word8]] -> [[W.Word8]]
mixColumns state = state

addRoundKey :: [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
addRoundKey key state = state

--------------------------------
-- Rijndael Decrypt Functions --
--------------------------------

decryptInit :: Int -> [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
decryptInit rounds key state = decryptRound rounds key state

decryptRound :: Int -> [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
decryptRound 0 key state = decryptFinalize key state
decryptRound rounds key state =
  let modify = invMixColumns . invShiftRows . invSubBytes
  in decryptRound (rounds-1) key $ invAddRoundKey key $ modify state

decryptFinalize :: [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
decryptFinalize key state = state

invSubBytes :: [[W.Word8]] -> [[W.Word8]]
invSubBytes state = state

invShiftRows :: [[W.Word8]] -> [[W.Word8]]
invShiftRows state = state

invMixColumns :: [[W.Word8]] -> [[W.Word8]]
invMixColumns state = state

invAddRoundKey :: [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
invAddRoundKey key state = state

-------------------------------------
-- Rijndael Key Schedule Functions --
-------------------------------------

-- returns a matrix where each row is a "word" (4 bytes) and the number of rows is
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

keyScheduleCore :: Int -> Int -> [[W.Word8]] -> [[W.Word8]] -> Int -> [[W.Word8]]
keyScheduleCore i numRows key derived nk
  | i == numRows    = derived
  | otherwise       = keyScheduleCore (i+1) numRows key (derived ++ [final]) nk
  where temp = derived !! (i-1)
        transformed = coreTransform i nk temp
        final = xorWord (derived !! (i-nk)) transformed []

coreTransform :: Int -> Int -> [W.Word8] -> [W.Word8]
coreTransform i nk word
  | i `mod` nk == 0           = fullTransform
  | nk > 6 && i `mod` nk == 4 = partialTransform
  | otherwise                 = word
  where fullTransform = xorRcon (subWord(rotate word)) (rcon (i `div` nk))
        partialTransform = subWord word

subWord :: [W.Word8] -> [W.Word8]
subWord = L.map subByte

rotate :: [a] -> [a]
rotate (x:xs) = xs ++ [x]

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

subByte :: W.Word8 -> W.Word8
subByte a = (sbox !! row) !! col
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
invSbox = L.transpose sbox

----------------------
-- Helper Functions --
----------------------

xorRcon :: [W.Word8] -> W.Word8 -> [W.Word8]
xorRcon (x:xs) rc = z:xs
  where z = x `B.xor` rc

xorWord :: [W.Word8] -> [W.Word8] -> [W.Word8] -> [W.Word8]
xorWord [] _ acc = acc
xorWord _ [] acc = acc
xorWord (x:xs) (y:ys) acc =
  let z = x `B.xor` y
  in xorWord xs ys (acc ++ [z])

applyFunToNthRowMatrix :: Int -> ([W.Word8] -> [W.Word8]) -> [[W.Word8]] -> [[W.Word8]]
applyFunToNthRowMatrix n f state = pre ++ [modified] ++ post
  where row = state !! n
        pre = take n state
        modified = f row
        post = drop (n+1) state

applyFunToNthColMatrix :: Int -> ([W.Word8] -> [W.Word8]) -> [[W.Word8]] -> [[W.Word8]]
applyFunToNthColMatrix n f state = L.transpose applied
  where transposed = L.transpose state
        applied = applyFunToNthRowMatrix n f transposed

applyFunToElemMatrix :: Int -> Int -> (W.Word8 -> W.Word8) -> [[W.Word8]] -> [[W.Word8]]
applyFunToElemMatrix i j f state = pre ++ [row'] ++ post
  where row = state !! i
        pre = take i state
        element = row !! j
        element' = f element
        row' = take j row ++ [element'] ++ drop (j+1) row
        post = drop (i+1) state

stateToByteStr :: [[W.Word8]] -> BS.ByteString
stateToByteStr matrix = byteStr
  where flatList = L.concat $ L.transpose matrix
        byteStr = BS.pack flatList

flatListToMatrix :: Int -> [W.Word8] -> [[W.Word8]] -> [[W.Word8]]
flatListToMatrix _ [] matrix = matrix
flatListToMatrix rowLen l matrix = flatListToMatrix rowLen l' matrix'
  where row = take rowLen l
        l' = drop rowLen l
        matrix' = matrix ++ [row]

intToWord8List :: Integer -> [W.Word8] -> [W.Word8]
intToWord8List 0 acc = acc
intToWord8List i acc = intToWord8List i' (byte:acc)
  where i' = B.shiftR i 8
        byte = fromIntegral i :: W.Word8