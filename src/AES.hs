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

--------------------
-- Init Functions --
--------------------

-- Turns ByteString representing key into matrix e.g. 128 bit keys have form
-- | b1  b2  b3  b4  |
-- | b5  b6  b7  b8  |
-- | b8  b9  b10 b11 |
-- | b12 b13 b14 b15 |
-- 192 bit keys have rows of length 6, 256 is 8
keyInit :: BS.ByteString -> [[W.Word8]]
keyInit bytes = key
  where flatKey = BS.unpack bytes
        rowLen = length flatKey `div` 4
        key = flatListToMatrix rowLen flatKey []

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

-- todo: figure out pattern matching failure
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

----------------------
-- Helper Functions --
----------------------

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