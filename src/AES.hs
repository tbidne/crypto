module AES
( keygen
)
where

import qualified System.Random as R
import qualified Data.ByteString.Lazy as BS
import qualified Data.Bits as B
import qualified Data.List as L
import qualified Data.Word as W

-- generates number in [2^(n-1)], 2^n - 1]
-- todo: turn into byte string
keygen :: (R.RandomGen a) => a -> Integer -> Maybe Integer
keygen g size = case size of
  s 
    | s `elem` [128, 196, 256] -> Just key
    | otherwise -> Nothing
    where key = fst $ R.randomR(2^(size-1), 2^size - 1) g

-- encryptIO :: String -> String -> IO()
-- encryptIO keyfile file do
  -- key <- initKey $ BS.readFile keyfile

-- Turns ByteString representing key into matrix e.g. 128 bit keys have form
-- | b1  b2  b3  b4  |
-- | b5  b6  b7  b8  |
-- | b8  b9  b10 b11 |
-- | b12 b13 b14 b15 |
-- 192 bit keys have rows of length 6, 256 is 8
initKey :: BS.ByteString -> [[W.Word8]]
initKey bytes = key
  where flatKey = BS.unpack bytes
        rowLen = length flatKey `div` 4
        key = flatListToMatrix rowLen flatKey []

-- Turns ByteString representing 128 bit block into matrix e.g.
-- | b1 b5 b9  b13 |
-- | b2 b6 b10 b14 |
-- | b3 b7 b11 b15 |
-- | b4 b8 b12 b16 |
-- Notice this matrix is the _transpose_ of what you'd normally expect
initState :: BS.ByteString -> [[W.Word8]]
initState byteStr = state
  where byteList = BS.unpack byteStr
        matrix = flatListToMatrix 4 byteList []
        state = L.transpose matrix

-- todo: figure out pattern matching failure
encrypt :: Int -> [[W.Word8]] -> [[W.Word8]] -> BS.ByteString
encrypt 0 _ = stateToByteStr
enrcrypt rounds key state =
  let modify = mixColumns . shiftRows . subBytes
  in enrcrypt (rounds-1) key $ addRoundKey key $ modify state

subBytes :: [[W.Word8]] -> [[W.Word8]]
subBytes state = state

shiftRows :: [[W.Word8]] -> [[W.Word8]]
shiftRows state = state

mixColumns :: [[W.Word8]] -> [[W.Word8]]
mixColumns state = state

addRoundKey :: [[W.Word8]] -> [[W.Word8]] -> [[W.Word8]]
addRoundKey key state = state

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