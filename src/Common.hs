module Common
( padToN
, intToWord8List
, word8ListToInt
, xorByte
, xorList
, xorMatrix
, flatListToMatrix
)
where

import Data.Bits (Bits)
import qualified Data.Bits as B (shiftL, shiftR, xor)
import Data.List
import Data.Word (Word8)

import Data.ByteString.Lazy (ByteString)

padToN :: Int -> [Word8] -> (Word8, [Word8])
padToN n bytes
  | length bytes `mod` n == 0 = (0, bytes)
  | otherwise = (fromIntegral numPadding, bytes ++ padded)
  where numPadding = n - length bytes `mod` n
        padded = replicate numPadding 0

-- Returns a Word8 list where each element in the list represents
-- a byte, e.g. 42310 -> [165, 70], or 0xA546.
intToWord8List :: Integer -> [Word8] -> [Word8]
intToWord8List 0 acc = acc
intToWord8List i acc = intToWord8List i' (byte:acc)
  where i' = B.shiftR i 8
        byte = fromIntegral i

word8ListToInt :: [Word8] -> Integer
word8ListToInt xs = foldl' (\x y -> (y + B.shiftL x 8)) 0 ys
  where ys = map fromIntegral xs

-- Xors every element in list with the param.
xorByte :: Bits a => [a] -> a -> [a]
xorByte xs e = map (`B.xor` e) xs

-- Xors every element in list X with corresponding element in list Y.
xorList :: Bits a => [a] -> [a] -> [a]
xorList = zipWith B.xor

-- Xors every element in matrix X with corresponding element in matrix Y.
xorMatrix :: Bits a => [[a]] -> [[a]] -> [[a]]
xorMatrix = zipWith xorList

-- Returns a list in matrix form based on rowLen.
flatListToMatrix :: Int -> [a] -> [[a]] -> [[a]]
flatListToMatrix _ [] matrix = matrix
flatListToMatrix rowLen l matrix = flatListToMatrix rowLen l' matrix'
  where row = take rowLen l
        l' = drop rowLen l
        matrix' = matrix ++ [row]