{-|
Module      : Common
Description : Exports utility functions.
License     : MIT
Maintainer  : tbidne@gmail.com

Exports utility functions.
-}
module Common
( padToN
, intToWord8List
, word8ListToInt
, xorByte
, xorList
, xorMatrix
, flatListToMatrix
, byteStringToInt
, intToByteString
)
where

import           Data.Bits (Bits, shiftL, shiftR, xor)
import           Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (pack, unpack)
import           Data.List
import           Data.Word (Word8)

-- | Takes an 'Int' @n@ and a 'Word8' list @w@ and returns a tuple @(a, [b])@
--   where @[b]@ is @w@ padded with zeroes to the nearest /greater/ multiple of @n@ and
--   @a@ is the amount of padding needed.
--
--   Example:
--
-- @
--   padToN 3 [23,12,64,32] -> (2,[23,12,64,32,0,0])
--   padToN 3 [23,12,64,32,6,42] -> (0,[23,12,64,32,6,42])
-- @
padToN :: Int -> [Word8] -> (Word8, [Word8])
padToN 0 bytes = (0, bytes)
padToN n bytes
  | length bytes `mod` n == 0 = (0, bytes)
  | otherwise                 = (fromIntegral numPadding, bytes ++ padded)
  where numPadding = n - length bytes `mod` n
        padded = replicate numPadding 0

-- | Converts an 'Integer' into a 'Word8' list where each element in the list represents
--   a byte. The inverse of 'word8ListToInt'.
--
-- Example:
--
-- @
--   intToWord8List 42310 -> [165, 70], or 0xA546.
--   intToWord8List 52582001236900766738172 -> [11,34,121,219,13,148,44,170,230,252], or 0xB2279DB0D942CAAE6FC.
-- @
intToWord8List :: Integer -> [Word8] -> [Word8]
intToWord8List 0 acc = acc
intToWord8List i acc = intToWord8List i' (byte:acc)
  where i' = shiftR i 8
        byte = fromIntegral i

-- | Converts a 'Word8' list of bytes into an 'Integer'. The inverse of 'intToWord8List'.
--
-- Example:
--
-- @
-- word8ListToInt [165,70] -> 42310
-- word8ListToInt [11,34,121,219,13,148,44,170,230,252] -> 52582001236900766738172
-- @
word8ListToInt :: [Word8] -> Integer
word8ListToInt xs = foldl' (\x y -> (y + shiftL x 8)) 0 ys
  where ys = map fromIntegral xs

-- | Xors every element in a 'Bit' list with the parameter 'Bit'.
--
-- Example:
--
-- @
-- xorByte [b1, b2 ... bn] b -> [b1 &#8853; b, b2 &#8853; b ... bn &#8853; b]
-- @
xorByte :: Bits a => [a] -> a -> [a]
xorByte xs e = map (`xor` e) xs

-- | For two 'Bit' lists, returns a new list with each corresponding `Bit` xor'd.
--
-- Example:
--
-- @
-- xorList [b1, b2 ... bn] [c1, c2 ... cn] -> [b1 &#8853; c1, b2 &#8853; c2 ... bn &#8853; cn]
-- @
xorList :: Bits a => [a] -> [a] -> [a]
xorList = zipWith xor

-- | For two 'Bit' matrices, returns a new matrix with each corresponding `Bit` xor'd.
--
-- Example:
--
-- @
-- xorMatrix [[b11, b12] [b12, b22]] [[c11, c12] [c12, c22]] -> [[b11 &#8853; c11, b12 &#8853; c12] [b12 &#8853; c12, b22 &#8853; c22]]
-- @
xorMatrix :: Bits a => [[a]] -> [[a]] -> [[a]]
xorMatrix = zipWith xorList

-- | For 'Integer' @n@, list @xs@, and starting matrix @m@, transforms @m@
-- into an @n x n@ matrix representation for @xs@.
--
-- Example:
--
-- @
-- flatListToMatrix 4 [b1 ... b16] -> [[b1 ... b4], [b5 ... b8], [b9 ... b12], [b13 ... n16]]
-- @
flatListToMatrix :: Int -> [a] -> [[a]] -> [[a]]
flatListToMatrix _ [] matrix = matrix
flatListToMatrix rowLen l matrix = flatListToMatrix rowLen l' matrix'
  where row = take rowLen l
        l' = drop rowLen l
        matrix' = matrix ++ [row]

-- | For a 'ByteString' @lb@, where @l@ is the two-byte representation of the integer /length/
-- of the next integer in @b@, returns @(i, rem)@ where @i@ is integer representation
-- of the next @l@ bytes in @b@, and @rem@ is the remaining bytes, if any.
--
-- Example:
--
-- @
-- byteStringToInt (pack [0,4,234,66,25,181,43,23]) -> (3930200501, pack [43,23]) (l = 04, b = [234,66,25,181] or 0xEA4219B5)
-- @
byteStringToInt :: ByteString -> (Integer, ByteString)
byteStringToInt bytes = (i, remaining)
  where byteList = BS.unpack bytes
        len = fromIntegral $ word8ListToInt $ take 2 byteList
        i = word8ListToInt $ take len (drop 2 byteList)
        remaining = BS.pack $ drop (len+2) byteList

-- | Turns an 'Integer' into 'ByteString' @lb@ where @b@ is @n@'s 'ByteString' representation
-- and @l@ is its two-byte length.
--
-- Example:
--
-- @
-- intToByteString 3930200501 -> pack [0,4,234,66,25,181]
-- @
intToByteString :: Integer -> ByteString
intToByteString i
  | numPadding == 0 = BS.pack $ bytesLen ++ byteList
  | otherwise = BS.pack $ reverse bytesLen ++ byteList
  where byteList = intToWord8List i []
        len = fromIntegral $ length byteList
        (numPadding, bytesLen) = padToN 2 $ intToWord8List len []