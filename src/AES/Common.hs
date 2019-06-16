{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module AES.Common
( subByte
, invSubByte
, sbox
, invSbox
, rotate
, rotateN
, invRotate
, invRotateN
, subWord
, subWords
, invSubWord
, invSubWords
, xorByte
, xorVector
, xorVMatrix
, toV4
, xorV4
, V4(..)
, vTranspose
, Listable(..)
)
where

import Prelude hiding (head, tail, zipWith, take, last)
import Data.Bits (shiftR, (.&.), xor)
import Data.Vector (Vector, cons, (!), fromList, zipWith, empty)
import Data.Word (Word8)

class Listable f a where
  toList :: f a -> [a]

data V4 a = V4 a a a a

instance Functor V4 where
  fmap f (V4 x1 x2 x3 x4) = V4 (f x1) (f x2) (f x3) (f x4)

instance Listable V4 a where
  toList (V4 x1 x2 x3 x4) = [x1, x2, x3, x4]

toV4 :: [a] -> V4 a
toV4 [x1, x2, x3, x4] = V4 x1 x2 x3 x4
toV4 _ = undefined

-- Returns a byte based on Rijndael sbox.
subByte :: Word8 -> Word8
subByte = subByteHelper sbox

-- Returns a byte based on Rijndael inverse sbox.
invSubByte :: Word8 -> Word8
invSubByte = subByteHelper invSbox

subByteHelper :: Vector (Vector Word8) -> Word8 -> Word8
subByteHelper matrix a = (matrix ! row) ! col
  where row = fromIntegral $ shiftR a 4 ::Int -- left most half byte
        col = fromIntegral a .&. 15 ::Int -- right most half byte

sbox :: Vector (Vector Word8)
sbox = (fromList . fmap fromList) [row0,row1,row2,row3,row4,row5,row6,row7,row8,row9,row10,row11,row12,row13,row14,row15]
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

invSbox :: Vector (Vector Word8)
invSbox = (fromList . fmap fromList) [row0,row1,row2,row3,row4,row5,row6,row7,row8,row9,row10,row11,row12,row13,row14,row15]
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

-- | Rotates a list by 1.
--
-- @
-- rotate [1,2,3] -> [2,3,1]
-- @
rotate :: V4 a -> V4 a
rotate (V4 x1 x2 x3 x4) = V4 x2 x3 x4 x1

rotateN :: Int -> V4 a -> V4 a
rotateN n vs = iterate rotate vs !! n

invRotateN :: Int -> V4 a -> V4 a
invRotateN n vs = iterate invRotate vs !! n

invRotate :: V4 a -> V4 a
invRotate (V4 x1 x2 x3 x4) = V4 x4 x1 x2 x3

-- Substitutes an entire vector based on the sbox
subWord :: V4 Word8 -> V4 Word8
subWord (V4 x1 x2 x3 x4) = V4 (subByte x1) (subByte x2) (subByte x3) (subByte x4)

subWords :: Vector (V4 Word8) -> Vector (V4 Word8)
subWords = fmap subWord

-- Substitutes an entire vector based on the inverse sbox
invSubWord :: V4 Word8 -> V4 Word8
invSubWord (V4 x1 x2 x3 x4) = V4 (invSubByte x1) (invSubByte x2) (invSubByte x3) (invSubByte x4)

invSubWords :: Vector (V4 Word8) -> Vector (V4 Word8)
invSubWords = fmap invSubWord

xorVector :: Vector Word8 -> Vector Word8 -> Vector Word8
xorVector = zipWith xor

xorV4 :: V4 Word8 -> V4 Word8 -> V4 Word8
xorV4 (V4 x1 x2 x3 x4) (V4 y1 y2 y3 y4) = V4 (x1 `xor` y1) (x2 `xor` y2) (x3 `xor` y3) (x4 `xor` y4)

xorVMatrix :: Vector (V4 Word8) -> Vector (V4 Word8) -> Vector (V4 Word8)
xorVMatrix = zipWith xorV4

xorByte :: V4 Word8 -> Word8 -> V4 Word8
xorByte v e = xorV4 v (V4 e e e e)

vTranspose :: Vector (V4 Word8) -> Vector (V4 Word8)
vTranspose vs
  = cons (V4 a1 b1 c1 d1) (cons (V4 a2 b2 c2 d2) (cons (V4 a3 b3 c3 d3) (cons (V4 a4 b4 c4 d4) empty)))
  where V4 a1 a2 a3 a4 = vs ! 0
        V4 b1 b2 b3 b4 = vs ! 1
        V4 c1 c2 c3 c4 = vs ! 2
        V4 d1 d2 d3 d4 = vs ! 3