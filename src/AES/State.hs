{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module AES.State
( flatListToState
, invShiftRows
, shiftRows
, State
, transpose
, subSWords
, invSubSWords
, xorSK
, toList
) where

import Prelude hiding (foldr)
import qualified Data.List as L (transpose)
import Data.List.Split (chunksOf)
import Data.Vector ((!), Vector)
import Data.Word (Word8)

import AES.Common

data State a = State a a a a

instance Functor State where
  fmap :: (a -> b) -> State a -> State b
  fmap f (State x1 x2 x3 x4) = State (f x1) (f x2) (f x3) (f x4)

instance Listable State a where
  toList (State x1 x2 x3 x4) = [x1, x2, x3, x4]

toState :: [V4 a] -> State (V4 a)
toState [v1, v2, v3, v4] = State v1 v2 v3 v4
toState _ = undefined

-- | Transforms a list of length 16, @xs@, transforms @m@
-- into an @4 x 4@ 'State' matrix for @xs@.
--
-- Example:
--
-- @
-- flatListToState [b1 ... b16] -> [[b1 ... b4], [b5 ... b8], [b9 ... b12], [b13 ... n16]]
-- @
flatListToState :: [a] -> State (V4 a)
flatListToState = toState . fmap toV4 . L.transpose . chunksOf 4

-- | Computes the transpose of the state.
--
-- Example:
--
-- @
-- transpose [b1 ... b16] -> [[b1 ... b4], [b5 ... b8], [b9 ... b12], [b13 ... n16]]
-- @
transpose :: State (V4 Word8) -> State (V4 Word8)
transpose (State (V4 w1 w2 w3 w4) (V4 x1 x2 x3 x4) (V4 y1 y2 y3 y4) (V4 z1 z2 z3 z4))
  = State (V4 w1 x1 y1 z1) (V4 w2 x2 y2 z2) (V4 w3 x3 y3 z3) (V4 w4 x4 y4 z4)

-- Shifts rows according to
-- | b1  b2  b3  b4  |      | b1  b2  b3  b4  |
-- | b5  b6  b7  b8  |  ->  | b6  b7  b8  b5  |
-- | b8  b9  b10 b11 |      | b10 b11 b8  b9  |
-- | b12 b13 b14 b15 |      | b15 b12 b13 b14 |
shiftRows :: State (V4 Word8) -> State (V4 Word8)
shiftRows (State (V4 w1 w2 w3 w4) (V4 x1 x2 x3 x4) (V4 y1 y2 y3 y4) (V4 z1 z2 z3 z4))
  = State (V4 w1 w2 w3 w4) (V4 x2 x3 x4 x1) (V4 y3 y4 y1 y2) (V4 z4 z1 z2 z3)

-- Shifts rows according to
-- | b1  b2  b3  b4  |      | b1  b2  b3  b4  |
-- | b6  b7  b8  b5  |  ->  | b5  b6  b7  b8  |
-- | b10 b11 b8  b9  |      | b9  b10 b11 b12 |
-- | b15 b12 b13 b14 |      | b13 b14 b15 b16 |
invShiftRows :: State (V4 Word8) -> State (V4 Word8)
invShiftRows (State (V4 w1 w2 w3 w4) (V4 x1 x2 x3 x4) (V4 y1 y2 y3 y4) (V4 z1 z2 z3 z4))
  = State (V4 w1 w2 w3 w4) (V4 x4 x1 x2 x3) (V4 y3 y4 y1 y2) (V4 z2 z3 z4 z1)

subSWords :: State (V4 Word8) -> State (V4 Word8)
subSWords (State v1 v2 v3 v4) = State (subWord v1) (subWord v2) (subWord v3) (subWord v4)

invSubSWords :: State (V4 Word8) -> State (V4 Word8)
invSubSWords (State v1 v2 v3 v4) = State (invSubWord v1) (invSubWord v2) (invSubWord v3) (invSubWord v4)

xorSK :: State (V4 Word8) -> Vector (V4 Word8) -> State (V4 Word8)
xorSK (State s1 s2 s3 s4) vs = State (xorV4 s1 v1) (xorV4 s2 v2) (xorV4 s3 v3) (xorV4 s4 v4)
  where v1 = vs ! 0
        v2 = vs ! 1
        v3 = vs ! 2
        v4 = vs ! 3