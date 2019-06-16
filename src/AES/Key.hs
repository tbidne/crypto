module AES.Key
( flatListToKeySchedule
, exposeKS
, Key
, KeyError(..)
, KeySchedule
, KeyDerivable(..)
) where

import Data.List.Split (chunksOf)
import Data.Vector (Vector, fromList, (!), snoc)
import Data.Word (Word8)

import AES.Common

data Key
  = K128 (Vector (V4 Word8))
  | K192 (Vector (V4 Word8))
  | K256 (Vector (V4 Word8))

data KeySchedule
  = KS128 (Vector (V4 Word8))
  | KS192 (Vector (V4 Word8))
  | KS256 (Vector (V4 Word8))

data KeyError
  = SizeErr Int
  | RConErr Int
  deriving Show

class KeyDerivable k where
  toNk :: k -> Int

  toNr :: k -> Int
  toNr = (+6) . toNk

  numRows :: k -> Int
  numRows = (*4) . (+1) . toNr

instance KeyDerivable Key where
  toNk (K128 _) = 4
  toNk (K192 _) = 6
  toNk (K256 _) = 8

instance KeyDerivable KeySchedule where
  toNk (KS128 _) = 4
  toNk (KS192 _) = 6
  toNk (KS256 _) = 8

flatListToKeySchedule :: [Word8] -> Either KeyError KeySchedule
flatListToKeySchedule = (=<<) getKeySchedule . flatListToKey

toKey :: [V4 Word8] -> Either KeyError Key
toKey vs =
  case length vs of
    4 -> Right $ K128 $ fromList vs
    6 -> Right $ K192 $ fromList vs
    8 -> Right $ K256 $ fromList vs
    l -> Left $ SizeErr l

flatListToKey :: [Word8] -> Either KeyError Key
flatListToKey = toKey . fmap toV4 . chunksOf 4

-- Expands the key where each row is a "word" (4 bytes) and the number of rows is
-- 128 --> 44
-- 192 --> 52
-- 256 --> 60
getKeySchedule :: Key -> Either KeyError KeySchedule
getKeySchedule key = keyScheduleCore (toNk key) key $ Right $ (f key) (exposeKey key)
  where f (K128 _) = KS128
        f (K192 _) = KS192
        f (K256 _) = KS256

exposeKey :: Key -> Vector (V4 Word8)
exposeKey (K128 ks) = ks
exposeKey (K192 ks) = ks
exposeKey (K256 ks) = ks

exposeKS :: KeySchedule -> Vector (V4 Word8)
exposeKS (KS128 ks) = ks
exposeKS (KS192 ks) = ks
exposeKS (KS256 ks) = ks

ksSnoc :: KeySchedule -> V4 Word8 -> KeySchedule
ksSnoc (KS128 ks) v = KS128 $ ks `snoc` v
ksSnoc (KS192 ks) v = KS192 $ ks `snoc` v
ksSnoc (KS256 ks) v = KS256 $ ks `snoc` v

-- Performs the bulk of the key expansion.
keyScheduleCore :: Int -> Key -> Either KeyError KeySchedule -> Either KeyError KeySchedule
keyScheduleCore _ _ (Left e) = Left e
keyScheduleCore i key (Right ks)
  | i == (numRows key)    = Right ks
  | otherwise       = (keyScheduleCore (i+1) key . Right . ksSnoc ks) =<< expanded
  where expanded = expand i (toNk key) $ exposeKS ks

expand :: Int -> Int -> Vector (V4 Word8) -> Either KeyError (V4 Word8)
expand i nk vs = fmap (xorV4 (f vs)) (g vs)
  where f = flip (!) (i-nk)
        g = coreTransform i nk . flip (!) (i-1)

-- Transforms the current word per Rijndael.
coreTransform :: Int -> Int -> V4 Word8 -> Either KeyError (V4 Word8)
coreTransform i nk word
  | i `rem` nk == 0               = case rcon (i `div` nk) of
      Right w -> Right $ (flip xorByte w . subWord . rotate) word
      Left err -> Left err
  | nk > 6 && i `rem` nk == 4     = Right $ subWord word
  | otherwise                     = Right $ word

-- Returns the round constant
rcon :: Int -> Either KeyError Word8
rcon 1 = Right 1
rcon 2 = Right 2
rcon 3 = Right 4
rcon 4 = Right 8
rcon 5 = Right 16
rcon 6 = Right 32
rcon 7 = Right 64
rcon 8 = Right 128
rcon 9 = Right 27
rcon 10 = Right 54
rcon i = Left $ RConErr i