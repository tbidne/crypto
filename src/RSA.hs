module RSA
( keygen
, encrypt
, decrypt
, modulus
, publicExponent
, privateExponent
) where

import qualified Data.Maybe as Maybe
import qualified System.Random as Random
import qualified NumberTheory as NT

data Key = Key {
  modulus :: Integer
, publicExponent :: Integer
, privateExponent :: Integer
}

keygen :: (Random.RandomGen g, Integral a) => g -> a -> Maybe Key
keygen g size = case size of
  s 
    | s `elem` [1024, 2048, 4096] -> Just key
    | otherwise -> Nothing
    where (p, q) = genModulus g size
          e = 65537
          d = NT.findInverse e p q
          key = Key {modulus = p*q, publicExponent = e, privateExponent = d}

-- TODO: these will take a key file name and message file name
encrypt = NT.powModN
decrypt = NT.powModN

genModulus :: (Random.RandomGen a, Integral b) => a -> b -> (Integer, Integer)
genModulus g size = (p, q)
  where p = NT.genPrime g $ size `div` 2
        q = NT.genPrime g' $ size `div` 2
        g' = snd $ Random.next g