module RSA.Internal
( Key (..)
, keyToByteString
, byteStringToKey
, genModulus
)
where

import System.Random (RandomGen)
import System.Random as R (next)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (append)

import qualified Common as C
import qualified NumberTheory as NT

data Key = Key {
  keyModulus :: !Integer
, keyExponent :: !Integer
} deriving (Eq, Show)

keyToByteString :: Key -> ByteString
keyToByteString key = eBytes `BS.append` mBytes
  where  eBytes = C.intToByteString (keyExponent key)
         mBytes = C.intToByteString (keyModulus key)

byteStringToKey :: ByteString -> Key
byteStringToKey keyBytes = key
  where (e, mBS) = C.byteStringToInt keyBytes
        (m,_) = C.byteStringToInt mBS
        key = Key {keyModulus = m, keyExponent = e}  

genModulus :: (RandomGen a, Integral b) => a -> b -> (Integer, Integer)
genModulus g size = (p, q)
  where p = NT.genPrime g $ size `div` 2
        q = NT.genPrime g' $ size `div` 2
        g' = snd $ R.next g